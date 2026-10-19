/*
 * CrashLogger.asi v1.2 - Pure Diagnostic Crash Logger for Deadly Premonition: The Director's Cut
 *
 * Loaded by Ultimate ASI Loader (d3d9.dll) from the scripts\ folder.
 * Contains NO game patches or hooks (all game fixes live in CrashFix.asi).
 *
 * Outputs (in scripts\CrashLogs\):
 *   scripts\CrashLogs\CrashLogger.log        session log (handlers, memory heartbeat, first-chance faults)
 *   scripts\CrashLogs\crash_<time>.txt       human-readable crash report (registers, x86 decode, stack, modules)
 *   scripts\CrashLogs\crash_<time>.dmp       minidump (open in WinDbg / Visual Studio)
 */
#define WIN32_LEAN_AND_MEAN
#define PSAPI_VERSION 2
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdarg.h>

#define CRASHLOGGER_VERSION "1.2"

/* Built with -nostdlib (no CRT inside the game process); the compiler may still emit these. */
void *memset(void *d, int c, size_t n) {
    volatile BYTE *p = (volatile BYTE *)d;
    while (n--) *p++ = (BYTE)c;
    return d;
}
void *memcpy(void *d, const void *s, size_t n) {
    volatile BYTE *p = (volatile BYTE *)d;
    const BYTE *q = (const BYTE *)s;
    while (n--) *p++ = *q++;
    return d;
}

/* ---------------- configuration (scripts\CrashLogger.ini) ---------------- */
static int cfgFullDump = 0;
static int cfgLogFirstChance = 1;
static int cfgMaxFirstChance = 100;
static int cfgTrackFiles = 1;
static int cfgMemInterval = 60;
static int cfgLockFilter = 1;

/* ---------------- globals ---------------- */
static HMODULE g_self;
static char g_dir[MAX_PATH];
static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logLock;
static DWORD g_startTick, g_loaderTid, g_workerTid;
static HANDLE g_crashEvent, g_doneEvent;
static volatile LONG g_crashing, g_firstChanceCount;
static PEXCEPTION_POINTERS g_crashEp;
static DWORD g_crashTid;
static const char *g_crashSource;
static LPTOP_LEVEL_EXCEPTION_FILTER g_prevUef;

typedef BOOL(WINAPI *PFN_MDWD)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION,
                               PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
static PFN_MDWD g_MiniDumpWriteDump;
typedef BOOL(WINAPI *PFN_GPMI)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
static PFN_GPMI g_GetProcessMemoryInfo;

/* ---------------- session log ---------------- */
static void LogWrite(const char *s) {
    DWORD w;
    if (g_log == INVALID_HANDLE_VALUE) return;
    EnterCriticalSection(&g_logLock);
    WriteFile(g_log, s, lstrlenA(s), &w, NULL);
    LeaveCriticalSection(&g_logLock);
}

static void Logf(const char *fmt, ...) {
    char buf[1100], line[1200];
    SYSTEMTIME t;
    va_list ap;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);
    GetLocalTime(&t);
    wsprintfA(line, "[%02u:%02u:%02u.%03u] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    LogWrite(line);
    LogWrite(buf);
    LogWrite("\r\n");
}

/* ---------------- safe memory helpers ---------------- */
static BOOL IsReadable(const void *p, SIZE_T n) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD a = (DWORD)p, end = a + (DWORD)n;
    if (!p || end < a) return FALSE;
    while (a < end) {
        if (!VirtualQuery((void *)a, &mbi, sizeof mbi)) return FALSE;
        if (mbi.State != MEM_COMMIT) return FALSE;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return FALSE;
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            return FALSE;
        a = (DWORD)mbi.BaseAddress + mbi.RegionSize;
        if (a == 0) break;
    }
    return TRUE;
}

static BOOL IsExec(DWORD addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!addr || !VirtualQuery((void *)addr, &mbi, sizeof mbi)) return FALSE;
    return mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
           (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

/* ---------------- lock-free module lookup (walks PEB loader list) ---------------- */
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } MyUStr;
typedef struct {
    LIST_ENTRY InLoadOrder, InMemoryOrder, InInitOrder;
    PVOID DllBase, EntryPoint;
    ULONG SizeOfImage;
    MyUStr FullDllName, BaseDllName;
} LdrEntry;
typedef struct { DWORD base, size, pref, stamp; char name[64]; } ModInfo;

static LIST_ENTRY *LdrHead(void) {
    BYTE *teb = (BYTE *)NtCurrentTeb();
    BYTE *peb = *(BYTE **)(teb + 0x30);
    BYTE *ldr = *(BYTE **)(peb + 0x0C);
    return (LIST_ENTRY *)(ldr + 0x0C);
}

static void FillMod(LdrEntry *e, ModInfo *m) {
    IMAGE_DOS_HEADER *d;
    m->base = (DWORD)e->DllBase;
    m->size = e->SizeOfImage;
    m->pref = m->base;
    m->stamp = 0;
    m->name[0] = 0;
    if (e->BaseDllName.Buffer && IsReadable(e->BaseDllName.Buffer, e->BaseDllName.Length)) {
        int n = WideCharToMultiByte(CP_ACP, 0, e->BaseDllName.Buffer, e->BaseDllName.Length / 2, m->name, 63, NULL, NULL);
        m->name[n > 0 ? n : 0] = 0;
    }
    d = (IMAGE_DOS_HEADER *)m->base;
    if (IsReadable(d, sizeof *d) && d->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(m->base + d->e_lfanew);
        if (IsReadable(nt, sizeof *nt) && nt->Signature == IMAGE_NT_SIGNATURE) {
            m->pref = nt->OptionalHeader.ImageBase;
            m->stamp = nt->FileHeader.TimeDateStamp;
        }
    }
}

static BOOL FindModule(DWORD a, ModInfo *m) {
    LIST_ENTRY *h = LdrHead(), *e;
    int guard = 0;
    for (e = h->Flink; e && e != h && guard < 4096; e = e->Flink, guard++) {
        LdrEntry *le = (LdrEntry *)e;
        DWORD b = (DWORD)le->DllBase;
        if (a >= b && a - b < le->SizeOfImage) {
            FillMod(le, m);
            return TRUE;
        }
    }
    return FALSE;
}

static char *FmtAddr(DWORD a, char *out) {
    ModInfo m;
    if (FindModule(a, &m))
        wsprintfA(out, "%s+0x%X (VA %08X)", m.name, a - m.base, m.pref + (a - m.base));
    else if (IsExec(a))
        wsprintfA(out, "%08X (executable memory outside any module: hook/trampoline?)", a);
    else
        wsprintfA(out, "%08X", a);
    return out;
}

static char *Annot(DWORD v, char *out) {
    ModInfo m;
    if (FindModule(v, &m))
        wsprintfA(out, "%s+0x%X", m.name, v - m.base);
    else if (IsReadable((void *)v, 4))
        wsprintfA(out, "-> %08X", *(DWORD *)v);
    else
        out[0] = 0;
    return out;
}

static BOOL LooksLikeRet(DWORD a) {
    BYTE *p = (BYTE *)a;
    if (a < 0x10000 || !IsExec(a) || !IsReadable(p - 7, 7)) return FALSE;
    if (p[-5] == 0xE8) return TRUE;
    if (p[-2] == 0xFF && (p[-1] & 0x38) == 0x10) return TRUE;
    if (p[-3] == 0xFF && (p[-2] & 0x38) == 0x10) return TRUE;
    if (p[-4] == 0xFF && (p[-3] & 0x38) == 0x10) return TRUE;
    if (p[-6] == 0xFF && (p[-5] & 0x38) == 0x10) return TRUE;
    if (p[-7] == 0xFF && (p[-6] & 0x38) == 0x10) return TRUE;
    return FALSE;
}

/* ---------------- lightweight x86 faulting instruction summary ---------------- */
static void DecodeFaultInsn(const BYTE *ip, char *out) {
    const BYTE *p = ip;
    int pfx = 0;
    if (!IsReadable(ip, 16)) {
        lstrcpyA(out, "(unreadable)");
        return;
    }
    while (pfx < 4 && (*p == 0x66 || *p == 0x67 || *p == 0xF0 || *p == 0xF2 || *p == 0xF3 ||
                       *p == 0x26 || *p == 0x2E || *p == 0x36 || *p == 0x3E || *p == 0x64 || *p == 0x65)) {
        p++;
        pfx++;
    }
    if (p[0] == 0x8B) wsprintfA(out, "MOV reg, r/m (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0x89) wsprintfA(out, "MOV r/m, reg (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0x8A) wsprintfA(out, "MOV r8, r/m8 (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0x88) wsprintfA(out, "MOV r/m8, r8 (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0x39 || p[0] == 0x3B || p[0] == 0x80 || p[0] == 0x81 || p[0] == 0x83)
        wsprintfA(out, "CMP/ALU r/m (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0xD8 || p[0] == 0xD9 || p[0] == 0xDA || p[0] == 0xDB ||
             p[0] == 0xDC || p[0] == 0xDD || p[0] == 0xDE || p[0] == 0xDF)
        wsprintfA(out, "x87 FPU op (opcode %02X %02X)", p[0], p[1]);
    else if (p[0] == 0xFF && ((p[1] & 0x38) == 0x10))
        wsprintfA(out, "CALL r/m32 (opcode FF %02X)", p[1]);
    else if (p[0] == 0xFF && ((p[1] & 0x38) == 0x20))
        wsprintfA(out, "JMP r/m32 (opcode FF %02X)", p[1]);
    else if (p[0] == 0x0F && (p[1] == 0xB6 || p[1] == 0xB7 || p[1] == 0xBE || p[1] == 0xBF))
        wsprintfA(out, "MOVZX/MOVSX reg, r/m (opcode 0F %02X %02X)", p[1], p[2]);
    else
        wsprintfA(out, "opcode %02X %02X %02X %02X", p[0], p[1], p[2], p[3]);
}

/* ---------------- exception helpers ---------------- */
static const char *ExcName(DWORD c) {
    switch (c) {
    case 0xC0000005: return "ACCESS_VIOLATION";
    case 0xC0000006: return "IN_PAGE_ERROR";
    case 0xC000001D: return "ILLEGAL_INSTRUCTION";
    case 0xC0000096: return "PRIVILEGED_INSTRUCTION";
    case 0xC0000094: return "INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095: return "INTEGER_OVERFLOW";
    case 0xC000008C: return "ARRAY_BOUNDS_EXCEEDED";
    case 0xC00000FD: return "STACK_OVERFLOW";
    case 0xC0000374: return "HEAP_CORRUPTION";
    case 0xC0000409: return "STACK_BUFFER_OVERRUN";
    case 0x80000002: return "DATATYPE_MISALIGNMENT";
    case 0xC000008D: return "FLT_DENORMAL_OPERAND";
    case 0xC000008E: return "FLT_DIVIDE_BY_ZERO";
    case 0xC000008F: return "FLT_INXACT_RESULT";
    case 0xC0000090: return "FLT_INVALID_OPERATION";
    case 0xC0000091: return "FLT_OVERFLOW";
    case 0xC0000092: return "FLT_STACK_CHECK";
    case 0xC0000093: return "FLT_UNDERFLOW";
    case 0xC0000017: return "NO_MEMORY";
    case 0xC0000025: return "NONCONTINUABLE_EXCEPTION";
    case 0xC0000026: return "INVALID_DISPOSITION";
    case 0x80000003: return "BREAKPOINT";
    case 0xE06D7363: return "C++ EXCEPTION (throw)";
    }
    return "UNKNOWN";
}

static BOOL IsInteresting(DWORD c) {
    switch (c) {
    case 0xC0000005: case 0xC0000006: case 0xC000001D: case 0xC0000096: case 0xC0000094:
    case 0xC0000095: case 0xC000008C: case 0xC00000FD: case 0xC0000374: case 0xC0000409:
    case 0x80000002: case 0xC000008D: case 0xC000008E: case 0xC000008F: case 0xC0000090:
    case 0xC0000091: case 0xC0000092: case 0xC0000093: case 0xC0000017: case 0xE06D7363:
        return TRUE;
    }
    return FALSE;
}

static const char *AccessType(ULONG_PTR t) {
    return t == 0 ? "READ" : t == 1 ? "WRITE" : t == 8 ? "EXECUTE (DEP)" : "?";
}

static void CxxTypeName(EXCEPTION_RECORD *er, char *out, int n) {
    DWORD ti, cta, ct, td;
    out[0] = 0;
    if (er->ExceptionCode != 0xE06D7363 || er->NumberParameters < 3) return;
    ti = (DWORD)er->ExceptionInformation[2];
    if (!IsReadable((void *)ti, 16)) return;
    cta = *(DWORD *)(ti + 12);
    if (!IsReadable((void *)cta, 8)) return;
    ct = *(DWORD *)(cta + 4);
    if (!IsReadable((void *)ct, 8)) return;
    td = *(DWORD *)(ct + 4);
    if (!IsReadable((void *)(td + 8), 4)) return;
    lstrcpynA(out, (char *)(td + 8), n);
}

/* ---------------- memory status ---------------- */
static DWORD g_largestFreeMB;
static void MemSummary(char *out) {
    MEMORYSTATUSEX ms;
    MEMORY_BASIC_INFORMATION mbi;
    PROCESS_MEMORY_COUNTERS_EX pmc;
    DWORD largest = 0, priv = 0, ws = 0, p = 0x10000;
    ms.dwLength = sizeof ms;
    GlobalMemoryStatusEx(&ms);
    while (VirtualQuery((void *)p, &mbi, sizeof mbi)) {
        DWORD nx = (DWORD)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State == MEM_FREE && mbi.RegionSize > largest) largest = mbi.RegionSize;
        if (nx <= p) break;
        p = nx;
    }
    ZeroMemory(&pmc, sizeof pmc);
    pmc.cb = sizeof pmc;
    if (g_GetProcessMemoryInfo && g_GetProcessMemoryInfo(GetCurrentProcess(), (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof pmc)) {
        priv = (DWORD)(pmc.PrivateUsage >> 20);
        ws = (DWORD)(pmc.WorkingSetSize >> 20);
    }
    g_largestFreeMB = largest >> 20;
    wsprintfA(out, "VA used %u/%u MB, free VA %u MB, largest free block %u MB, private %u MB, working set %u MB, RAM free %u/%u MB",
              (DWORD)((ms.ullTotalVirtual - ms.ullAvailVirtual) >> 20), (DWORD)(ms.ullTotalVirtual >> 20),
              (DWORD)(ms.ullAvailVirtual >> 20), largest >> 20, priv, ws,
              (DWORD)(ms.ullAvailPhys >> 20), (DWORD)(ms.ullTotalPhys >> 20));
}

/* ---------------- recent file opens ---------------- */
#define FR_COUNT 32
typedef struct { DWORD tick, tid; char path[200]; } FileRec;
static FileRec g_files[FR_COUNT];
static volatile LONG g_fileSeq;
typedef HANDLE(WINAPI *PFN_CFA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static PFN_CFA g_origCFA;

static HANDLE WINAPI HookCreateFileA(LPCSTR fn, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                     DWORD disp, DWORD flags, HANDLE tmpl) {
    LONG i = InterlockedIncrement(&g_fileSeq) - 1;
    FileRec *r = &g_files[(DWORD)i % FR_COUNT];
    const char *src = fn ? fn : "(null)";
    int len = lstrlenA(src);
    if (len > (int)sizeof r->path - 1) src += len - ((int)sizeof r->path - 1);
    r->tick = GetTickCount();
    r->tid = GetCurrentThreadId();
    lstrcpynA(r->path, src, sizeof r->path);
    return g_origCFA(fn, acc, share, sa, disp, flags, tmpl);
}

static BOOL HookIAT(HMODULE mod, const char *dll, const char *fn, void *hook, void **orig) {
    BYTE *b = (BYTE *)mod;
    IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + d->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *id;
    void *real = GetProcAddress(GetModuleHandleA(dll), fn);
    if (!dir.VirtualAddress) return FALSE;
    for (id = (IMAGE_IMPORT_DESCRIPTOR *)(b + dir.VirtualAddress); id->Name; id++) {
        IMAGE_THUNK_DATA32 *ft, *ot;
        if (lstrcmpiA((char *)(b + id->Name), dll)) continue;
        ft = (IMAGE_THUNK_DATA32 *)(b + id->FirstThunk);
        ot = id->OriginalFirstThunk ? (IMAGE_THUNK_DATA32 *)(b + id->OriginalFirstThunk) : NULL;
        for (; ft->u1.Function; ft++) {
            BOOL match = FALSE;
            if (ot && !(ot->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(b + ot->u1.AddressOfData);
                match = !lstrcmpA((char *)ibn->Name, fn);
            } else if (real && (void *)ft->u1.Function == real) {
                match = TRUE;
            }
            if (ot) ot++;
            if (match) {
                DWORD old;
                if (!VirtualProtect(&ft->u1.Function, 4, PAGE_READWRITE, &old)) return FALSE;
                *orig = (void *)ft->u1.Function;
                ft->u1.Function = (DWORD)hook;
                VirtualProtect(&ft->u1.Function, 4, old, &old);
                return TRUE;
            }
        }
    }
    return FALSE;
}

static int LockUef(void) {
    static const BYTE patch[5] = {0x33, 0xC0, 0xC2, 0x04, 0x00};
    void *t[2];
    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    int i, n = 0;
    t[0] = GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetUnhandledExceptionFilter");
    t[1] = kb ? GetProcAddress(kb, "SetUnhandledExceptionFilter") : NULL;
    for (i = 0; i < 2; i++) {
        DWORD old;
        if (!t[i] || (i == 1 && t[1] == t[0])) continue;
        if (VirtualProtect(t[i], sizeof patch, PAGE_EXECUTE_READWRITE, &old)) {
            CopyMemory(t[i], patch, sizeof patch);
            VirtualProtect(t[i], sizeof patch, old, &old);
            FlushInstructionCache(GetCurrentProcess(), t[i], sizeof patch);
            n++;
        }
    }
    return n;
}

/* ---------------- crash report (runs on the worker thread) ---------------- */
static HANDLE g_rpt = INVALID_HANDLE_VALUE;
static void R(const char *fmt, ...) {
    char buf[1100];
    DWORD w;
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (n > 0 && g_rpt != INVALID_HANDLE_VALUE) WriteFile(g_rpt, buf, n, &w, NULL);
}

static DWORD StackTop(DWORD esp) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)esp, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) return esp;
    return (DWORD)mbi.BaseAddress + mbi.RegionSize;
}

static void WriteReport(void) {
    EXCEPTION_RECORD *er = g_crashEp->ExceptionRecord;
    CONTEXT *cx = g_crashEp->ContextRecord;
    SYSTEMTIME t;
    char base[MAX_PATH], path[MAX_PATH + 8], a[256], b[256], mem[400];
    DWORD up = (GetTickCount() - g_startTick) / 1000;
    DWORD esp = cx->Esp, eip = cx->Eip, top = StackTop(esp), p;
    int i, found;
    LIST_ENTRY *h, *e;

    GetLocalTime(&t);
    wsprintfA(base, "%s\\crash_%04u-%02u-%02u_%02u-%02u-%02u", g_dir, t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    wsprintfA(path, "%s.txt", base);
    g_rpt = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    R("==== Deadly Premonition CrashLogger %s report ====\r\n", CRASHLOGGER_VERSION);
    R("Time      : %04u-%02u-%02u %02u:%02u:%02u\r\n", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    R("Uptime    : %u min %u s\r\n", up / 60, up % 60);
    R("Caught by : %s\r\n", g_crashSource);
    R("Thread    : %u%s\r\n", g_crashTid, g_crashTid == g_loaderTid ? " (thread that loaded ASIs, normally the main/game thread)" : "");

    R("\r\n-- Exception --\r\n");
    R("Code      : %08X %s%s\r\n", er->ExceptionCode, ExcName(er->ExceptionCode),
      (er->ExceptionFlags & EXCEPTION_NONCONTINUABLE) ? " (noncontinuable)" : "");
    R("Address   : %s\r\n", FmtAddr((DWORD)er->ExceptionAddress, a));
    DecodeFaultInsn((const BYTE *)eip, b);
    R("Insn      : %s\r\n", b);
    if ((er->ExceptionCode == 0xC0000005 || er->ExceptionCode == 0xC0000006) && er->NumberParameters >= 2) {
        DWORD target = (DWORD)er->ExceptionInformation[1];
        R("Access    : %s of address %08X%s\r\n", AccessType(er->ExceptionInformation[0]), target,
          target < 0x10000 ? "   <-- NULL pointer (+ field offset)" : "");
    }
    if (er->ExceptionCode == 0xE06D7363) {
        CxxTypeName(er, a, sizeof a);
        R("C++ type  : %s\r\n", a[0] ? a : "(unknown)");
    }
    R("First-chance faults logged this session: %d\r\n", (int)g_firstChanceCount);

    R("\r\n-- Registers --\r\n");
    R("EAX = %08X  %s\r\n", cx->Eax, Annot(cx->Eax, a));
    R("EBX = %08X  %s\r\n", cx->Ebx, Annot(cx->Ebx, a));
    R("ECX = %08X  %s\r\n", cx->Ecx, Annot(cx->Ecx, a));
    R("EDX = %08X  %s\r\n", cx->Edx, Annot(cx->Edx, a));
    R("ESI = %08X  %s\r\n", cx->Esi, Annot(cx->Esi, a));
    R("EDI = %08X  %s\r\n", cx->Edi, Annot(cx->Edi, a));
    R("EBP = %08X  %s\r\n", cx->Ebp, Annot(cx->Ebp, a));
    R("ESP = %08X  (stack top %08X)\r\n", esp, top);
    R("EIP = %08X  %s\r\n", eip, FmtAddr(eip, a));
    R("EFL = %08X\r\n", cx->EFlags);

    R("\r\n-- Code bytes around EIP ([..] = faulting instruction) --\r\n");
    if (IsReadable((void *)(eip - 16), 32)) {
        int k = 0;
        for (i = -16; i < 16; i++) k += wsprintfA(b + k, i == 0 ? "[%02X] " : "%02X ", ((BYTE *)eip)[i]);
        R("%s\r\n", b);
    } else {
        R("(EIP not readable - probably a call through a bad function pointer; see [ESP] below)\r\n");
    }

    R("\r\n-- Call stack (EBP chain) --\r\n");
    R("#00 %s\r\n", FmtAddr(eip, a));
    {
        DWORD ebp = cx->Ebp;
        for (i = 1; i < 64; i++) {
            DWORD ret, next;
            if (ebp < esp || ebp + 8 > top || (ebp & 3)) break;
            ret = *(DWORD *)(ebp + 4);
            next = *(DWORD *)ebp;
            if (!ret) break;
            R("#%02d %s\r\n", i, FmtAddr(ret, a));
            if (next <= ebp) break;
            ebp = next;
        }
    }

    R("\r\n-- Stack scan: probable return addresses (most reliable for FPO code) --\r\n");
    if (IsReadable((void *)esp, 4)) R("[ESP]      %s\r\n", FmtAddr(*(DWORD *)esp, a));
    for (p = esp, found = 0; p + 4 <= top && p < esp + 0x10000 && found < 64; p += 4) {
        DWORD v = *(DWORD *)p;
        if (LooksLikeRet(v)) {
            R("ESP+%04X  %s\r\n", p - esp, FmtAddr(v, a));
            found++;
        }
    }

    R("\r\n-- Raw stack --\r\n");
    for (p = esp, i = 0; i < 32 && p + 16 <= top; i++, p += 16) {
        DWORD *q = (DWORD *)p;
        R("%08X: %08X %08X %08X %08X\r\n", p, q[0], q[1], q[2], q[3]);
    }

    R("\r\n-- Recent CreateFileA calls by DP.exe (newest first) --\r\n");
    {
        LONG seq = g_fileSeq;
        DWORD now = GetTickCount();
        if (!cfgTrackFiles) R("(disabled in ini)\r\n");
        for (i = 0; i < FR_COUNT && i < seq; i++) {
            FileRec *r = &g_files[(DWORD)(seq - 1 - i) % FR_COUNT];
            R("%7u ms ago  tid=%-6u %s\r\n", now - r->tick, r->tid, r->path);
        }
    }

    R("\r\n-- Memory --\r\n");
    MemSummary(mem);
    R("%s\r\n", mem);
    if (g_largestFreeMB < 64)
        R("WARNING: address space nearly exhausted - crash is probably out-of-memory related.\r\n");

    R("\r\n-- Loaded modules --\r\n");
    h = LdrHead();
    for (e = h->Flink, i = 0; e && e != h && i < 4096; e = e->Flink, i++) {
        ModInfo m;
        FillMod((LdrEntry *)e, &m);
        R("%08X-%08X  %-28s pref=%08X  stamp=%08X\r\n", m.base, m.base + m.size, m.name, m.pref, m.stamp);
    }

    wsprintfA(path, "%s.dmp", base);
    if (g_MiniDumpWriteDump) {
        HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION mei;
            MINIDUMP_TYPE type = cfgFullDump ? (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData |
                                                               MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules)
                                             : (MINIDUMP_TYPE)(MiniDumpWithDataSegs | MiniDumpWithIndirectlyReferencedMemory |
                                                               MiniDumpWithProcessThreadData | MiniDumpWithThreadInfo |
                                                               MiniDumpWithUnloadedModules | MiniDumpWithHandleData);
            BOOL ok;
            mei.ThreadId = g_crashTid;
            mei.ExceptionPointers = g_crashEp;
            mei.ClientPointers = FALSE;
            ok = g_MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, type, &mei, NULL, NULL);
            R("\r\nMinidump  : %s (%s, err=%u)\r\n", path, ok ? "OK" : "FAILED", ok ? 0 : GetLastError());
            CloseHandle(f);
        }
    } else {
        R("\r\nMinidump  : dbghelp.dll not available\r\n");
    }

    if (g_rpt != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_rpt);
        CloseHandle(g_rpt);
        g_rpt = INVALID_HANDLE_VALUE;
    }
    Logf("[CRASH] %08X %s at %s -> %s.txt", er->ExceptionCode, ExcName(er->ExceptionCode),
         FmtAddr((DWORD)er->ExceptionAddress, a), base);
    if (g_log != INVALID_HANDLE_VALUE) FlushFileBuffers(g_log);
}

/* ---------------- handlers ---------------- */
static void HandleCrash(PEXCEPTION_POINTERS ep, const char *src) {
    if (InterlockedExchange(&g_crashing, 1)) {
        WaitForSingleObject(g_doneEvent, 60000);
        return;
    }
    g_crashEp = ep;
    g_crashTid = GetCurrentThreadId();
    g_crashSource = src;
    if (g_crashEvent && g_workerTid) {
        SetEvent(g_crashEvent);
        WaitForSingleObject(g_doneEvent, 60000);
    }
}

static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    DWORD c = er->ExceptionCode;
    if (GetCurrentThreadId() == g_workerTid || !IsInteresting(c)) return EXCEPTION_CONTINUE_SEARCH;

    if (c == EXCEPTION_STACK_OVERFLOW) {
        HandleCrash(ep, "vectored handler (stack overflow)");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (cfgLogFirstChance && InterlockedIncrement(&g_firstChanceCount) <= cfgMaxFirstChance) {
        char a[200], x[160], ra[200];
        DWORD ebp = ep->ContextRecord->Ebp, caller = 0;
        x[0] = 0;
        if ((c == 0xC0000005 || c == 0xC0000006) && er->NumberParameters >= 2)
            wsprintfA(x, " %s %08X", AccessType(er->ExceptionInformation[0]), (DWORD)er->ExceptionInformation[1]);
        else if (c == 0xE06D7363) {
            char tn[120];
            CxxTypeName(er, tn, sizeof tn);
            wsprintfA(x, " type=%s", tn);
        }
        if (IsReadable((void *)(ebp + 4), 4)) caller = *(DWORD *)(ebp + 4);
        Logf("[FirstChance #%d] %08X %s at %s%s | tid=%u caller~%s", (int)g_firstChanceCount, c, ExcName(c),
             FmtAddr((DWORD)er->ExceptionAddress, a), x, GetCurrentThreadId(), caller ? FmtAddr(caller, ra) : "?");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI UnhandledFilter(PEXCEPTION_POINTERS ep) {
    if (GetCurrentThreadId() != g_workerTid) HandleCrash(ep, "unhandled exception filter");
    if (g_prevUef && g_prevUef != UnhandledFilter) return g_prevUef(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---------------- worker thread ---------------- */
static DWORD WINAPI Worker(LPVOID unused) {
    char sys[MAX_PATH + 16], m[400];
    HMODULE dh;
    DWORD timeout;
    (void)unused;
    g_workerTid = GetCurrentThreadId();

    GetSystemDirectoryA(sys, MAX_PATH);
    lstrcatA(sys, "\\dbghelp.dll");
    dh = LoadLibraryA(sys);
    if (dh) g_MiniDumpWriteDump = (PFN_MDWD)GetProcAddress(dh, "MiniDumpWriteDump");
    g_GetProcessMemoryInfo = (PFN_GPMI)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetProcessMemoryInfo");
    Logf("dbghelp: %s", g_MiniDumpWriteDump ? "OK (minidumps enabled)" : "NOT FOUND (no .dmp files)");
    MemSummary(m);
    Logf("[Mem] %s", m);

    timeout = cfgMemInterval > 0 ? (DWORD)cfgMemInterval * 1000 : INFINITE;
    for (;;) {
        DWORD r = WaitForSingleObject(g_crashEvent, timeout);
        if (r == WAIT_TIMEOUT) {
            MemSummary(m);
            Logf("[Mem] uptime %us | %s", (GetTickCount() - g_startTick) / 1000, m);
            continue;
        }
        if (r != WAIT_OBJECT_0) break;
        WriteReport();
        SetEvent(g_doneEvent);
    }
    return 0;
}

/* ---------------- init ---------------- */
static void Init(void) {
    char dir[MAX_PATH], ini[MAX_PATH + 32], logp[MAX_PATH + 32], prev[MAX_PATH + 32], exe[MAX_PATH];
    char *slash;
    int locked = 0;
    BOOL hooked = FALSE;

    /* Avoid duplicate initialization if Ultimate ASI Loader loads from both root and scripts\ */
    if (GetEnvironmentVariableA("DP_CRASHLOGGER_ACTIVE", dir, sizeof dir) > 0) return;
    SetEnvironmentVariableA("DP_CRASHLOGGER_ACTIVE", "1");

    GetModuleFileNameA(g_self, dir, MAX_PATH);
    {
        char *c;
        slash = NULL;
        for (c = dir; *c; c++)
            if (*c == '\\') slash = c;
    }
    if (slash) *slash = 0;

    /* If loaded from scripts\, rename any stale root CrashLogger.asi so ASI Loader won't load it twice */
    {
        char *parentSlash = NULL, *c;
        for (c = dir; *c; c++)
            if (*c == '\\') parentSlash = c;
        if (parentSlash && lstrcmpiA(parentSlash + 1, "scripts") == 0) {
            char rootAsi[MAX_PATH], rootAsiOld[MAX_PATH], rootIni[MAX_PATH], rootIniOld[MAX_PATH];
            *parentSlash = 0;
            wsprintfA(rootAsi, "%s\\CrashLogger.asi", dir);
            wsprintfA(rootAsiOld, "%s\\CrashLogger.asi.old", dir);
            wsprintfA(rootIni, "%s\\CrashLogger.ini", dir);
            wsprintfA(rootIniOld, "%s\\CrashLogger.ini.old", dir);
            *parentSlash = '\\';
            if (GetFileAttributesA(rootAsi) != INVALID_FILE_ATTRIBUTES)
                MoveFileExA(rootAsi, rootAsiOld, MOVEFILE_REPLACE_EXISTING);
            if (GetFileAttributesA(rootIni) != INVALID_FILE_ATTRIBUTES)
                MoveFileExA(rootIni, rootIniOld, MOVEFILE_REPLACE_EXISTING);
        }
    }

    wsprintfA(ini, "%s\\CrashLogger.ini", dir);
    cfgFullDump = GetPrivateProfileIntA("CrashLogger", "FullMemoryDump", cfgFullDump, ini);
    cfgLogFirstChance = GetPrivateProfileIntA("CrashLogger", "LogFirstChance", cfgLogFirstChance, ini);
    cfgMaxFirstChance = GetPrivateProfileIntA("CrashLogger", "MaxFirstChanceLogs", cfgMaxFirstChance, ini);
    cfgTrackFiles = GetPrivateProfileIntA("CrashLogger", "TrackFileOpens", cfgTrackFiles, ini);
    cfgMemInterval = GetPrivateProfileIntA("CrashLogger", "MemoryLogIntervalSec", cfgMemInterval, ini);
    cfgLockFilter = GetPrivateProfileIntA("CrashLogger", "LockExceptionFilter", cfgLockFilter, ini);

    wsprintfA(g_dir, "%s\\CrashLogs", dir);
    CreateDirectoryA(g_dir, NULL);
    wsprintfA(logp, "%s\\CrashLogger.log", g_dir);
    wsprintfA(prev, "%s\\CrashLogger.prev.log", g_dir);
    MoveFileExA(logp, prev, MOVEFILE_REPLACE_EXISTING);
    InitializeCriticalSection(&g_logLock);
    g_log = CreateFileA(logp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    g_startTick = GetTickCount();
    g_loaderTid = GetCurrentThreadId();
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    Logf("CrashLogger %s (pure diagnostic logger) loaded into %s (base %08X, pid %u, tid %u)", CRASHLOGGER_VERSION, exe,
         (DWORD)GetModuleHandleA(NULL), GetCurrentProcessId(), g_loaderTid);

    g_crashEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_doneEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    AddVectoredExceptionHandler(1, VectoredHandler);
    g_prevUef = SetUnhandledExceptionFilter(UnhandledFilter);
    if (cfgLockFilter) locked = LockUef();
    if (cfgTrackFiles)
        hooked = HookIAT(GetModuleHandleA(NULL), "kernel32.dll", "CreateFileA", (void *)HookCreateFileA, (void **)&g_origCFA);

    CreateThread(NULL, 0, Worker, NULL, 0, NULL);

    Logf("Config: FullMemoryDump=%d LogFirstChance=%d MaxFirstChanceLogs=%d TrackFileOpens=%d MemoryLogIntervalSec=%d LockExceptionFilter=%d",
         cfgFullDump, cfgLogFirstChance, cfgMaxFirstChance, cfgTrackFiles, cfgMemInterval, cfgLockFilter);
    Logf("Handlers: vectored=on, unhandled filter=on (previous=%08X), filter lock patched %d function(s), CreateFileA tracking=%s",
         (DWORD)g_prevUef, locked, hooked ? "on" : (cfgTrackFiles ? "FAILED (import not found)" : "off"));
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = h;
        DisableThreadLibraryCalls(h);
        Init();
    }
    return TRUE;
}
