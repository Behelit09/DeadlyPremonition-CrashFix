/*
 * CrashFix.asi v1.2 - Standalone Crash Fix Plugin for Deadly Premonition: The Director's Cut
 *
 * Loaded by Ultimate ASI Loader (d3d9.dll) from the scripts\ folder.
 * Separated from CrashLogger.asi so diagnostics and game patches are independent modules.
 *
 * === MULTI-LAYER FIXES ===
 * 1. Layer 1 - SetAiState Invalid Waypoint Guard (0x0047D710 / 0x0047D7B3 & 0x0047D804):
 *    - At cutscene exit (e.g. Episode 2 Part 1 Art Gallery exit), 0x004CA2A0 calls SetAiState(1, 0)
 *      on CNpcNormal (charType == 3) while its target waypoint [ESI + 0x634] is -1 (0xFFFF).
 *    - Vanilla 0x0047D7B3 only aborted the walk setup if charType == 7, allowing charType == 3
 *      to enter walk state (aiState = 1) toward waypoint -1.
 *    - We intercept 0x0047D7B3: if [ESI + 0x634] is -1 or out of bounds in NavTable, we preserve
 *      npc->targetPos = npc->pos ([ESI + 0x7BC..0x7C8] = [ESI + 0x58..0x64]), keep vanilla behavior
 *      if charType == 7, and for other character types set aiState = 0 (Idle) and return cleanly.
 *
 * 2. Layer 2 - OnReachedWaypoint & GetWaypointPos Position Preservation (0x004CCD50, 0x004D1363, 0x004D8980):
 *    - In 0x004CCD00 (at 0x004CCD50) and 0x004D1310 (at 0x004D1363), the game passes a stack buffer
 *      to 0x004D8980(buf, nodeIdx) and unconditionally copies the result into npc->pos ([ESI + 0x58]).
 *    - If nodeIdx is invalid (-1), zeroing that stack buffer wipes npc->pos to (0, 0, 0, 0).
 *    - We hook 0x004CCD50, 0x004D1363, and 0x004D8980 so failed waypoint position lookups fall back
 *      to the NPC's own current world position [ESI + 0x58] (or preserve out if out == &npc->pos).
 *
 * 3. Layer 3 - Full NavTable (0x01437A20) Bounds Checking & Writable Dummy Structs:
 *    - Bounds-checks all NavTable indexing methods:
 *      005E1ED0, 005E19E0, 005E1A70, 005E1AE0, 005E1B30, 005E1B70, 005E1BA0,
 *      005E1BD0, 005E1C00, 005E19B0, 005E2150, 005E21F0, 005E2240
 *      and navigation wrappers 004D8750, 004D8790, 004D8860.
 *    - In 005E1AE0 (GetNodeInfoPtr): 177 of 198 call sites in DP.exe (including 0x0047F134 -> 0x0047F1CB)
 *      dereference the returned pointer without a NULL check, and 6 call sites write to it.
 *      When an out-of-bounds index is passed from an unchecked caller, we reset and return a writable
 *      64-byte dummy struct (flags = 0, actionType (+0x04) = 0, subId (+0x06) = -1) so 0x0047F1CB
 *      (CMP word ptr [EDI + 0x4], 0) takes the clean exit path instead of crashing on NULL+0x4.
 *
 * Session log: scripts\CrashLogs\CrashFix.log
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>

#define CRASHFIX_VERSION "1.2"

/* Built with -nostdlib (no CRT inside the game process); compiler may emit calls to memset/memcpy. */
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

/* ---------------- configuration (scripts\CrashFix.ini) ---------------- */
static int cfgEpisode2WaypointFix = 1;
static int cfgNavTableBoundsFix = 1;
static int cfgLogPrevented = 1;
static int cfgMaxPreventedLogs = 100;

/* ---------------- globals ---------------- */
static HMODULE g_self;
static char g_dir[MAX_PATH];
static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logLock;
static volatile LONG g_preventedCount;

/* ---------------- logging ---------------- */
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
    if (g_log == INVALID_HANDLE_VALUE) return;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);
    GetLocalTime(&t);
    wsprintfA(line, "[%02u:%02u:%02u.%03u] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    LogWrite(line);
    LogWrite(buf);
    LogWrite("\r\n");
}

static void NotePrevented(const char *where, int idx, int maxIdx) {
    LONG n = InterlockedIncrement(&g_preventedCount);
    if (!cfgLogPrevented) return;
    if (n <= cfgMaxPreventedLogs || (n % 250) == 0) {
        Logf("[Fix] Prevented invalid/OOB node access #%d in %s (index=%d, max=%d)",
             (int)n, where, idx, maxIdx);
    }
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

static BOOL IsWritable(const void *p, SIZE_T n) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD a = (DWORD)p, end = a + (DWORD)n;
    if (!p || end < a) return FALSE;
    while (a < end) {
        if (!VirtualQuery((void *)a, &mbi, sizeof mbi)) return FALSE;
        if (mbi.State != MEM_COMMIT) return FALSE;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return FALSE;
        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
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

static BOOL IsOnCurrentThreadStack(const void *p) {
    BYTE *teb = (BYTE *)NtCurrentTeb();
    DWORD stackHigh = *(DWORD *)(teb + 0x04);
    DWORD stackLow  = *(DWORD *)(teb + 0x08);
    DWORD addr = (DWORD)p;
    return addr >= stackLow && addr + 16 <= stackHigh;
}

/* ---------------- NavTable layout & writable dummy buffers ---------------- */
#define NAV_OBJ_ADDR   0x01437A20
#define NAV_BASE_WORD  0x01438B9E

typedef struct {
    void *vtable;       /* +0x00 */
    BYTE  active;       /* +0x04 */
    BYTE  pad[3];
    int   maxIndex;     /* +0x08 (number of 0x3C-byte entries in nodes) */
    int   unk0C;        /* +0x0C */
    int   unk10;        /* +0x10 */
    int   unk14;        /* +0x14 */
    BYTE *nodes;        /* +0x18 (stride 0x3C) */
    WORD *adjWords;     /* +0x1C */
    BYTE *strTable;     /* +0x20 */
    BYTE *extraTable;   /* +0x24 */
} NavTable;

/* Writable dummy buffers for pointer-returning methods (never const / never NULL on unchecked callers) */
static BYTE s_dummyNodeInfo[64];
static BYTE s_dummyExtraStr[64];

static void *GetFreshDummyNodeInfo(void) {
    memset(s_dummyNodeInfo, 0, sizeof s_dummyNodeInfo);
    *(WORD *)(s_dummyNodeInfo + 0x04) = 0;      /* actionType = 0 (so 0047F1CB CMP word [EDI+4], 0 is equal) */
    *(WORD *)(s_dummyNodeInfo + 0x06) = 0xFFFF; /* subId = -1 (so 004D88EA never matches a valid subId) */
    return (void *)s_dummyNodeInfo;
}

static void *GetFreshDummyExtraStr(void) {
    memset(s_dummyExtraStr, 0, sizeof s_dummyExtraStr);
    return (void *)s_dummyExtraStr;
}

static BOOL ValidNodeIndex(const NavTable *nav, int idx, const char *where) {
    if (!nav || !nav->active || !nav->nodes) return FALSE;
    if (idx < 0 || idx >= nav->maxIndex) {
        NotePrevented(where, idx, nav->maxIndex);
        return FALSE;
    }
    return TRUE;
}

/* Checks if the instruction immediately at the caller's return address tests EAX for NULL:
   - 85 C0                TEST EAX, EAX
   - 3B C3                CMP EAX, EBX
   - 8B F0 85 F6          MOV ESI, EAX; TEST ESI, ESI
   - 8B F8 85 FF          MOV EDI, EAX; TEST EDI, EDI
   - 8B C8 85 C9          MOV ECX, EAX; TEST ECX, ECX */
static BOOL CallerChecksNull(const BYTE *retAddr) {
    if (!IsReadable(retAddr, 4)) return FALSE;
    if (retAddr[0] == 0x85 && retAddr[1] == 0xC0) return TRUE;
    if (retAddr[0] == 0x3B && retAddr[1] == 0xC3) return TRUE;
    if (retAddr[0] == 0x8B && retAddr[2] == 0x85) {
        if (retAddr[1] == 0xF0 && retAddr[3] == 0xF6) return TRUE;
        if (retAddr[1] == 0xF8 && retAddr[3] == 0xFF) return TRUE;
        if (retAddr[1] == 0xC8 && retAddr[3] == 0xC9) return TRUE;
    }
    return FALSE;
}

/* ---------------- Layer 3: NavTable Bounds-Checked Methods ---------------- */

/* 005E1ED0: bool __thiscall GetNodePos(NavTable *this, float out[4], int idx) */
static BYTE __fastcall Hook_005E1ED0(NavTable *self, void *edx_unused, float *out, int idx) {
    const float *p;
    (void)edx_unused;
    if (!self || !self->active) return 0;
    if (idx == 0x7FFFFE) {
        out[0] = *(const float *)0x0077A034;
        out[1] = *(const float *)0x007703C4;
        out[2] = *(const float *)0x0077A030;
        return 1;
    }
    if (idx == 0x7FFFF7) {
        out[0] = *(const float *)0x0077A02C;
        out[1] = *(const float *)0x007703C4;
        out[2] = *(const float *)0x0077A028;
        return 1;
    }
    if (!ValidNodeIndex(self, idx, "GetNodePos(005E1ED0)")) {
        /* Only zero stack buffers; if out points to an object field (e.g. &npc->pos), preserve it. */
        if (out && IsOnCurrentThreadStack(out)) {
            out[0] = 0.0f; out[1] = 0.0f; out[2] = 0.0f; out[3] = 0.0f;
        }
        return 0;
    }
    p = (const float *)(self->nodes + idx * 0x3C + 4);
    out[0] = p[0];
    out[1] = p[1];
    out[2] = p[2];
    out[3] = 0.0f;
    return 1;
}

/* 005E19E0: void __thiscall GetNodeRot(NavTable *this, float out[4], int idx) */
static void __fastcall Hook_005E19E0(NavTable *self, void *edx_unused, float *out, int idx) {
    const float *p;
    (void)edx_unused;
    if (!self || !self->active) return;
    if (idx == 0x7FFFFE) {
        out[0] = 0.0f;
        out[1] = *(const float *)0x007768A4;
        out[2] = 0.0f;
        out[3] = *(const float *)0x007768A4;
        return;
    }
    if (idx == 0x7FFFF7) {
        out[0] = 0.0f;
        out[1] = *(const float *)0x00773508;
        out[2] = 0.0f;
        out[3] = *(const float *)0x00773508;
        return;
    }
    if (!ValidNodeIndex(self, idx, "GetNodeRot(005E19E0)")) {
        if (out && IsOnCurrentThreadStack(out)) {
            out[0] = 0.0f; out[1] = 0.0f; out[2] = 0.0f; out[3] = 0.0f;
        }
        return;
    }
    p = (const float *)(self->nodes + idx * 0x3C + 0x10);
    out[0] = p[0];
    out[1] = p[1];
    out[2] = p[2];
    out[3] = 0.0f;
}

/* 005E1A70: void __thiscall GetNodeScale(NavTable *this, float out[4], int idx) */
static void __fastcall Hook_005E1A70(NavTable *self, void *edx_unused, float *out, int idx) {
    const float *p;
    (void)edx_unused;
    if (!self || !self->active) return;
    if (idx == 0x7FFFFE || idx == 0x7FFFF7) {
        out[0] = 1.0f; out[1] = 1.0f; out[2] = 1.0f; out[3] = 0.0f;
        return;
    }
    if (!ValidNodeIndex(self, idx, "GetNodeScale(005E1A70)")) {
        if (out && IsWritable(out, 16)) {
            out[0] = 1.0f; out[1] = 1.0f; out[2] = 1.0f; out[3] = 0.0f;
        }
        return;
    }
    p = (const float *)(self->nodes + idx * 0x3C + 0x1C);
    out[0] = p[0];
    out[1] = p[1];
    out[2] = p[2];
    out[3] = 0.0f;
}

/* 005E1AE0: void* __thiscall GetNodeInfoPtr(NavTable *this, int idx) */
static void *__fastcall Hook_005E1AE0(NavTable *self, void *edx_unused, int idx) {
    const BYTE *retAddr = (const BYTE *)__builtin_return_address(0);
    DWORD off;
    BYTE *base;
    (void)edx_unused;
    if (!self || !self->active) {
        return CallerChecksNull(retAddr) ? NULL : GetFreshDummyNodeInfo();
    }
    if (idx == 0x7FFFFE || idx == 0x7FFFF7) return (void *)0x008AF214;
    if (!ValidNodeIndex(self, idx, "GetNodeInfoPtr(005E1AE0)") || !self->strTable) {
        if (idx < 0 && CallerChecksNull(retAddr)) return NULL;
        return GetFreshDummyNodeInfo();
    }
    off = *(DWORD *)(self->nodes + idx * 0x3C + 0x34);
    base = self->strTable;
    return base + off + base[off] + 1;
}

/* 005E1B30: void __thiscall GetNodeExtraVec(NavTable *this, float out[4], int idx) */
static void __fastcall Hook_005E1B30(NavTable *self, void *edx_unused, float *out, int idx) {
    BYTE *entry;
    const float *p;
    (void)edx_unused;
    if (!self || !self->active || !ValidNodeIndex(self, idx, "GetNodeExtraVec(005E1B30)")) {
        if (out && IsOnCurrentThreadStack(out)) {
            out[0] = 0.0f; out[1] = 0.0f; out[2] = 0.0f; out[3] = 0.0f;
        }
        return;
    }
    entry = self->nodes + idx * 0x3C;
    if (entry[0] != 1 || !self->extraTable) return;
    p = (const float *)(self->extraTable + *(DWORD *)(entry + 0x38) + 4);
    out[0] = p[0];
    out[1] = p[1];
    out[2] = p[2];
    out[3] = 0.0f;
}

/* 005E1B70: float __thiscall GetNodeExtraFloat10(NavTable *this, int idx) */
static float __fastcall Hook_005E1B70(NavTable *self, void *edx_unused, int idx) {
    BYTE *entry;
    (void)edx_unused;
    if (!self || !self->active || !ValidNodeIndex(self, idx, "GetNodeExtraFloat10(005E1B70)") || !self->extraTable)
        return 0.0f;
    entry = self->nodes + idx * 0x3C;
    if (entry[0] != 1) return 0.0f;
    return *(const float *)(self->extraTable + *(DWORD *)(entry + 0x38) + 0x10);
}

/* 005E1BA0: float __thiscall GetNodeExtraFloat14(NavTable *this, int idx) */
static float __fastcall Hook_005E1BA0(NavTable *self, void *edx_unused, int idx) {
    BYTE *entry;
    (void)edx_unused;
    if (!self || !self->active || !ValidNodeIndex(self, idx, "GetNodeExtraFloat14(005E1BA0)") || !self->extraTable)
        return 0.0f;
    entry = self->nodes + idx * 0x3C;
    if (entry[0] != 1) return 0.0f;
    return *(const float *)(self->extraTable + *(DWORD *)(entry + 0x38) + 0x14);
}

/* 005E1BD0: DWORD __thiscall GetNodeExtraDword18(NavTable *this, int idx) */
static DWORD __fastcall Hook_005E1BD0(NavTable *self, void *edx_unused, int idx) {
    BYTE *entry;
    (void)edx_unused;
    if (!self || !self->active || !ValidNodeIndex(self, idx, "GetNodeExtraDword18(005E1BD0)") || !self->extraTable)
        return 0;
    entry = self->nodes + idx * 0x3C;
    if (entry[0] != 1) return 0;
    return *(const DWORD *)(self->extraTable + *(DWORD *)(entry + 0x38) + 0x18);
}

/* 005E1C00: void* __thiscall GetNodeExtraPtr1D(NavTable *this, int idx) */
static void *__fastcall Hook_005E1C00(NavTable *self, void *edx_unused, int idx) {
    const BYTE *retAddr = (const BYTE *)__builtin_return_address(0);
    BYTE *entry;
    (void)edx_unused;
    if (!self || !self->active || !ValidNodeIndex(self, idx, "GetNodeExtraPtr1D(005E1C00)") || !self->extraTable) {
        return CallerChecksNull(retAddr) ? NULL : GetFreshDummyExtraStr();
    }
    entry = self->nodes + idx * 0x3C;
    if (entry[0] != 1) return NULL;
    return (void *)(self->extraTable + *(DWORD *)(entry + 0x38) + 0x1D);
}

/* 005E19B0: int __thiscall GetGridCellNode(NavTable *this, int cellIdx, int subIdx) */
static int __fastcall Hook_005E19B0(NavTable *self, void *edx_unused, int cellIdx, int subIdx) {
    DWORD **cellTable;
    DWORD *cellPtr;
    BYTE *entry;
    (void)edx_unused;
    if (!self || cellIdx < 0 || subIdx < 0) return -1;
    cellTable = *(DWORD ***)((BYTE *)self + 0x2320);
    if (!cellTable || !IsReadable(cellTable + cellIdx, 4)) return -1;
    cellPtr = cellTable[cellIdx];
    if (!cellPtr) return -1;
    entry = (BYTE *)(cellPtr + subIdx);
    if (!IsReadable(entry, 4)) return -1;
    if ((int)*(WORD *)(entry + 2) != cellIdx) return -1;
    return (int)*(WORD *)entry;
}

/* 005E2150: int __thiscall GetNodeTypeSlot(NavTable *this, int idx)
   Fixes vanilla bug where negative idx bypassed CMP EAX, ESI; JG and indexed nodes[idx] before TEST EAX, EAX! */
static int __fastcall Hook_005E2150(NavTable *self, void *edx_unused, int idx) {
    static const int kOffsets[6] = { 0, 6, 9, 0x3E1, 0x758, 0x767 };
    BYTE *entry;
    int type;
    WORD sub;
    (void)edx_unused;
    if (!self || !self->active) return 0;
    if (!ValidNodeIndex(self, idx, "GetNodeTypeSlot(005E2150)")) return 1;
    entry = self->nodes + idx * 0x3C;
    type = (int)(entry[0] & 0x0F);
    if (type < 0 || type >= 6) type = 0;
    sub = *(const WORD *)(entry + 2);
    return kOffsets[type] + (int)sub + 1;
}

/* 005E21F0: const char* __thiscall GetNodeSubStr(NavTable *this, int subIdx, int idx)
   Fixes vanilla bug where negative idx bypassed CMP EAX, [ECX+8]; JG! */
static void *__fastcall Hook_005E21F0(NavTable *self, void *edx_unused, int subIdx, int idx) {
    BYTE *entry, *base;
    int off;
    (void)edx_unused;
    if (!self || !self->active) return NULL;
    if (!ValidNodeIndex(self, idx, "GetNodeSubStr(005E21F0)") || !self->extraTable) return NULL;
    entry = self->nodes + idx * 0x3C;
    if ((entry[0] & 0x0F) < 2) return NULL;
    base = self->extraTable + *(DWORD *)(entry + 0x38) + 4;
    off = (subIdx <= 0) ? 4 : (int)base[subIdx - 1];
    return (void *)(base + off);
}

/* 005E2240: int __thiscall GetNodeSubVal(NavTable *this, int subIdx, int idx)
   Fixes vanilla bug where negative idx bypassed CMP EAX, [ECX+8]; JG! */
static int __fastcall Hook_005E2240(NavTable *self, void *edx_unused, int subIdx, int idx) {
    BYTE *entry, *p, *arr;
    (void)edx_unused;
    if (!self || !self->active || subIdx < 0) return -1;
    if (!ValidNodeIndex(self, idx, "GetNodeSubVal(005E2240)") || !self->extraTable) return -1;
    entry = self->nodes + idx * 0x3C;
    if ((entry[0] & 0x0F) < 2) return -1;
    p = self->extraTable + *(DWORD *)(entry + 0x38);
    arr = p + 4 + p[7];
    return *(const int *)(arr + subIdx * 4);
}

/* 004D8750: int __thiscall GetNodeNeighborCount(void *this, short relIdx) */
static int __fastcall Hook_004D8750(void *self, void *edx_unused, int relIdx) {
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    int idx;
    DWORD off;
    (void)self;
    (void)edx_unused;
    if (!nav->active) return 0;
    idx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)relIdx;
    if (!ValidNodeIndex(nav, idx, "GetNodeNeighborCount(004D8750)") || !nav->adjWords) return 0;
    off = *(DWORD *)(nav->nodes + idx * 0x3C + 0x30);
    return (int)nav->adjWords[off];
}

/* 004D8790: int __thiscall GetNodeNeighborRelIdx(void *this, short relIdx, int neighborNum)
   Fixes both out-of-bounds relIdx and vanilla's nav->active == 0 bug that dereferenced relIdx as a pointer! */
static int __fastcall Hook_004D8790(void *self, void *edx_unused, int relIdx, int neighborNum) {
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    int idx, count, targetAbs, slot, res;
    DWORD off;
    (void)self;
    (void)edx_unused;
    if (!nav->active || neighborNum < 0) return -1;
    idx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)relIdx;
    if (!ValidNodeIndex(nav, idx, "GetNodeNeighborRelIdx(004D8790)") || !nav->adjWords) return -1;
    off = *(DWORD *)(nav->nodes + idx * 0x3C + 0x30);
    count = (int)nav->adjWords[off];
    if (neighborNum >= count) return -1;
    targetAbs = (int)nav->adjWords[off + 1 + neighborNum];
    if (targetAbs < 0) return -1;
    slot = Hook_005E2150(nav, NULL, targetAbs);
    if (slot != 1) return -1;
    res = targetAbs - (int)*((const WORD *)0x01438B9C + slot);
    return ((short)res == -1) ? -1 : res;
}

/* 004D8860: int __thiscall GetNodeNeighborRaw(void *this, short relIdx, int neighborNum) */
static int __fastcall Hook_004D8860(void *self, void *edx_unused, int relIdx, int neighborNum) {
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    int idx, count;
    DWORD off;
    (void)self;
    (void)edx_unused;
    if (!nav->active || neighborNum < 0) return 0;
    idx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)relIdx;
    if (!ValidNodeIndex(nav, idx, "GetNodeNeighborRaw(004D8860)") || !nav->adjWords) return 0;
    off = *(DWORD *)(nav->nodes + idx * 0x3C + 0x30);
    count = (int)nav->adjWords[off];
    if (neighborNum >= count) return 0;
    return (int)nav->adjWords[off + 1 + neighborNum];
}

/* ---------------- Layer 1: SetAiState (0x0047D710) Invalid Waypoint Guard ---------------- */

/* Returns:
   1 -> waypoint is valid; jump to 0x0047D7D1 (normal walk setup)
   2 -> waypoint is invalid and charType == 7; jump to 0x0047D8AC (vanilla charType 7 behavior)
   0 -> waypoint is invalid and charType != 7; set Idle (aiState=0) and jump to 0x0047D8C0 (clean return) */
static int __fastcall CheckSetAiStateWalk(BYTE *npc) {
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    short rawIdx;
    int actualIdx;
    BOOL valid;
    BYTE charType = 0;

    if (!npc || !IsReadable(npc, 0x800)) return 0;
    rawIdx = *(const short *)(npc + 0x634);
    actualIdx = (int)*(const WORD *)NAV_BASE_WORD + (int)rawIdx;
    valid = (rawIdx != -1) &&
            (actualIdx == 0x7FFFFE || actualIdx == 0x7FFFF7 ||
             (nav->active && nav->nodes && actualIdx >= 0 && actualIdx < nav->maxIndex));
    if (valid) return 1;

    /* Call vtable[+0xA4]() to obtain charType just like vanilla 0047D7BD..0047D7C7 */
    {
        typedef BYTE(__fastcall * PFN_GetCharType)(void *self, void *edx_unused);
        void **vtbl = *(void ***)npc;
        if (IsReadable(vtbl, 0xA8) && IsExec((DWORD)vtbl[0xA4 / 4])) {
            PFN_GetCharType fn = (PFN_GetCharType)vtbl[0xA4 / 4];
            charType = fn(npc, NULL);
        }
    }

    /* Synchronize npc->targetPos ([npc + 0x7BC]) with npc->pos ([npc + 0x58]) so distance is 0.0f */
    if (IsWritable(npc + 0x7BC, 16)) {
        const float *pos = (const float *)(npc + 0x58);
        float *targetPos = (float *)(npc + 0x7BC);
        targetPos[0] = pos[0];
        targetPos[1] = pos[1];
        targetPos[2] = pos[2];
        targetPos[3] = pos[3];
    }

    NotePrevented("Layer1:SetAiState_Walk(0047D710)", actualIdx, nav->maxIndex);

    if (charType == 7) return 2;

    /* Transition NPC cleanly to Idle (aiState = 0, aiSubState = 0) instead of walking to waypoint -1 */
    npc[0x618] = 0;
    npc[0x619] = 0;
    npc[0x665] = 0;
    return 0;
}

static DWORD g_jmp_0047D7D1 = 0x0047D7D1;
static DWORD g_jmp_0047D8AC = 0x0047D8AC;
static DWORD g_jmp_0047D8C0 = 0x0047D8C0;

__attribute__((naked)) static void Stub_0047D7B3(void) {
    __asm__ volatile (
        "movl %%esi, %%ecx\n\t"
        "call %P0\n\t"
        "cmpl $1, %%eax\n\t"
        "je 1f\n\t"
        "cmpl $2, %%eax\n\t"
        "je 2f\n\t"
        "jmpl *%1\n\t"
        "1:\n\t"
        "jmpl *%2\n\t"
        "2:\n\t"
        "jmpl *%3\n\t"
        :
        : "i"(CheckSetAiStateWalk), "m"(g_jmp_0047D8C0), "m"(g_jmp_0047D7D1), "m"(g_jmp_0047D8AC)
    );
}

/* Secondary safeguard at 0047D804 (CALL 004D8980 inside 0047D710) */
static BYTE __fastcall Hook_0047D804_Call(void *navMgr, void *edx_unused, float *out, int rawIdx) {
    int actualIdx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)rawIdx;
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    (void)navMgr;
    (void)edx_unused;
    if (Hook_005E1ED0(nav, NULL, out, actualIdx)) return 1;
    if (out && IsWritable(out, 16)) {
        const float *charPos = (const float *)((const BYTE *)out - (0x7BC - 0x58));
        if (IsReadable(charPos, 16)) {
            out[0] = charPos[0];
            out[1] = charPos[1];
            out[2] = charPos[2];
            out[3] = charPos[3];
        }
    }
    return 0;
}

/* ---------------- Layer 2: OnReachedWaypoint (0x004CCD00) & GetWaypointPos (0x004D8980) ---------------- */

static BOOL LooksLikeCharWithWaypoint(const BYTE *reg, short rawIdx) {
    DWORD vt;
    if (!reg || ((DWORD)reg & 3) || !IsReadable(reg, 0x640)) return FALSE;
    vt = *(const DWORD *)reg;
    if (vt < 0x0076E000 || vt >= 0x008B0000 || !IsReadable((const void *)vt, 0x100)) return FALSE;
    if (!IsExec(*(const DWORD *)(vt + 0xA4))) return FALSE;
    return *(const short *)(reg + 0x630) == rawIdx ||
           *(const short *)(reg + 0x632) == rawIdx ||
           *(const short *)(reg + 0x634) == rawIdx ||
           *(const short *)(reg + 0x636) == rawIdx ||
           *(const short *)(reg + 0x638) == rawIdx ||
           *(const short *)(reg + 0x63C) == rawIdx;
}

/* Called by Stub_004CCD50_Call (at 004CCD50 and 004D1363) where ESI = npc and out is stack buffer
   about to be copied into npc->pos ([ESI + 0x58]) or rider->pos. */
static BYTE __stdcall C_Hook_004CCD50(float *out, int rawIdx, BYTE *npc) {
    int actualIdx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)rawIdx;
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    if (Hook_005E1ED0(nav, NULL, out, actualIdx)) return 1;

    NotePrevented("Layer2:OnReachedWaypoint_PosCopy(004CCD50)", actualIdx, nav->maxIndex);
    if (out && IsWritable(out, 16) && npc && IsReadable(npc + 0x58, 16)) {
        const float *srcPos = (const float *)(npc + 0x58);
        if (IsReadable(npc, 0x688) && npc[0x627] == 1) {
            const BYTE *rider = *(const BYTE *const *)(npc + 0x684);
            if (rider && IsReadable(rider + 0x58, 16)) {
                srcPos = (const float *)(rider + 0x58);
            }
        }
        out[0] = srcPos[0];
        out[1] = srcPos[1];
        out[2] = srcPos[2];
        out[3] = srcPos[3];
    }
    return 0;
}

__attribute__((naked)) static void Stub_004CCD50_Call(void) {
    __asm__ volatile (
        "pushl %%esi\n\t"
        "pushl 12(%%esp)\n\t"
        "pushl 12(%%esp)\n\t"
        "call %P0\n\t"
        "ret $8\n\t"
        :
        : "i"(C_Hook_004CCD50)
    );
}

/* General 004D8980 hook covering all 52 callers of GetWaypointPos(out, relIdx) */
static BYTE __stdcall C_Hook_004D8980(float *out, int rawIdx, BYTE *regEsi, BYTE *regEbp, BYTE *regEdi) {
    int actualIdx = (int)*(WORD *)NAV_BASE_WORD + (int)(short)rawIdx;
    NavTable *nav = (NavTable *)NAV_OBJ_ADDR;
    const BYTE *charCandidates[3];
    int i;

    if (Hook_005E1ED0(nav, NULL, out, actualIdx)) return 1;
    if (!out || !IsWritable(out, 16)) return 0;

    charCandidates[0] = regEsi;
    charCandidates[1] = regEbp;
    charCandidates[2] = regEdi;

    for (i = 0; i < 3; i++) {
        const BYTE *c = charCandidates[i];
        if (!c) continue;
        /* If caller passed &npc->pos ([c + 0x58]) directly as out, preserve it! */
        if ((const BYTE *)out == c + 0x58 && IsReadable(c + 0x58, 16)) {
            return 0;
        }
        /* If caller passed &npc->targetPos ([c + 0x7BC]) or c is a character holding rawIdx, copy npc->pos */
        if (((const BYTE *)out == c + 0x7BC && IsReadable(c + 0x58, 16)) ||
            LooksLikeCharWithWaypoint(c, (short)rawIdx)) {
            const float *pos = (const float *)(c + 0x58);
            out[0] = pos[0];
            out[1] = pos[1];
            out[2] = pos[2];
            out[3] = pos[3];
            return 0;
        }
    }
    return 0;
}

__attribute__((naked)) static void Stub_004D8980(void) {
    __asm__ volatile (
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "pushl %%esi\n\t"
        "pushl 20(%%esp)\n\t"
        "pushl 20(%%esp)\n\t"
        "call %P0\n\t"
        "ret $8\n\t"
        :
        : "i"(C_Hook_004D8980)
    );
}

/* ---------------- patching helpers ---------------- */
static BOOL WriteJmp(DWORD fromVA, void *toFunc) {
    DWORD old;
    BYTE buf[5];
    if (!VirtualProtect((void *)fromVA, 5, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    buf[0] = 0xE9;
    *(DWORD *)(buf + 1) = (DWORD)toFunc - (fromVA + 5);
    memcpy((void *)fromVA, buf, 5);
    VirtualProtect((void *)fromVA, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)fromVA, 5);
    return TRUE;
}

static BOOL WriteJmpNop(DWORD fromVA, void *toFunc, int totalBytes) {
    DWORD old;
    BYTE buf[16];
    int i;
    if (totalBytes < 5 || totalBytes > (int)sizeof buf) return FALSE;
    if (!VirtualProtect((void *)fromVA, totalBytes, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    buf[0] = 0xE9;
    *(DWORD *)(buf + 1) = (DWORD)toFunc - (fromVA + 5);
    for (i = 5; i < totalBytes; i++) buf[i] = 0x90;
    memcpy((void *)fromVA, buf, totalBytes);
    VirtualProtect((void *)fromVA, totalBytes, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)fromVA, totalBytes);
    return TRUE;
}

static BOOL WriteCall(DWORD callVA, void *toFunc) {
    DWORD old;
    BYTE buf[5];
    if (!VirtualProtect((void *)callVA, 5, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    buf[0] = 0xE8;
    *(DWORD *)(buf + 1) = (DWORD)toFunc - (callVA + 5);
    memcpy((void *)callVA, buf, 5);
    VirtualProtect((void *)callVA, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void *)callVA, 5);
    return TRUE;
}

static void ApplyFixes(void) {
    int layer12Ok = 0, layer3Ok = 0;

    /* Initialize writable dummy buffers before any hooks go live */
    GetFreshDummyNodeInfo();
    GetFreshDummyExtraStr();

    /* Verify DP.exe code signatures before patching */
    if (!IsReadable((void *)0x005E1ED0, 16) ||
        *(BYTE *)0x005E1ED0 != 0x80 ||
        *(BYTE *)0x005E1AE0 != 0x80 ||
        *(BYTE *)0x0047D7B3 != 0x66 ||
        *(BYTE *)0x0047D804 != 0xE8 ||
        *(BYTE *)0x004CCD50 != 0xE8) {
        Logf("[CrashFix] WARNING: Process does not match expected DP.exe signatures; skipping binary patches");
        return;
    }

    if (cfgNavTableBoundsFix) {
        layer3Ok += WriteJmp(0x005E1ED0, (void *)Hook_005E1ED0);
        layer3Ok += WriteJmp(0x005E19E0, (void *)Hook_005E19E0);
        layer3Ok += WriteJmp(0x005E1A70, (void *)Hook_005E1A70);
        layer3Ok += WriteJmp(0x005E1AE0, (void *)Hook_005E1AE0);
        layer3Ok += WriteJmp(0x005E1B30, (void *)Hook_005E1B30);
        layer3Ok += WriteJmp(0x005E1B70, (void *)Hook_005E1B70);
        layer3Ok += WriteJmp(0x005E1BA0, (void *)Hook_005E1BA0);
        layer3Ok += WriteJmp(0x005E1BD0, (void *)Hook_005E1BD0);
        layer3Ok += WriteJmp(0x005E1C00, (void *)Hook_005E1C00);
        layer3Ok += WriteJmp(0x005E19B0, (void *)Hook_005E19B0);
        layer3Ok += WriteJmp(0x005E2150, (void *)Hook_005E2150);
        layer3Ok += WriteJmp(0x005E21F0, (void *)Hook_005E21F0);
        layer3Ok += WriteJmp(0x005E2240, (void *)Hook_005E2240);
        layer3Ok += WriteJmp(0x004D8750, (void *)Hook_004D8750);
        layer3Ok += WriteJmp(0x004D8790, (void *)Hook_004D8790);
        layer3Ok += WriteJmp(0x004D8860, (void *)Hook_004D8860);
        Logf("[CrashFix] Layer 3 NavTableBoundsFix applied (%d/16 hooks active)", layer3Ok);
    } else {
        Logf("[CrashFix] Layer 3 NavTableBoundsFix disabled in CrashFix.ini");
    }

    if (cfgEpisode2WaypointFix) {
        layer12Ok += WriteJmpNop(0x0047D7B3, (void *)Stub_0047D7B3, 8);
        layer12Ok += WriteCall(0x0047D804, (void *)Hook_0047D804_Call);
        layer12Ok += WriteCall(0x004CCD50, (void *)Stub_004CCD50_Call);
        layer12Ok += WriteCall(0x004D1363, (void *)Stub_004CCD50_Call);
        layer12Ok += WriteJmp(0x004D8980, (void *)Stub_004D8980);
        Logf("[CrashFix] Layer 1 & 2 Episode2CutsceneWaypointFix applied (%d/5 hooks active: 0047D7B3, 0047D804, 004CCD50, 004D1363, 004D8980)", layer12Ok);
    } else {
        Logf("[CrashFix] Layer 1 & 2 Episode2CutsceneWaypointFix disabled in CrashFix.ini");
    }
}

/* ---------------- init ---------------- */
static void Init(void) {
    char dir[MAX_PATH], ini[MAX_PATH + 32], logp[MAX_PATH + 32], prev[MAX_PATH + 32], exe[MAX_PATH];
    char *slash;

    /* Avoid duplicate initialization if Ultimate ASI Loader scans both root and scripts\ */
    if (GetEnvironmentVariableA("DP_CRASHFIX_ACTIVE", dir, sizeof dir) > 0) return;
    SetEnvironmentVariableA("DP_CRASHFIX_ACTIVE", "1");

    GetModuleFileNameA(g_self, dir, MAX_PATH);
    {
        char *c;
        slash = NULL;
        for (c = dir; *c; c++)
            if (*c == '\\') slash = c;
    }
    if (slash) *slash = 0;

    wsprintfA(ini, "%s\\CrashFix.ini", dir);
    cfgEpisode2WaypointFix = GetPrivateProfileIntA("Fixes", "Episode2CutsceneWaypointFix", cfgEpisode2WaypointFix, ini);
    cfgNavTableBoundsFix   = GetPrivateProfileIntA("Fixes", "NavTableBoundsFix", cfgNavTableBoundsFix, ini);
    cfgLogPrevented        = GetPrivateProfileIntA("Fixes", "LogPreventedCrashes", cfgLogPrevented, ini);
    cfgMaxPreventedLogs    = GetPrivateProfileIntA("Fixes", "MaxPreventedLogs", cfgMaxPreventedLogs, ini);

    wsprintfA(g_dir, "%s\\CrashLogs", dir);
    CreateDirectoryA(g_dir, NULL);
    wsprintfA(logp, "%s\\CrashFix.log", g_dir);
    wsprintfA(prev, "%s\\CrashFix.prev.log", g_dir);
    MoveFileExA(logp, prev, MOVEFILE_REPLACE_EXISTING);
    InitializeCriticalSection(&g_logLock);
    g_log = CreateFileA(logp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    GetModuleFileNameA(NULL, exe, MAX_PATH);
    Logf("CrashFix %s loaded into %s (base %08X, pid %u, tid %u)", CRASHFIX_VERSION, exe,
         (DWORD)GetModuleHandleA(NULL), GetCurrentProcessId(), GetCurrentThreadId());
    Logf("Config: Episode2CutsceneWaypointFix=%d NavTableBoundsFix=%d LogPreventedCrashes=%d MaxPreventedLogs=%d",
         cfgEpisode2WaypointFix, cfgNavTableBoundsFix, cfgLogPrevented, cfgMaxPreventedLogs);

    ApplyFixes();
    if (g_log != INVALID_HANDLE_VALUE) FlushFileBuffers(g_log);
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
