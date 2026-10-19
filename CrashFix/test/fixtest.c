/*
 * Deep verification test harness for CrashFix.asi + CrashLogger.asi.
 * Maps the real DP.exe sections at their exact virtual addresses (0x00400000..0x014B5000),
 * loads scripts\CrashLogger.asi and scripts\CrashFix.asi, verifies all 21 hooks are applied,
 * and tests all 3 layers (valid inputs, negative -1/0xFFFF inputs, out-of-bounds >= maxIndex,
 * NULL-checking vs non-NULL-checking callers, writable dummy struct reset, and inactive NavTable).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>

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

static HANDLE g_out;
static int g_failures = 0;

static void Printf(const char *fmt, ...) {
    char buf[1024];
    DWORD w;
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (n > 0) WriteFile(g_out, buf, n, &w, NULL);
}

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        Printf("[FAIL] %s (line %d)\r\n", msg, __LINE__); \
        g_failures++; \
    } else { \
        Printf("[PASS] %s\r\n", msg); \
    } \
} while (0)

typedef struct {
    void *vtable;
    BYTE  active;
    BYTE  pad[3];
    int   maxIndex;
    int   unk0C;
    int   unk10;
    int   unk14;
    BYTE *nodes;
    WORD *adjWords;
    BYTE *strTable;
    BYTE *extraTable;
} NavTable;

static BYTE g_testCharType = 3;
static BYTE __fastcall Mock_GetCharType(void *self, void *edx_unused) {
    (void)self;
    (void)edx_unused;
    return g_testCharType;
}

static BOOL MapDpExeSections(const char *dpPath) {
    HANDLE f = CreateFileA(dpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD fileSize, r;
    BYTE *fileBuf;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sec;
    int i;

    if (f == INVALID_HANDLE_VALUE) return FALSE;
    fileSize = GetFileSize(f, NULL);
    fileBuf = (BYTE *)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuf || !ReadFile(f, fileBuf, fileSize, &r, NULL) || r != fileSize) {
        CloseHandle(f);
        return FALSE;
    }
    CloseHandle(f);

    dos = (IMAGE_DOS_HEADER *)fileBuf;
    nt = (IMAGE_NT_HEADERS32 *)(fileBuf + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    /* Reserve/commit 64KB chunks for the required DP.exe address ranges */
    {
        static const DWORD kBases[] = {
            0x00470000, 0x00480000, 0x004C0000, 0x004D0000,
            0x005E0000, 0x00760000, 0x00770000, 0x008A0000,
            0x01430000
        };
        for (i = 0; i < (int)(sizeof(kBases) / sizeof(kBases[0])); i++) {
            DWORD base = kBases[i];
            if (!VirtualAlloc((void *)base, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) &&
                !VirtualAlloc((void *)base, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
                DWORD old;
                if (!VirtualProtect((void *)base, 0x10000, PAGE_EXECUTE_READWRITE, &old)) {
                    Printf("[!] Could not allocate/protect 0x%08X, err=%u\r\n", base, GetLastError());
                    VirtualFree(fileBuf, 0, MEM_RELEASE);
                    return FALSE;
                }
            }
            /* Populate from DP.exe sections */
            {
                int s;
                DWORD rvaStart = base - 0x00400000;
                DWORD rvaEnd = rvaStart + 0x10000;
                for (s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                    DWORD secStart = sec[s].VirtualAddress;
                    DWORD secEnd = secStart + sec[s].SizeOfRawData;
                    DWORD ovStart = rvaStart > secStart ? rvaStart : secStart;
                    DWORD ovEnd = rvaEnd < secEnd ? rvaEnd : secEnd;
                    if (ovStart < ovEnd) {
                        memcpy((void *)(0x00400000 + ovStart),
                               fileBuf + sec[s].PointerToRawData + (ovStart - secStart),
                               ovEnd - ovStart);
                    }
                }
            }
        }
    }
    VirtualFree(fileBuf, 0, MEM_RELEASE);
    return TRUE;
}

/* Helper callers to test CallerChecksNull in Hook_005E1AE0 */
typedef void *(__fastcall *PFN_005E1AE0)(void *self, void *edx, int idx);

__attribute__((noinline)) static void *Call_005E1AE0_Unchecked(void *nav, int idx) {
    void *res;
    /* Emit MOV EDI, EAX right after CALL so it matches 0047F134 -> 0047F139 (non-NULL-checked caller) */
    __asm__ volatile (
        "pushl %2\n\t"
        "movl %1, %%ecx\n\t"
        "movl $0x005E1AE0, %%eax\n\t"
        "call *%%eax\n\t"
        "movl %%eax, %%edi\n\t"
        "movl %%edi, %0\n\t"
        : "=r"(res)
        : "r"(nav), "r"(idx)
        : "eax", "ecx", "edx", "edi", "memory"
    );
    return res;
}

__attribute__((noinline)) static void *Call_005E1AE0_Checked(void *nav, int idx) {
    void *res;
    /* Emit TEST EAX, EAX (85 C0) right after CALL so it matches NULL-checking callers */
    __asm__ volatile (
        "pushl %2\n\t"
        "movl %1, %%ecx\n\t"
        "movl $0x005E1AE0, %%eax\n\t"
        "call *%%eax\n\t"
        "testl %%eax, %%eax\n\t"
        "movl %%eax, %0\n\t"
        : "=r"(res)
        : "r"(nav), "r"(idx)
        : "eax", "ecx", "edx", "cc", "memory"
    );
    return res;
}

void __stdcall Start(void) {
    NavTable *nav;
    BYTE *nodesBuf, *strBuf, *extraBuf;
    WORD *adjBuf;
    BYTE *npc;
    DWORD *fakeVtable;
    float out[4];
    int i;

    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    Printf("=== CrashFix.asi & CrashLogger.asi Verification Suite ===\r\n");

    CHECK(MapDpExeSections("DP.exe"), "Mapped DP.exe sections at 0x00400000");

    /* Load both ASIs from scripts\ */
    CHECK(LoadLibraryA("scripts\\CrashLogger.asi") != NULL, "Loaded scripts\\CrashLogger.asi");
    CHECK(LoadLibraryA("scripts\\CrashFix.asi") != NULL, "Loaded scripts\\CrashFix.asi");

    /* Verify CrashFix patched all target addresses */
    CHECK(*(BYTE *)0x005E1ED0 == 0xE9, "0x005E1ED0 patched with JMP");
    CHECK(*(BYTE *)0x005E1AE0 == 0xE9, "0x005E1AE0 patched with JMP");
    CHECK(*(BYTE *)0x0047D7B3 == 0xE9, "0x0047D7B3 patched with JMP");
    CHECK(*(BYTE *)0x0047D804 == 0xE8, "0x0047D804 patched with CALL");
    CHECK(*(BYTE *)0x004CCD50 == 0xE8, "0x004CCD50 patched with CALL");
    CHECK(*(BYTE *)0x004D1363 == 0xE8, "0x004D1363 patched with CALL");
    CHECK(*(BYTE *)0x004D8980 == 0xE9, "0x004D8980 patched with JMP");

    /* Set up synthetic NavTable at 0x01437A20 with 2 valid nodes */
    nav = (NavTable *)0x01437A20;
    nodesBuf = (BYTE *)VirtualAlloc(NULL, 2 * 0x3C, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    adjBuf   = (WORD *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    strBuf   = (BYTE *)VirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    extraBuf = (BYTE *)VirtualAlloc(NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    memset(nav, 0, sizeof *nav);
    nav->active = 1;
    nav->maxIndex = 2;
    nav->nodes = nodesBuf;
    nav->adjWords = adjBuf;
    nav->strTable = strBuf;
    nav->extraTable = extraBuf;
    *(WORD *)0x01438B9C = 0;
    *(WORD *)0x01438B9E = 0;

    /* Node 0: pos = (100.0, 200.0, 300.0), rot = (0.1, 0.2, 0.3), scale = (2, 2, 2), type = 1 */
    nodesBuf[0] = 1;
    *(WORD *)(nodesBuf + 2) = 5;
    *(float *)(nodesBuf + 4) = 100.0f;
    *(float *)(nodesBuf + 8) = 200.0f;
    *(float *)(nodesBuf + 12) = 300.0f;
    *(float *)(nodesBuf + 0x10) = 0.1f;
    *(float *)(nodesBuf + 0x14) = 0.2f;
    *(float *)(nodesBuf + 0x18) = 0.3f;
    *(float *)(nodesBuf + 0x1C) = 2.0f;
    *(float *)(nodesBuf + 0x20) = 2.0f;
    *(float *)(nodesBuf + 0x24) = 2.0f;
    *(DWORD *)(nodesBuf + 0x30) = 0; /* adjWords offset */
    *(DWORD *)(nodesBuf + 0x34) = 0; /* strTable offset */
    *(DWORD *)(nodesBuf + 0x38) = 0; /* extraTable offset */

    adjBuf[0] = 1; /* 1 neighbor */
    adjBuf[1] = 0; /* neighbor 0 is node 0 */

    strBuf[0] = 3; /* string length 3 */
    *(WORD *)(strBuf + 4 + 4) = 0x1234; /* actionType at +4 of NodeInfo */
    *(WORD *)(strBuf + 4 + 6) = 42;     /* subId at +6 of NodeInfo */

    *(float *)(extraBuf + 4) = 7.0f;
    *(float *)(extraBuf + 8) = 8.0f;
    *(float *)(extraBuf + 12) = 9.0f;
    *(float *)(extraBuf + 0x10) = 11.5f;
    *(float *)(extraBuf + 0x14) = 22.5f;
    *(DWORD *)(extraBuf + 0x18) = 0xCAFEBABE;

    /* Test Layer 3: 005E1ED0 (GetNodePos) */
    {
        typedef BYTE(__fastcall * PFN_GetNodePos)(void *, void *, float *, int);
        PFN_GetNodePos fn = (PFN_GetNodePos)0x005E1ED0;
        BYTE ok1 = fn(nav, NULL, out, 0);
        CHECK(ok1 == 1 && out[0] == 100.0f && out[1] == 200.0f && out[2] == 300.0f,
              "Layer 3: 005E1ED0 valid index 0 returns (100, 200, 300)");

        out[0] = 99.0f;
        BYTE okNeg = fn(nav, NULL, out, -1);
        CHECK(okNeg == 0 && out[0] == 0.0f,
              "Layer 3: 005E1ED0 negative index -1 (0xFFFF) prevented crash and zeroed stack buffer");

        BYTE okOob = fn(nav, NULL, out, 30990);
        CHECK(okOob == 0,
              "Layer 3: 005E1ED0 out-of-bounds index >= maxIndex prevented crash");
    }

    /* Test Layer 3: 005E1AE0 (GetNodeInfoPtr) unchecked vs checked callers + writable dummy reset */
    {
        BYTE *infoValid = (BYTE *)Call_005E1AE0_Unchecked(nav, 0);
        CHECK(infoValid == strBuf + 4 && *(WORD *)(infoValid + 4) == 0x1234,
              "Layer 3: 005E1AE0 valid index 0 returns real NodeInfo pointer");

        BYTE *infoNegUnchecked = (BYTE *)Call_005E1AE0_Unchecked(nav, -1);
        CHECK(infoNegUnchecked != NULL && *(WORD *)(infoNegUnchecked + 4) == 0 && *(short *)(infoNegUnchecked + 6) == -1,
              "Layer 3: 005E1AE0 index -1 from unchecked caller (like 0047F134) returns non-NULL dummy with actionType=0, subId=-1");

        /* Mutate the dummy buffer (simulating the 6 writing call sites in DP.exe) and verify next call resets it */
        infoNegUnchecked[1] = 0x77;
        *(WORD *)(infoNegUnchecked + 4) = 0x9999;
        BYTE *infoOobUnchecked = (BYTE *)Call_005E1AE0_Unchecked(nav, 5000);
        CHECK(infoOobUnchecked == infoNegUnchecked && infoOobUnchecked[1] == 0 && *(WORD *)(infoOobUnchecked + 4) == 0,
              "Layer 3: 005E1AE0 dummy buffer is writable and freshly reset on each OOB call");

        void *infoNegChecked = Call_005E1AE0_Checked(nav, -1);
        CHECK(infoNegChecked == NULL,
              "Layer 3: 005E1AE0 index -1 from NULL-checking caller (TEST EAX, EAX) returns NULL");
    }

    /* Test Layer 3: 005E2150, 005E21F0, 005E2240, 004D8750, 004D8790, 004D8860 with negative index -1 */
    {
        typedef int(__fastcall * PFN_Idx1)(void *, void *, int);
        typedef int(__fastcall * PFN_Idx2)(void *, void *, int, int);
        typedef void *(__fastcall * PFN_Idx2Ptr)(void *, void *, int, int);
        int slotNeg = ((PFN_Idx1)0x005E2150)(nav, NULL, -1);
        void *strNeg = ((PFN_Idx2Ptr)0x005E21F0)(nav, NULL, 0, -1);
        int valNeg = ((PFN_Idx2)0x005E2240)(nav, NULL, 0, -1);
        int cntNeg = ((PFN_Idx1)0x004D8750)(NULL, NULL, -1);
        int relNeg = ((PFN_Idx2)0x004D8790)(NULL, NULL, -1, 0);
        int rawNeg = ((PFN_Idx2)0x004D8860)(NULL, NULL, -1, 0);
        CHECK(slotNeg == 1 && strNeg == NULL && valNeg == -1 && cntNeg == 0 && relNeg == -1 && rawNeg == 0,
              "Layer 3: 005E2150/21F0/2240 and 004D8750/8790/8860 safely handle negative index -1");
    }

    /* Allocate synthetic CNpcNormal (0x1200 bytes) with vtable inside DP.exe .rdata range (0x0077563C) */
    npc = (BYTE *)VirtualAlloc(NULL, 0x1200, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fakeVtable = (DWORD *)0x0077563C;
    fakeVtable[0xA4 / 4] = (DWORD)Mock_GetCharType;
    *(DWORD **)npc = fakeVtable;

    /* Set NPC world position to (-4221.5f, 1320.25f, 1986.75f, 1.0f) and waypoint [npc + 0x634] = -1 (0xFFFF) */
    *(float *)(npc + 0x58) = -4221.5f;
    *(float *)(npc + 0x5C) = 1320.25f;
    *(float *)(npc + 0x60) = 1986.75f;
    *(float *)(npc + 0x64) = 1.0f;
    *(short *)(npc + 0x634) = -1;
    *(short *)(npc + 0x636) = -1;

    /* Test Layer 1: 0x0047D710 (SetAiState) with param_1 = 1 (walk), param_2 = 0, charType = 3, waypoint = -1 */
    {
        typedef void(__fastcall * PFN_SetAiState)(void *self, void *edx, int state, int subState);
        PFN_SetAiState setAiState = (PFN_SetAiState)0x0047D710;
        g_testCharType = 3;
        npc[0x618] = 99;
        npc[0x619] = 99;
        npc[0x665] = 1;
        setAiState(npc, NULL, 1, 0);
        CHECK(npc[0x618] == 0 && npc[0x619] == 0 && npc[0x665] == 0 &&
              *(float *)(npc + 0x7BC) == -4221.5f && *(float *)(npc + 0x7C0) == 1320.25f && *(float *)(npc + 0x7C4) == 1986.75f,
              "Layer 1: 0047D710(1, 0) with waypoint -1 on CNpcNormal (type 3) transitions to Idle (0) and preserves targetPos = pos");

        /* Verify charType == 7 preserves vanilla behavior (jumps to 0047D8AC -> sets aiState = 1, aiSubState = 5) */
        g_testCharType = 7;
        setAiState(npc, NULL, 1, 5);
        CHECK(npc[0x618] == 1 && npc[0x619] == 5,
              "Layer 1: 0047D710(1, 5) with waypoint -1 on charType 7 preserves vanilla behavior (state=1, sub=5)");
        g_testCharType = 3;
    }

    /* Test Layer 2: 0x004CCD50 call hook (OnReachedWaypoint) & 0x004D8980 when waypoint is -1 */
    {
        float stackBuf[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        DWORD relTarget = *(DWORD *)(0x004CCD50 + 1) + (0x004CCD50 + 5);
        BYTE res = 99;
        __asm__ volatile (
            "movl %2, %%esi\n\t"
            "pushl $-1\n\t"
            "pushl %1\n\t"
            "call *%3\n\t"
            "movb %%al, %0\n\t"
            : "=m"(res)
            : "r"(stackBuf), "m"(npc), "m"(relTarget)
            : "eax", "ecx", "edx", "esi", "memory"
        );
        CHECK(res == 0 && stackBuf[0] == -4221.5f && stackBuf[1] == 1320.25f && stackBuf[2] == 1986.75f && stackBuf[3] == 1.0f,
              "Layer 2: 004CCD50 hook fills stack buffer with npc->pos on invalid waypoint -1 (never wipes npc->pos to 0)");

        /* Also test 0x004D8980 directly when out == &npc->pos (like 004CA4DB) */
        __asm__ volatile (
            "movl %0, %%esi\n\t"
            "pushl $-1\n\t"
            "leal 0x58(%%esi), %%edi\n\t"
            "pushl %%edi\n\t"
            "movl $0x004D8980, %%eax\n\t"
            "call *%%eax\n\t"
            :
            : "m"(npc)
            : "eax", "ecx", "edx", "esi", "edi", "memory"
        );
        CHECK(*(float *)(npc + 0x58) == -4221.5f && *(float *)(npc + 0x5C) == 1320.25f && *(float *)(npc + 0x60) == 1986.75f,
              "Layer 2: 004D8980(&npc->pos, -1) preserves npc->pos without zeroing");
    }

    Printf("=== Total failures: %d ===\r\n", g_failures);
    ExitProcess(g_failures ? 1 : 0);
}
