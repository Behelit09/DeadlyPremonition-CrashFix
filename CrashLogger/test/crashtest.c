/* Test harness: loads CrashLogger.asi (same folder) like the ASI loader would, then crashes on purpose.
   usage: crashtest.exe a|s|d   (access violation / stack overflow / divide by zero)
   Built with -nostdlib, entry point = Start. */
#include <windows.h>

static volatile int g_zero = 0;

__attribute__((noinline)) static int Recurse(int n) {
    volatile char pad[512];
    pad[0] = (char)n;
    return Recurse(n + 1) + pad[0];
}

__attribute__((noinline)) static void DoAV(void) {
    volatile int *p = (volatile int *)(DWORD_PTR)(0x24 + g_zero);
    *p = 1;
}

void __stdcall Start(void) {
    char exe[MAX_PATH], *c, *slash = NULL, mode;
    const char *cmd = GetCommandLineA();
    HANDLE f;
    int len = lstrlenA(cmd);
    while (len > 0 && cmd[len - 1] == ' ') len--;
    mode = len ? cmd[len - 1] : 'a';

    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    for (c = exe; *c; c++) if (*c == '\\') slash = c;
    if (slash) lstrcpyA(slash + 1, "CrashLogger.asi");
    if (!LoadLibraryA(exe)) ExitProcess(3);

    f = CreateFileA("crashtest_breadcrumb.tmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    Sleep(300);
    if (mode == 'a') DoAV();
    if (mode == 's') ExitProcess(Recurse(0));
    if (mode == 'd') ExitProcess(10 / g_zero);
    ExitProcess(0);
}
