/* Stands in for VC6's c2.dll (cl /B2): loads the real back end, C2REAL,
   and forwards both entry points to it. With C2O_BREAK set it stops on an
   int 3 first, so a debugger attached to cl.exe can plant breakpoints in
   c2.dll once it is mapped. Build: cl /nologo /O2 /LD c2stub.c */
#include <windows.h>
#include <stdlib.h>

typedef int (__stdcall *INVOKE)(int, char **, void *);
typedef void (__stdcall *ABORT)(int);

static HMODULE real;

static void load(void)
{
    if (!real)
        real = LoadLibrary(getenv("C2REAL"));
}

__declspec(dllexport) int __stdcall InvokeCompilerPass(int argc, char **argv, void *x)
{
    INVOKE f;
    load();
    f = (INVOKE)GetProcAddress(real, "_InvokeCompilerPass@12");
    if (getenv("C2O_BREAK"))
        __asm int 3
    return f(argc, argv, x);
}

__declspec(dllexport) void __stdcall AbortCompilerPass(int x)
{
    ABORT f;
    load();
    f = (ABORT)GetProcAddress(real, "_AbortCompilerPass@4");
    f(x);
}
