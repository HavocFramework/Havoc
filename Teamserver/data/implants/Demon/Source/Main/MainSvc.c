#include <Demon.h>

// Service status handle
SERVICE_STATUS_HANDLE StatusHandle = NULL;

// Service Entrypoint functions
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv );
VOID WINAPI SrvCtrlHandler( DWORD CtrlCode );

// Our entrypoint for Windows service executable.
INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain (Service Main): hInstance:[%p]\n", hInstance )

    SERVICE_TABLE_ENTRY DispatchTable[ ] = {
            { SERVICE_NAME, SvcMain },
            { NULL, NULL }
    };

    StartServiceCtrlDispatcherA( DispatchTable );

    return 0;
}

VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv )
{
    StatusHandle = RegisterServiceCtrlHandlerA( SERVICE_NAME, SrvCtrlHandler );
    if ( ! StatusHandle )
        return;

    // fire up our demon agent...
    DemonMain( NULL );
}

VOID WINAPI SrvCtrlHandler( DWORD CtrlCode )
{
    if ( CtrlCode == SERVICE_CONTROL_STOP )
    {
        SetServiceStatus( StatusHandle, &StatusHandle );
        ExitProcess( 0 );
    }
}