#include <Demon.h>

// Our entrypoint for windows executable.
INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain: hInstance:[%p]\n", hInstance )
    DemonMain( NULL );
}
