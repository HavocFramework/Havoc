#include <Demon.h>

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain: hInstance:[%p] hPrevInstance:[%p] lpCmdLine:[%s] nShowCmd:[%d]\n", hInstance, hPrevInstance, lpCmdLine, nShowCmd )
    DemonMain( NULL, NULL );
    return 0;
}
