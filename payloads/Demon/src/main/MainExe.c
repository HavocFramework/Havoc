#include <Demon.h>

INT WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd )
{
    PRINTF( "WinMain: hInstance:[%p] hPrevInstance:[%p] lpCmdLine:[%s] nShowCmd:[%d]\n", hInstance, hPrevInstance, lpCmdLine, nShowCmd )

    INSTANCE Inst = { 0 };

    /* "allocate" instance on stack */
    Instance = & Inst;

    DemonMain( NULL, NULL );
    return 0;
}
