#include <Core/Spoof.h>
#include <Core/MiniStd.h>

PVOID FindGadget( LPBYTE Module, ULONG Size )
{
    for ( int x = 0; x < Size; x++ )
    {
        if ( MemCompare( Module + x, "\xFF\x23", 2 ) == 0 )
        {
            return ( PVOID )( Module + x );
        };
    };

    return NULL;
}

PVOID SpoofRetAddr( PVOID Function, HANDLE Module, ULONG Size, PVOID a, PVOID b, PVOID c, PVOID d, PVOID e, PVOID f, PVOID g, PVOID h )
{
    PVOID Trampoline = NULL;

    if ( Function != NULL )
    {
        Trampoline = FindGadget( Module, Size );
        if ( Trampoline != NULL )
        {
            PRM param = { Trampoline, Function };
            return ( ( PVOID( * ) ( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID ) ) ( ( PVOID ) Spoof ) ) ( a, b, c, d, &param, NULL, e, f, g, h );
        }
    }

    return NULL;
}