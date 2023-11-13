#ifndef DEMON_SPOOF_H
#define DEMON_SPOOF_H

#include <windows.h>

// NOTE: this code is taken from AceLdr by kyleavery. So huge credit goes to him. https://github.com/kyleavery/AceLdr

#if _WIN64

typedef struct
{
    const PVOID trampoline;
    PVOID       function;
    PVOID       rbx;
} PRM, *PPRM;

static ULONG_PTR Spoof();

#define SPOOF_X( function, module, size )                             SpoofRetAddr( function, module, size, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_A( function, module, size, a )                          SpoofRetAddr( function, module, size, a, NULL, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_B( function, module, size, a, b )                       SpoofRetAddr( function, module, size, a, b, NULL, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_C( function, module, size, a, b, c )                    SpoofRetAddr( function, module, size, a, b, c, NULL, NULL, NULL, NULL, NULL )
#define SPOOF_D( function, module, size, a, b, c, d )                 SpoofRetAddr( function, module, size, a, b, c, d, NULL, NULL, NULL, NULL )
#define SPOOF_E( function, module, size, a, b, c, d, e )              SpoofRetAddr( function, module, size, a, b, c, d, e, NULL, NULL, NULL )
#define SPOOF_F( function, module, size, a, b, c, d, e, f )           SpoofRetAddr( function, module, size, a, b, c, d, e, f, NULL, NULL )
#define SPOOF_G( function, module, size, a, b, c, d, e, f, g )        SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, NULL )
#define SPOOF_H( function, module, size, a, b, c, d, e, f, g, h )     SpoofRetAddr( function, module, size, a, b, c, d, e, f, g, h )
#define SETUP_ARGS(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, ...) arg12
#define SPOOF_MACRO_CHOOSER(...) SETUP_ARGS(__VA_ARGS__, SPOOF_H, SPOOF_G, SPOOF_F, SPOOF_E, SPOOF_D, SPOOF_C, SPOOF_B, SPOOF_A, SPOOF_X, )
#define SpoofFunc(...) SPOOF_MACRO_CHOOSER(__VA_ARGS__)(__VA_ARGS__)

PVOID SpoofRetAddr(
    IN     PVOID  Module,
    IN     ULONG  Size,
    IN     HANDLE Function,
    IN OUT PVOID  a,
    IN OUT PVOID  b,
    IN OUT PVOID  c,
    IN OUT PVOID  d,
    IN OUT PVOID  e,
    IN OUT PVOID  f,
    IN OUT PVOID  g,
    IN OUT PVOID  h
);

#endif

#endif
