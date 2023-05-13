#ifndef DEMON_HWBPEXCEPTIONS_H
#define DEMON_HWBPEXCEPTIONS_H

#include <windows.h>

#if defined( __x86_64__ ) || defined( _M_X64 )

#define EXCEPTION_DUMP( e ) \
    PRINTF(                                                             \
        "Exception:     \n"                                             \
        " - Rip:  %p    \n"                                             \
        " - Rax:  %p    \n"                                             \
        " - Arg1: %p    \n"                                             \
        " - Arg2: %p    \n"                                             \
        " - Arg3: %p    \n"                                             \
        " - Arg4: %p    \n"                                             \
        " - Arg5: %p    \n"                                             \
        " - Arg6: %p    \n",                                            \
        e->ContextRecord->Rip,                                          \
        e->ContextRecord->Rax,                                          \
        e->ContextRecord->Rcx,                                          \
        e->ContextRecord->Rdx,                                          \
        e->ContextRecord->R8,                                           \
        e->ContextRecord->R9,                                           \
        *( PVOID* ) ( e->ContextRecord->Rsp + sizeof( PVOID ) * 5 ),    \
        *( PVOID* ) ( e->ContextRecord->Rsp + sizeof( PVOID ) * 6 )     \
    )

#define EXCEPTION_SET_RIP( e, p )   e->ContextRecord->Rip = p
#define EXCEPTION_SET_RET( e, r )   e->ContextRecord->Rax = r
#define EXCEPTION_RESUME( e )       e->ContextRecord->EFlags = ( 1 << 16 )
#define EXCEPTION_GET_RET( e )      *( PVOID* ) ( e->ContextRecord->Rsp )
#define EXCEPTION_ADJ_STACK( e, i ) e->ContextRecord->Rsp += i
#define EXCEPTION_ARG_1( e )        ( e->ContextRecord->Rcx )
#define EXCEPTION_ARG_2( e )        ( e->ContextRecord->Rdx )
#define EXCEPTION_ARG_3( e )        ( e->ContextRecord->R8 )
#define EXCEPTION_ARG_4( e )        ( e->ContextRecord->R9 )
#define EXCEPTION_ARG_5( e )        *( PVOID* ) ( e->ContextRecord->Rsp + sizeof( PVOID ) * 5 )
#define EXCEPTION_ARG_6( e )        *( PVOID* ) ( e->ContextRecord->Rsp + sizeof( PVOID ) * 6 )
#define EXCEPTION_ARG_7( e )        *( PVOID* ) ( e->ContextRecord->Rsp + sizeof( PVOID ) * 7 )

#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)

#define EXCEPTION_ARG_1( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 1 )
#define EXCEPTION_ARG_2( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 2 )
#define EXCEPTION_ARG_3( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 3 )
#define EXCEPTION_ARG_4( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 4 )
#define EXCEPTION_ARG_5( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 5 )
#define EXCEPTION_ARG_6( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 6 )
#define EXCEPTION_ARG_7( e )    *( PVOID* )( e->ContextRecord->Esp + sizeof( PVOID ) * 7 )

#endif

VOID HwBpExAmsiScanBuffer(
    IN OUT PEXCEPTION_POINTERS Exception
);

VOID HwBpExNtTraceEvent(
    IN OUT PEXCEPTION_POINTERS Exception
);

#endif //DEMON_HWBPEXCEPTIONS_H
