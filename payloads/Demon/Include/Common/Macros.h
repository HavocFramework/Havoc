#ifndef DEMON_MACROS_H
#define DEMON_MACROS_H

#include <stdio.h>

#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readfsdword( 0x30 )
#endif

#define NT_SUCCESS(Status)              ( ( ( NTSTATUS ) ( Status ) ) >= 0 )
#define NtCurrentProcess()              ( ( HANDLE ) ( LONG_PTR ) - 1 )
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
    if ( d ) { \
        MemSet( d, 0, l ); \
        Instance.Win32.LocalFree( d ); \
        d = NULL; \
    }

#define SEC_DATA        __attribute__( ( section( ".data" ) ) )
#define U_PTR( x )      ( ( UINT_PTR ) x )
#define C_PTR( x )      ( ( LPVOID ) x )
#define B_PTR( x )      ( ( PBYTE ) ( x ) )
#define DREF_U8( x )    ( ( BYTE ) *( PBYTE* )( x ) )
#define DREF_U16( x )   ( ( WORD ) *( PWORD* )( x ) )
#define HTONS32( x )    __builtin_bswap32( x )
#define HTONS16( x )    __builtin_bswap16( x )
#define IMAGE_SIZE( IM ) \
    ( ( ( PIMAGE_NT_HEADERS ) ( IM + ( ( PIMAGE_DOS_HEADER ) IM )->e_lfanew ) )->OptionalHeader.SizeOfImage )

// DEBUG
#ifdef DEBUG
#if SEND_LOGS
#define PRINTF( f, ... )                { DemonPrintf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#elif SVC_EXE
#define PRINTF( f, ... )                { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { DbgPrint( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#elif SHELLCODE
#define PRINTF( f, ... )                { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { LogToConsole( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#else
#define PRINTF( f, ... )                { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#define PRINTF_DONT_SEND( f, ... )      { printf( "[DEBUG::%s::%d] " f, __FUNCTION__, __LINE__, __VA_ARGS__ ); }
#endif
#else
#define PRINTF( f, ... )                { ; }
#define PRINTF_DONT_SEND( f, ... )      { ; }
#endif

#ifdef DEBUG
#if SEND_LOGS
#define PUTS( s )           { DemonPrintf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { ; }
#elif SHELLCODE
#define PUTS( s )           { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { LogToConsole( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#else
#define PUTS( s )           { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#define PUTS_DONT_SEND( s ) { printf( "[DEBUG::%s::%d] %s\n", __FUNCTION__, __LINE__, s ); }
#endif
#else
#define PUTS( s )           { ; }
#define PUTS_DONT_SEND( s ) { ; }
#endif

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
