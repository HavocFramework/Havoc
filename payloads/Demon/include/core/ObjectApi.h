#ifndef DEMON_OBJECTAPI_H
#define DEMON_OBJECTAPI_H

#include <windows.h>

typedef struct
{
    UINT_PTR    NameHash;
    PVOID       Pointer;
} COFFAPIFUNC;

extern COFFAPIFUNC  BeaconApi[];
extern DWORD        BeaconApiCounter;
extern COFFAPIFUNC  LdrApi[];
extern COFFAPIFUNC  NtApi[];

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

typedef struct {
    PCHAR  original; /* the original buffer [so we can free it] */
    PCHAR  buffer;   /* current pointer into our buffer */
    INT    length;   /* remaining length of data */
    INT    size;     /* total size of this buffer */
} datap, *PDATA, *PFORMAT;

typedef struct {
    char * ptr;
    size_t size;
} HEAP_RECORD;
#define MASK_SIZE 13

typedef struct {
    char  * sleep_mask_ptr;
    DWORD   sleep_mask_text_size;
    DWORD   sleep_mask_total_size;

    char  * beacon_ptr;
    DWORD * sections;
    HEAP_RECORD * heap_records;
    char    mask[MASK_SIZE];
} BEACON_INFO;

#define DATA_STORE_TYPE_EMPTY 0
#define DATA_STORE_TYPE_GENERAL_FILE 1

typedef struct {
    int type;
    DWORD64 hash;
    BOOL masked;
    char* buffer;
    size_t length;
} DATA_STORE_OBJECT, *PDATA_STORE_OBJECT;

VOID    BeaconDataParse( PDATA parser, PCHAR  buffer, INT size );
INT     BeaconDataInt( PDATA parser );
SHORT   BeaconDataShort( PDATA parser );
INT     BeaconDataLength( PDATA parser );
PCHAR   BeaconDataExtract( PDATA parser, PINT size );

VOID    BeaconFormatAlloc( PFORMAT format, INT maxsz );
VOID    BeaconFormatReset( PFORMAT format );
VOID    BeaconFormatFree( PFORMAT format );
VOID    BeaconFormatAppend( PFORMAT format, PCHAR text, INT len );
VOID    BeaconFormatPrintf( PFORMAT format, PCHAR fmt, ... );
PCHAR   BeaconFormatToString( PFORMAT format, PINT size );
VOID    BeaconFormatInt( PFORMAT format, INT value );

VOID    BeaconPrintf( INT Type, PCHAR fmt, ... );
VOID    BeaconOutput( INT Type, PCHAR data, INT len );

/* Token Functions */
BOOL    BeaconUseToken( HANDLE token );
BOOL    BeaconIsAdmin();

/* Spawn+Inject Functions */
VOID    BeaconGetSpawnTo( BOOL x86, PCHAR  buffer, INT length );
BOOL    BeaconSpawnTemporaryProcess( BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo );
VOID    BeaconInjectProcess( HANDLE hProc, INT pid, PCHAR  payload, INT p_len, INT p_offset, PCHAR  arg, INT a_len );
VOID    BeaconInjectTemporaryProcess( PROCESS_INFORMATION * pInfo, PCHAR  payload, INT p_len, INT p_offset, PCHAR  arg, INT a_len );
VOID    BeaconCleanupProcess( PROCESS_INFORMATION* pInfo );

/* Utility Functions */
BOOL   toWideChar( PCHAR src, PWCHAR dst, INT max );
UINT32 swap_endianness( UINT32 indata );

BOOL   GetRequestIDForCallingObjectFile( PVOID CoffeeFunctionReturn, PUINT32 RequestID );

VOID BeaconInformation(BEACON_INFO * info);

BOOL BeaconAddValue(const char * key, void * ptr);
PVOID BeaconGetValue(const char * key);
BOOL BeaconRemoveValue(const char * key);

PDATA_STORE_OBJECT BeaconDataStoreGetItem(SIZE_T index);
VOID BeaconDataStoreProtectItem(SIZE_T index);
VOID BeaconDataStoreUnprotectItem(SIZE_T index);
SIZE_T BeaconDataStoreMaxEntries();

/* Beacon User Data functions */
PCHAR BeaconGetCustomUserData();

#endif
