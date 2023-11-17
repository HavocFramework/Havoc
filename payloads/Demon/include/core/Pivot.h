#ifndef DEMON_PIVOT_H
#define DEMON_PIVOT_H

#include <windows.h>

#define MAX_SMB_PACKETS_PER_LOOP 30

typedef struct _PIVOT_DATA
{
    UINT32 DemonID;
    BUFFER PipeName;
    HANDLE Handle;

    struct  _PIVOT_DATA* Next;
} PIVOT_DATA, *PPIVOT_DATA;

BOOL        PivotAdd( BUFFER NamedPipe, PVOID* Output, PDWORD BytesSize );
BOOL        PivotRemove( DWORD DemonId );
DWORD       PivotCount();
PPIVOT_DATA PivotGet( DWORD AgentID );
UINT32      PivotParseDemonID( PVOID Response, SIZE_T Size );
VOID        PivotPush();

#endif
