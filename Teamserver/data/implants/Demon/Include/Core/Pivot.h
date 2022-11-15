#ifndef DEMON_PIVOT_H
#define DEMON_PIVOT_H

#include <windows.h>

typedef struct _PIVOT_DATA
{
    UINT32 DemonID;
    BUFFER PipeName;
    HANDLE Handle;

    struct  _PIVOT_DATA* Next;
} PIVOT_DATA, *PPIVOT_DATA;

BOOL        PivotAdd( BUFFER NamedPipe, PVOID* Output, PSIZE_T BytesSize );
BOOL        PivotRemove( DWORD DemonId );
DWORD       PivotCount();
PPIVOT_DATA PivotGet( DWORD AgentID );
UINT32      PivotParseDemonID( PVOID Response, SIZE_T Size );
VOID        PivotPush();

#endif
