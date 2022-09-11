#ifndef DEMON_PIVOT_H
#define DEMON_PIVOT_H

#include <windows.h>

typedef struct _PIVOT_DATA
{
    LPSTR   PipeName;
    HANDLE  Handle;
    UINT32  DemonID;

    struct  _PIVOT_DATA* Next;
} PIVOT_DATA, *PPIVOT_DATA;

BOOL    PivotAdd( PCHAR NamedPipe, PVOID* Output, PSIZE_T BytesSize );
BOOL    PivotRemove( DWORD DemonId );

UINT32  PivotParseDemonID( PVOID Response, SIZE_T Size );
VOID    PivotCollectOutput();

#endif
