#ifndef DEMON_DSTDIO_H
#define DEMON_DSTDIO_H

#include <Demon.h>
DWORD   HashStringA(PCHAR String);

INT     StringCompareA( LPCSTR String1, LPCSTR String2 );
PCHAR   StringCopyA( PCHAR String1, PCHAR String2 );
SIZE_T  StringLengthA( LPCSTR String );
SIZE_T  StringLengthW( LPCWSTR String );
PCHAR   StringConcatA(PCHAR String, PCHAR String2);
PCHAR   StringTokenA(PCHAR String, CONST PCHAR Delim);

VOID    MemSet( PVOID Destination, INT Val, SIZE_T Size );
INT     MemCompare( PVOID s1, PVOID s2, INT len );

SIZE_T  WCharStringToCharString( PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed );
SIZE_T  CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );

#endif
