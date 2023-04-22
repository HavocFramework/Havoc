#ifndef DEMON_PARSER_H
#define DEMON_PARSER_H

#include <windows.h>

typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;

    UINT32  TaskID;
    BOOL    Endian;
} PARSER, *PPARSER;

VOID   ParserNew( PPARSER parser, PBYTE buffer, UINT32 size );
VOID   ParserDecrypt( PPARSER parser, PBYTE Key, PBYTE IV );
INT16  ParserGetInt16( PPARSER parser );
BYTE   ParserGetByte( PPARSER parser );
INT    ParserGetInt32( PPARSER parser );
INT64  ParserGetInt64( PPARSER parser );
PBYTE  ParserGetBytes( PPARSER parser, PUINT32 size );
PCHAR  ParserGetString( PPARSER parser, PUINT32 size );
PWCHAR ParserGetWString( PPARSER parser, PUINT32 size );
VOID   ParserDestroy( PPARSER Parser );

#endif //DEMON_PARSER_H
