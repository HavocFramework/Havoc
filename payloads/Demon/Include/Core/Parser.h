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

VOID  ParserNew( PPARSER parser, PCHAR buffer, UINT32 size );
VOID  ParserDecrypt( PPARSER parser, PBYTE Key, PBYTE IV );
INT   ParserGetInt32( PPARSER parser );
PCHAR ParserGetBytes( PPARSER parser, PINT size );
VOID  ParserDestroy( PPARSER Parser );

#endif //DEMON_PARSER_H
