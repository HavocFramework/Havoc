#include <Demon.h>

#include <Core/MiniStd.h>

/*
 * Most of the functions from here are from VX-Underground https://github.com/vxunderground/VX-API
 */

INT StringCompareA( LPCSTR String1, LPCSTR String2 )
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);

}

DWORD HashStringA( PCHAR String )
{
    ULONG Hash = HASH_KEY;
    INT c;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}


PCHAR StringCopyA(PCHAR String1, PCHAR String2)
{
    PCHAR p = String1;

    while ((*p++ = *String2++) != 0);

    return String1;
}

SIZE_T StringLengthA(LPCSTR String)
{
    LPCSTR String2;

    if ( String == NULL )
        return 0;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

PCHAR StringConcatA(PCHAR String, PCHAR String2)
{
    StringCopyA( &String[ StringLengthA( String ) ], String2 );

    return String;
}

VOID MemSet(PVOID Destination, int Val, SIZE_T Size)
{
    PULONG Dest = ( PULONG )Destination;
    SIZE_T Count = Size / sizeof( ULONG );

    while ( Count > 0 )
    {
        *Dest = Val;
        Dest++;
        Count--;
    }
}

INT MemCompare( PVOID s1, PVOID s2, INT len)
{
    PUCHAR p = s1;
    PUCHAR q = s2;
    INT charCompareStatus = 0;

    if (s1 == s2)
        return charCompareStatus;

    while (len > 0)
    {
        if (*p != *q)
        {
            charCompareStatus = (*p >*q)?1:-1;
            break;
        }
        len--;
        p++;
        q++;
    }
    return charCompareStatus;
}

SIZE_T WCharStringToCharString(PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

SIZE_T CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if ( ! ( *Destination++ = *Source++ ) )
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

PCHAR StringTokenA(PCHAR String, CONST PCHAR Delim)
{
    PCHAR Last;
    PCHAR SpanP, Token;
    INT C, SC;

    if ( String == NULL )
        return NULL;

CONTINUE:

    C = *String++;

    for (SpanP = (PCHAR)Delim; (SC = *SpanP++) != ERROR_SUCCESS;)
    {
        if (C == SC)
            goto CONTINUE;
    }

    if (C == ERROR_SUCCESS) { Last = NULL; return NULL; }

    Token = String - 1;

    for (;;)
    {
        C = *String++;
        SpanP = (PCHAR)Delim;

        do {
            if ((SC = *SpanP++) == C)
            {
                if (C == ERROR_SUCCESS)
                    String = NULL;
                else
                    String[-1] = '\0';

                Last = String;
                return Token;
            }
        } while (SC != ERROR_SUCCESS);
    }

    return NULL;

}
