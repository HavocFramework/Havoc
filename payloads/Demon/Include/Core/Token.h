#ifndef DEMON_TOKEN_H
#define DEMON_TOKEN_H

#include <windows.h>
#include <Core/Win32.h>

#define TOKEN_TYPE_STOLEN       0x1
#define TOKEN_TYPE_MAKE_NETWORK 0x2

#define TOKEN_OWNER_FLAG_DEFAULT 0x0 /* query domain/user */
#define TOKEN_OWNER_FLAG_USER    0x1 /* query user only */
#define TOKEN_OWNER_FLAG_DOMAIN  0x2 /* query domain only */

#define MAX_PROCESSES 5000
#define BUF_SIZE      4096
#define MAX_USERNAME  512

#define RtlOffsetToPointer(B,O)  ((PCHAR)( ((PCHAR)(B)) + ((ULONG_PTR)(O))  ))

#ifndef ALIGN_UP_TYPE
#define ALIGN_UP_TYPE(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(Address, Type) ALIGN_UP_TYPE(Address, sizeof(Type))
#endif

#define ObjectTypesInformation 3

#define OBJECT_TYPES_FIRST_ENTRY(ObjectTypes) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectTypes, ALIGN_UP(sizeof(ULONG), ULONG_PTR))

#define OBJECT_TYPES_NEXT_ENTRY(ObjectType) (POBJECT_TYPE_INFORMATION)\
    RtlOffsetToPointer(ObjectType, sizeof(OBJECT_TYPE_INFORMATION) + \
    ALIGN_UP(ObjectType->TypeName.MaximumLength, ULONG_PTR))

typedef struct _PROCESS_LIST
{
    ULONG Count;
    ULONG ProcessId[MAX_PROCESSES];
} PROCESS_LIST, *PPROCESS_LIST;

typedef struct _USER_TOKEN_DATA
{
    WCHAR  username[MAX_USERNAME];
    DWORD  dwProcessID;
    HANDLE localHandle;
    DWORD  integrity_level;
    DWORD  impersonation_level;
    DWORD  TokenType;
} USER_TOKEN_DATA, *PUSER_TOKEN_DATA;

typedef struct _OBJECT_TYPE_INFORMATION_V2 {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION_V2, * POBJECT_TYPE_INFORMATION_V2;

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

BOOL TokenSetSeDebugPriv(
    IN BOOL Enable
);

BOOL TokenSetSeImpersonatePriv(
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

BOOL SysDuplicateTokenEx(
    IN HANDLE ExistingTokenHandle,
    IN DWORD dwDesiredAccess,
    IN LPSECURITY_ATTRIBUTES lpTokenAttributes  OPTIONAL,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE DuplicateTokenHandle);

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

BOOL ListTokens( PUSER_TOKEN_DATA* pTokens, PDWORD pNumTokens );

BOOL ImpersonateTokenFromVault(
    IN DWORD TokenID
);

BOOL ImpersonateTokenInStore(
    IN PTOKEN_LIST_DATA TokenData
);

BOOL SysImpersonateLoggedOnUser( HANDLE hToken );

#endif
