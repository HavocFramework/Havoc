/*
    All custom win32 apis here in this file
*/

#include <Core/Win32.h>

#include <ntstatus.h>

/* Move this to Token.c
 * New name is going to be TokenDuplicate*/
BOOL Win32_DuplicateTokenEx(
        HANDLE                       ExistingTokenHandle,
        DWORD                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES        lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
        TOKEN_TYPE                   TokenType,
        PHANDLE                      DuplicateTokenHandle )
{
    OBJECT_ATTRIBUTES           ObjectAttributes    = { 0 };
    NTSTATUS                    Status              = STATUS_SUCCESS;
    SECURITY_QUALITY_OF_SERVICE Sqos                = { 0 };

    Sqos.Length              = sizeof( SECURITY_QUALITY_OF_SERVICE );
    Sqos.ImpersonationLevel  = ImpersonationLevel;
    Sqos.ContextTrackingMode = 0;
    Sqos.EffectiveOnly       = FALSE;

    if ( lpTokenAttributes != NULL )
    {
        InitializeObjectAttributes(
            &ObjectAttributes,
            NULL,
            lpTokenAttributes->bInheritHandle ? OBJ_INHERIT : 0,
            NULL,
            lpTokenAttributes->lpSecurityDescriptor
        );
    }
    else
    {
        InitializeObjectAttributes(
            &ObjectAttributes,
            NULL,
            NULL,
            NULL,
            NULL
        );
    }

    ObjectAttributes.SecurityQualityOfService = &Sqos;

    if ( ! NT_SUCCESS( Status = Instance.Syscall.NtDuplicateToken( ExistingTokenHandle, dwDesiredAccess, &ObjectAttributes, FALSE, TokenType, DuplicateTokenHandle ) ) )
    {
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( Status ) );
        return FALSE;
    }

    return TRUE;
}