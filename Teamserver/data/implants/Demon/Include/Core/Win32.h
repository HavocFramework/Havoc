#ifndef DEMON_WIN32_H
#define DEMON_WIN32_H

#include <Demon.h>

BOOL Win32_DuplicateTokenEx (
        HANDLE 	                        ExistingTokenHandle,
        DWORD 	                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES           lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL    ImpersonationLevel,
        TOKEN_TYPE                      TokenType,
        PHANDLE                         DuplicateTokenHandle
);

#endif
