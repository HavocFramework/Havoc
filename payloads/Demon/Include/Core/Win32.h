#ifndef DEMON_WIN32_H
#define DEMON_WIN32_H

#include <Demon.h>

typedef PSYSTEM_PROCESS_INFORMATION  PSYS_PROC_INFO;
typedef SECURITY_QUALITY_OF_SERVICE  SEC_QUALITY_SERVICE;
typedef OBJECT_ATTRIBUTES            OBJ_ATTR;

BOOL Win32_DuplicateTokenEx (
        HANDLE 	                        ExistingTokenHandle,
        DWORD 	                        dwDesiredAccess,
        LPSECURITY_ATTRIBUTES           lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL    ImpersonationLevel,
        TOKEN_TYPE                      TokenType,
        PHANDLE                         DuplicateTokenHandle
);

#endif
