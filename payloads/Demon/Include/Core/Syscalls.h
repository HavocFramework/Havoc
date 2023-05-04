
#ifndef DEMON_SYSCALLS_H
#define DEMON_SYSCALLS_H

#include <windows.h>
#include <Common/Native.h>

/* Syscall functions */
#define SYS_ASM_RET 0xC3
#define SYS_RANGE   0x1E

#define SYS_EXTRACT( NtName )                                                       \
    if ( Instance.Win32.NtName ) {                                                  \
        SysExtract(                                                                 \
            Instance.Win32.NtName,                                                  \
            &Instance.Syscall.NtName,                                               \
            NULL                                                                    \
        );                                                                          \
        PRINTF( "Extracted \"%s\": [Ssn: %x]\n", #NtName, Instance.Syscall.NtName ) \
    }

typedef struct _SYS_CONFIG {
    PVOID Adr; /* indirect syscall instruction address */
    WORD  Ssn; /* syscall service number */
} SYS_CONFIG, *PSYS_CONFIG;

BOOL SysInitialize(
    IN PVOID Ntdll
);

BOOL SysExtract(
    IN  PVOID  Function,
    OUT PWORD  Ssn,
    OUT PVOID* Addr
);

VOID SysSetConfig(
    IN PSYS_CONFIG Config
);

NTSTATUS SysInvoke(
    IN OUT /* Args... */
);

#endif
