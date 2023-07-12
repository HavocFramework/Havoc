
#ifndef DEMON_SYSCALLS_H
#define DEMON_SYSCALLS_H

#include <windows.h>
#include <Common/Native.h>

/* Syscall functions */
#define SYS_ASM_RET 0xC3
#define SYS_RANGE   0x1E
#if _WIN64
 #define SYSCALL_ASM  0x050F
 #define SSN_OFFSET_1 0x4
 #define SSN_OFFSET_2 0x5
#else
 #define SYSCALL_ASM  0x340f
 #define SSN_OFFSET_1 0x1
 #define SSN_OFFSET_2 0x2
#endif

#define SYS_EXTRACT( NtName )                                                       \
    if ( Instance.Win32.NtName ) {                                                  \
        SysExtract(                                                                 \
            Instance.Win32.NtName,                                                  \
            TRUE,                                                                   \
            &Instance.Syscall.NtName,                                               \
            NULL                                                                    \
        );                                                                          \
        PRINTF( "Extracted \"%s\": [Ssn: %x] Ptr:[%p]\n", #NtName, Instance.Syscall.NtName, Instance.Win32.NtName ) \
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
    IN  BOOL   ResolveHooked,
    OUT PWORD  Ssn,
    OUT PVOID* Addr
);

BOOL FindSsnOfHookedSyscall(
    IN  PVOID  Function,
    OUT PWORD  Ssn
);

VOID SysSetConfig(
    IN PSYS_CONFIG Config
);

NTSTATUS SysInvoke(
    IN OUT /* Args... */
);

BOOL IsWoW64();

#endif
