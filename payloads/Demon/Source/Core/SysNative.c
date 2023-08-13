#include <Demon.h>

#include <Core/Syscalls.h>
#include <Core/SysNative.h>

NTSTATUS NTAPI SysNtOpenThread(
    OUT    PHANDLE            ThreadHandle,
    IN     ACCESS_MASK        DesiredAccess,
    IN     POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPT PCLIENT_ID         ClientId
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtOpenThread, ThreadHandle, DesiredAccess, ObjectAttributes, ClientId )

    return NtStatus;
}

NTSTATUS NTAPI SysNtOpenProcess(
    OUT    PHANDLE             ProcessHandle,
    IN     ACCESS_MASK         DesiredAccess,
    IN     POBJECT_ATTRIBUTES  ObjectAttributes,
    IN OPT PCLIENT_ID          ClientId
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtOpenProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );

    return NtStatus;
}

NTSTATUS NTAPI SysNtTerminateProcess(
    IN OPTIONAL HANDLE   ProcessHandle,
    IN          NTSTATUS ExitStatus
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtTerminateProcess, ProcessHandle, ExitStatus );

    return NtStatus;
}

NTSTATUS NTAPI SysNtOpenThreadToken(
    IN  HANDLE      ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  BOOLEAN     OpenAsSelf,
    OUT PHANDLE     TokenHandle
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtOpenThreadToken, ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle );

    return NtStatus;
}

NTSTATUS NTAPI SysNtOpenProcessToken(
    IN  HANDLE      ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     TokenHandle
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtOpenProcessToken, ProcessHandle, DesiredAccess, TokenHandle );

    return NtStatus;
}

NTSTATUS NTAPI SysNtDuplicateToken(
    IN  HANDLE             ExistingTokenHandle,
    IN  ACCESS_MASK        DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  BOOLEAN            EffectiveOnly,
    IN  TOKEN_TYPE         TokenType,
    OUT PHANDLE            NewTokenHandle
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtDuplicateToken, ExistingTokenHandle, DesiredAccess, ObjectAttributes, EffectiveOnly, TokenType, NewTokenHandle );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueueApcThread(
    IN     HANDLE          ThreadHandle,
    IN     PPS_APC_ROUTINE ApcRoutine,
    IN OPT PVOID           ApcArgument1,
    IN OPT PVOID           ApcArgument2,
    IN OPT PVOID           ApcArgument3
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueueApcThread, ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3 );

    return NtStatus;
}

NTSTATUS NTAPI SysNtSuspendThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtSuspendThread, ThreadHandle, PreviousSuspendCount );

    return NtStatus;
}

NTSTATUS NTAPI SysNtResumeThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtResumeThread, ThreadHandle, PreviousSuspendCount );

    return NtStatus;
}

NTSTATUS NTAPI SysNtCreateEvent (
    OUT    PHANDLE            EventHandle,
    IN     ACCESS_MASK        DesiredAccess,
    IN OPT POBJECT_ATTRIBUTES ObjectAttributes,
    IN     EVENT_TYPE         EventType,
    IN     BOOLEAN            InitialState
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtCreateEvent, EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState );

    return NtStatus;
}

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
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtCreateThreadEx,
        hThread,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        lpStartAddress,
        lpParameter,
        Flags,
        StackZeroBits,
        SizeOfStackCommit,
        SizeOfStackReserve,
        lpBytesBuffer
    );

    return NtStatus;
}

NTSTATUS NTAPI SysNtDuplicateObject(
    IN     HANDLE      SourceProcessHandle,
    IN     HANDLE      SourceHandle,
    IN OPT HANDLE      TargetProcessHandle,
    OUT    PHANDLE     TargetHandle,
    IN     ACCESS_MASK DesiredAccess,
    IN     ULONG       HandleAttributes,
    IN     ULONG       Options
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtDuplicateObject, SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options );

    return NtStatus;
}

NTSTATUS NTAPI SysNtGetContextThread (
    IN     HANDLE   ThreadHandle,
    IN OUT PCONTEXT ThreadContext
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtGetContextThread, ThreadHandle, ThreadContext );

    return NtStatus;
}

NTSTATUS NTAPI SysNtSetContextThread(
    IN HANDLE   ThreadHandle,
    IN PCONTEXT ThreadContext
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtSetContextThread, ThreadHandle, ThreadContext );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueryInformationProcess(
    IN      HANDLE           ProcessHandle,
    IN      PROCESSINFOCLASS ProcessInformationClass,
    OUT     PVOID            ProcessInformation,
    IN      ULONG            ProcessInformationLength,
    OUT OPT PULONG           ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQuerySystemInformation (
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPT PVOID                    SystemInformation,
    IN      ULONG                    SystemInformationLength,
    OUT OPT PULONG                   ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQuerySystemInformation, SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtWaitForSingleObject(
    IN     HANDLE         Handle,
    IN     BOOLEAN        Alertable,
    IN OPT PLARGE_INTEGER Timeout
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtWaitForSingleObject, Handle, Alertable, Timeout );

    return NtStatus;
}

NTSTATUS NTAPI SysNtAllocateVirtualMemory(
    IN     HANDLE    ProcessHandle,
    IN OUT PVOID*    BaseAddress,
    IN     ULONG_PTR ZeroBits,
    IN OUT PSIZE_T   RegionSize,
    IN     ULONG     AllocationType,
    IN     ULONG     Protect
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtAllocateVirtualMemory, ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect );

    return NtStatus;
}

NTSTATUS NTAPI SysNtWriteVirtualMemory(
    IN       HANDLE  ProcessHandle,
    IN OPT   PVOID   BaseAddress,
    IN CONST VOID*   Buffer,
    IN       SIZE_T  BufferSize,
    OUT OPT  PSIZE_T NumberOfBytesWritten
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten );

    return NtStatus;
}

NTSTATUS NTAPI SysNtFreeVirtualMemory(
    IN     HANDLE  ProcessHandle,
    IN OUT PVOID*  BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN     ULONG   FreeType
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtFreeVirtualMemory, ProcessHandle, BaseAddress, RegionSize, FreeType );

    return NtStatus;
}

NTSTATUS NTAPI SysNtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID  BaseAddress
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtUnmapViewOfSection, ProcessHandle, BaseAddress );

    return NtStatus;
}

NTSTATUS NTAPI SysNtProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    IN OUT PVOID*  BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtProtectVirtualMemory, ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect );

    return NtStatus;
}

NTSTATUS NTAPI SysNtReadVirtualMemory (
    IN      HANDLE  ProcessHandle,
    IN OPT  PVOID   BaseAddress,
    OUT     PVOID   Buffer,
    IN      SIZE_T  BufferSize,
    OUT OPT PSIZE_T NumberOfBytesRead
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtReadVirtualMemory, ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead );

    return NtStatus;
}

NTSTATUS NTAPI SysNtTerminateThread (
    IN OPT HANDLE   ThreadHandle,
    IN     NTSTATUS ExitStatus
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtTerminateThread, ThreadHandle, ExitStatus );

    return NtStatus;
}

NTSTATUS NTAPI SysNtAlertResumeThread(
    IN      HANDLE ThreadHandle,
    OUT OPT PULONG PreviousSuspendCount
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtAlertResumeThread, ThreadHandle, PreviousSuspendCount );

    return NtStatus;
}

NTSTATUS NTAPI SysNtSignalAndWaitForSingleObject(
    IN     HANDLE         SignalHandle,
    IN     HANDLE         WaitHandle,
    IN     BOOLEAN        Alertable,
    IN OPT PLARGE_INTEGER Timeout
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtSignalAndWaitForSingleObject, SignalHandle, WaitHandle, Alertable, Timeout );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueryVirtualMemory(
    IN      HANDLE                   ProcessHandle,
    IN      PVOID                    BaseAddress,
    IN      MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT     PVOID                    MemoryInformation,
    IN      SIZE_T                   MemoryInformationLength,
    OUT OPT PSIZE_T                  ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueryVirtualMemory, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueryInformationToken (
    IN  HANDLE                  TokenHandle,
    IN  TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID                   TokenInformation,
    IN  ULONG                   TokenInformationLength,
    OUT PULONG                  ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueryInformationToken, TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueryInformationThread(
    IN      HANDLE          ThreadHandle,
    IN      THREADINFOCLASS ThreadInformationClass,
    OUT     PVOID           ThreadInformation,
    IN      ULONG           ThreadInformationLength,
    OUT OPT PULONG          ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueryInformationThread, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtQueryObject(
    IN  HANDLE                   Handle,
    IN  OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID                    ObjectInformation,
    IN  ULONG                    ObjectInformationLength,
    OUT PULONG                   ReturnLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtQueryObject, Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtClose (
    IN HANDLE Handle
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtClose, Handle );

    return NtStatus;
}

NTSTATUS NTAPI SysNtSetInformationThread (
    IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtSetInformationThread, ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtSetInformationVirtualMemory(
    IN HANDLE                           ProcessHandle,
    IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    IN ULONG_PTR                        NumberOfEntries,
    IN PMEMORY_RANGE_ENTRY              VirtualAddresses,
    IN PVOID                            VmInformation,
    IN ULONG                            VmInformationLength
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtSetInformationVirtualMemory, ProcessHandle, VmInformationClass, NumberOfEntries, VirtualAddresses, VmInformation, VmInformationLength );

    return NtStatus;
}

NTSTATUS NTAPI SysNtGetNextThread(
    IN  HANDLE      ProcessHandle,
    IN  HANDLE      ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  ULONG       HandleAttributes,
    IN  ULONG       Flags,
    OUT PHANDLE     NewThreadHandle
) {
    NTSTATUS   NtStatus  = STATUS_SUCCESS;
    SYS_CONFIG SysConfig = { 0 };

    SYSCALL_INVOKE( NtGetNextThread, ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle );

    return NtStatus;
}