#ifndef DEMON_MEMORY_H
#define DEMON_MEMORY_H

#include <common/Native.h>

typedef enum _DX_MEMORY
{
    DX_MEM_DEFAULT  = 0,
    DX_MEM_WIN32    = 1,
    DX_MEM_SYSCALL  = 2,
} DX_MEMORY;

PVOID MmHeapAlloc(
    _In_ ULONG Length
);

PVOID MmHeapReAlloc(
    _In_ PVOID Memory,
    _In_ ULONG Length
);

BOOL MmHeapFree(
    _In_ PVOID Memory
);

PVOID MmVirtualAlloc(
    IN DX_MEMORY Method,
    IN HANDLE    Process,
    IN SIZE_T    Size,
    IN DWORD     Protect
);

BOOL MmVirtualProtect(
    IN DX_MEMORY Method,
    IN HANDLE    Process,
    IN PVOID     Memory,
    IN SIZE_T    Size,
    IN DWORD     Protect
);

BOOL MmVirtualWrite(
    IN  HANDLE Process,
    OUT PVOID  Memory,
    IN  PVOID  Buffer,
    IN  SIZE_T Size
);

BOOL MmVirtualFree(
    IN  HANDLE Process,
    OUT PVOID  Memory
);

PVOID MmGadgetFind(
    _In_ PVOID  Memory,
    _In_ SIZE_T Length,
    _In_ PVOID  PatternBuffer,
    _In_ SIZE_T PatternLength
);

BOOL FreeReflectiveLoader(
    IN PVOID BaseAddress
);

#endif
