#ifndef DEMON_MEMORY_H
#define DEMON_MEMORY_H

#include <Common/Native.h>

typedef enum _DX_MEMORY
{
    DX_MEM_DEFAULT  = 0,
    DX_MEM_WIN32    = 1,
    DX_MEM_SYSCALL  = 2,
} DX_MEMORY;

PVOID MemoryAlloc(
    IN DX_MEMORY Method,
    IN HANDLE    Process,
    IN SIZE_T    Size,
    IN DWORD     Protect
);

BOOL MemoryProtect(
    IN DX_MEMORY Method,
    IN HANDLE    Process,
    IN PVOID     Memory,
    IN SIZE_T    Size,
    IN DWORD     Protect
);

BOOL MemoryWrite(
    IN  HANDLE Process,
    OUT PVOID  Memory,
    IN  PVOID  Buffer,
    IN  SIZE_T Size
);

BOOL MemoryFree(
    IN  HANDLE Process,
    OUT PVOID  Memory
);

BOOL FreeReflectiveLoader(
    IN PVOID BaseAddress
);

#endif
