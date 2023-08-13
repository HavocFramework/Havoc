#ifndef DEMON_INJECTUTIL_H
#define DEMON_INJECTUTIL_H

#include <windows.h>
#include <Inject/Inject.h>

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

#ifndef ProcThreadAttributeValue

#define PROC_THREAD_ATTRIBUTE_NUMBER    0x0000FFFF
#define PROC_THREAD_ATTRIBUTE_THREAD    0x00010000
#define PROC_THREAD_ATTRIBUTE_INPUT     0x00020000
#define PROC_THREAD_ATTRIBUTE_ADDITIVE  0x00040000

#define ProcThreadAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PROC_THREAD_ATTRIBUTE_NUMBER) | \
     ((Thread != FALSE) ? PROC_THREAD_ATTRIBUTE_THREAD : 0) | \
     ((Input != FALSE) ? PROC_THREAD_ATTRIBUTE_INPUT : 0) | \
     ((Additive != FALSE) ? PROC_THREAD_ATTRIBUTE_ADDITIVE : 0))

#endif

#define ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X64_TO_X86   0x1001
#define ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X86_TO_X64   0x1002
#define ERROR_INJECT_FAILED_TO_SPAWN_TARGET_PROCESS            0x1003

DWORD   Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
DWORD   GetReflectiveLoaderOffset( PVOID lpReflectiveDllBuffer );
DWORD   GetPeArch( PVOID PeBytes );

#endif
