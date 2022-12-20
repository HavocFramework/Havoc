#ifndef DEMON_INJECTUTIL_H
#define DEMON_INJECTUTIL_H

#include <windows.h>
#include <Inject/Inject.h>

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

typedef enum _PS_ATTRIBUTE_NUM{ // 13 elements, 0x4 bytes
    PsAttributeParentProcess = 0 /*0x0*/,
    PsAttributeDebugObject = 1 /*0x1*/,
    PsAttributeToken = 2 /*0x2*/,
    PsAttributeClientId = 3 /*0x3*/,
    PsAttributeTebAddress = 4 /*0x4*/,
    PsAttributeImageName = 5 /*0x5*/,
    PsAttributeImageInfo = 6 /*0x6*/,
    PsAttributeMemoryReserve = 7 /*0x7*/,
    PsAttributePriorityClass = 8 /*0x8*/,
    PsAttributeErrorMode = 9 /*0x9*/,
    PsAttributeStdHandleInfo = 10 /*0xA*/,
    PsAttributeHandleList = 11 /*0xB*/,
    PsAttributeMax = 12 /*0xC*/
}PS_ATTRIBUTE_NUM, *PPS_ATTRIBUTE_NUM;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
    ULONG_PTR Attribute;
    ULONG_PTR Size;
    ULONG_PTR* pValue;
    ULONG_PTR Unknown;
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
    ULONG_PTR Length;
    PROC_THREAD_ATTRIBUTE_ENTRY Entry;
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

#define ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X64_TO_X86   0x1001
#define ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X86_TO_X64   0x1002
#define ERROR_INJECT_FAILED_TO_SPAWN_TARGET_PROCESS            0x1003

LPVOID  MemoryAlloc( DX_MEMORY AllocMethode, HANDLE hProcess, SIZE_T MemSize, DWORD Protect );
BOOL    MemoryProtect( DX_MEMORY ProtectMethode, HANDLE hProcess, LPVOID Memory, SIZE_T MemSize, DWORD Protect );
BOOL    ThreadCreate( DX_THREAD ThreadCreate, HANDLE hProcess, LPVOID EntryPoint, PINJECTION_CTX ctx );

DWORD   Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
DWORD   GetReflectiveLoaderOffset( PVOID lpReflectiveDllBuffer );

DWORD   GetPeArch( PVOID PeBytes );

#endif
