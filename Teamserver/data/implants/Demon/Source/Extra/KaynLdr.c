
#include "Extra/KaynLdr.h"
#include "Common/Macros.h"
#include "Core/WinUtils.h"

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

DLLEXPORT VOID KaynLoader( LPVOID lpParameter )
{
    KAYNINSTANCE            Instance        = { 0 };
    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    DWORD                   KMemSize        = 0;
    PVOID                   SecMemory       = NULL;
    PVOID                   SecMemorySize   = 0;
    DWORD                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir       = NULL;

    // 0. First we need to get our own image base
    KaynLibraryLdr = KaynCaller();

    Instance.Modules.Ntdll                 = LdrModulePeb( NTDLL_HASH );

    Instance.Win32.LdrLoadDll              = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.NtAllocateVirtualMemory = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = LdrFunctionAddr( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );

    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage;

    if ( NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            MemCopy(
                    C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress ),    // Section New Memory
                    C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData ),  // Section Raw Data
                    SecHeader[ i ].SizeOfRawData                                // Section Size
            );
        }

        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KReAllocSections( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ) );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // --------------------------------
        // 6. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, lpParameter );
    }
}

VOID KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

__asm__(
        "KaynCaller:                        \n"
        "       call pop                    \n"
        "       pop:                        \n"
        "       pop rcx                     \n"
        "   loop:                           \n"
        "       xor rbx, rbx                \n"
        "       mov ebx, 0x5A4D             \n"
        "       dec rcx                     \n"
        "       cmp bx,  word ptr ds:[ rcx ]\n"
        "       jne loop                    \n"
        "       xor rax, rax                \n"
        "       mov ax,  [ rcx + 0x3C ]     \n"
        "       add rax, rcx                \n"
        "       xor rbx, rbx                \n"
        "       add bx,  0x4550             \n"
        "       cmp bx,  word ptr ds:[ rax ]\n"
        "       jne loop                    \n"
        "       mov rax, rcx                \n"
        "   ret"
);
