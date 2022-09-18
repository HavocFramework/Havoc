#include <Win32.h>
#include <Utils.h>
#include <winternl.h>

SEC( text, B ) UINT_PTR LdrModulePeb( UINT_PTR hModuleHash )
{
    PLDR_DATA_TABLE_ENTRY pModule      = ( PLDR_DATA_TABLE_ENTRY ) ( ( PPEB ) PPEB_PTR )->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;

    do
    {
        DWORD ModuleHash = HashString( pModule->FullDllName.Buffer, pModule->FullDllName.Length );

        if ( ModuleHash == hModuleHash )
            return ( UINT_PTR ) pModule->Reserved2[ 0 ];

        pModule = ( PLDR_DATA_TABLE_ENTRY ) pModule->Reserved1[ 0 ];
    } while ( pModule && pModule != pFirstModule );

    return INVALID_HANDLE_VALUE;
}

SEC( text, B ) PVOID LdrFunctionAddr( UINT_PTR Module, UINT_PTR FunctionHash )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;

    ModuleNtHeader          = C_PTR( Module + ( ( PIMAGE_DOS_HEADER ) Module )->e_lfanew );
    ModuleExportedDirectory = C_PTR( Module + ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    AddressOfNames          = C_PTR( Module + ModuleExportedDirectory->AddressOfNames );
    AddressOfFunctions      = C_PTR( Module + ModuleExportedDirectory->AddressOfFunctions );
    AddressOfNameOrdinals   = C_PTR( Module + ModuleExportedDirectory->AddressOfNameOrdinals );

    for (DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++)
    {
        if ( HashString( C_PTR( Module + AddressOfNames[i] ), 0 ) == FunctionHash )
            return C_PTR( Module + AddressOfFunctions[ AddressOfNameOrdinals[ i ] ] );
    }
}