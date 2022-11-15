
#ifndef DEMON_SLEEPOBF_H
#define DEMON_SLEEPOBF_H

#include <windows.h>

VOID WINAPI CfgAddressAdd( LPVOID ImageBase, LPVOID Function );
VOID        SleepObf( UINT32 Timeout );

#endif