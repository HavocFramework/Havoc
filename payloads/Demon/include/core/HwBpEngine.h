#ifndef DEMON_HWBPENGINE_H
#define DEMON_HWBPENGINE_H

#include <windows.h>
#include <ntstatus.h>

typedef struct _BP_LIST
{
    DWORD Tid;
    PVOID Address;
    PVOID Function;
    BYTE  Position;

    /* next in the list */
    struct _BP_LIST* Next;
} BP_LIST, *PBP_LIST;

typedef struct _HWBP_ENGINE
{
    /* Veh (Vectored Exception Handling) handle */
    HANDLE Veh;

    /* first time adding hw bp. need to prepare register */
    BYTE First;

    /* list of breakpoints */
    PBP_LIST Breakpoints;
} HWBP_ENGINE, *PHWBP_ENGINE;

NTSTATUS HwBpEngineInit(
    OUT PHWBP_ENGINE Engine,
    IN  PVOID        Exception
);

NTSTATUS HwBpEngineAdd(
    IN PHWBP_ENGINE Engine,
    IN DWORD        Tid,
    IN PVOID        Address,
    IN PVOID        Function,
    IN BYTE         Position
);

NTSTATUS HwBpEngineRemove(
    IN PHWBP_ENGINE Engine,
    IN DWORD        Tid,
    IN PVOID        Address
);

NTSTATUS HwBpEngineDestroy(
    IN PHWBP_ENGINE Engine
);

#endif