#ifndef DEMON_THREAD_H
#define DEMON_THREAD_H

#include <Common/Native.h>
#include <Core/Win32.h>

/* thread execution methods */
#define THREAD_METHOD_DEFAULT            0
#define THREAD_METHOD_CREATEREMOTETHREAD 1
#define THREAD_METHOD_NTCREATEHREADEX    2
#define THREAD_METHOD_NTQUEUEAPCTHREAD   3

BOOL ThreadQueryTib(
    IN  PVOID   Adr,
    OUT PNT_TIB Tib
);

HANDLE ThreadCreate(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  PVOID  Entry,
    IN  PVOID  Arg,
    OUT PDWORD ThreadId
);

#endif //DEMON_THREAD_H
