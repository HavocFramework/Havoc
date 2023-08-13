#ifndef DEMON_RUNTIME_H
#define DEMON_RUNTIME_H

#include <windows.h>

BOOL RtAdvapi32(
    VOID
);

BOOL RtMscoree(
    VOID
);

BOOL RtOleaut32(
    VOID
);

BOOL RtUser32(
    VOID
);

BOOL RtShell32(
    VOID
);

BOOL RtMsvcrt(
    VOID
);

BOOL RtIphlpapi(
    VOID
);

BOOL RtGdi32(
    VOID
);

BOOL RtNetApi32(
    VOID
);

BOOL RtWs2_32(
    VOID
);

BOOL RtSspicli(
    VOID
);

BOOL RtAmsi(
    VOID
);

#ifdef TRANSPORT_HTTP
BOOL RtWinHttp(
    VOID
);
#endif

#endif