#ifndef DEMON_TRANSPORTSMB_H
#define DEMON_TRANSPORTSMB_H

#include <Core/Win32.h>

#ifdef TRANSPORT_SMB

/* Objects we allocated and need to free */
typedef struct
{
    PSID Sid;
    PSID SidLow;
    PACL SAcl;

    PSECURITY_DESCRIPTOR SecDec;
} SMB_PIPE_SEC_ATTR, *PSMB_PIPE_SEC_ATTR;

BOOL SmbSend( PBUFFER Send );
BOOL SmbRecv( PBUFFER Resp );

VOID SmbSecurityAttrOpen( PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecurityAttr );
VOID SmbSecurityAttrFree( PSMB_PIPE_SEC_ATTR SmbSecAttr );

/* TRANSPORT_SMB */
#endif

/* DEMON_TRANSPORTSMB_H */
#endif
