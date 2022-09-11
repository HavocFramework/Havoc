#ifndef CALLBACK_PACKAGE_H
#define CALLBACK_PACKAGE_H

#include <Demon.h>
#include <Core/Command.h>

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;

PPACKAGE PackageCreate( UINT32 CommandID );
PPACKAGE PackageNew( VOID );

/* PackageAddInt32
 * package => pointer to package response struct
 * dataInt => unsigned 32-bit integer data to add to the response
 * Description: Add unsigned 32-bit integer to the response buffer
 */
VOID PackageAddInt32(
        PPACKAGE package,
        UINT32 iData
);

VOID PackageAddInt64(
        PPACKAGE Package,
        UINT64 dataInt
);

// PackageAddBytes
VOID PackageAddBytes(
        PPACKAGE package,
        PUCHAR data,
        size_t dataSize
);

// PackageAddBytes
VOID PackageAddPad(
        PPACKAGE package,
        PUCHAR data,
        size_t dataSize
);

// PackageDestroy
VOID PackageDestroy(
        PPACKAGE package
);

// PackageTransmit
BOOL PackageTransmit(
        PPACKAGE Package,
        PVOID*   Response,
        PSIZE_T  Size
);

VOID PackageGen( PPACKAGE Package );

// PackageTransmitError
VOID PackageTransmitError(
        UINT32 CommandID,
        UINT32 ErrorCode
);

VOID PackageTransmitInfo(
        UINT32 CommandID,
        UINT32 InfoCode
);

#endif
