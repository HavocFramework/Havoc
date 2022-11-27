#ifndef DEMON_FILETRANFER_H
#define DEMON_FILETRANFER_H

#include <windows.h>

#define DOWNLOAD_MODE_OPEN       0x0
#define DOWNLOAD_MODE_WRITE      0x1
#define DOWNLOAD_MODE_CLOSE      0x2

#define DOWNLOAD_REASON_FINISHED 0x0
#define DOWNLOAD_REASON_REMOVED  0x1

#define DOWNLOAD_STATE_RUNNING   0x1
#define DOWNLOAD_STATE_STOPPED   0x2
#define DOWNLOAD_STATE_REMOVE    0x3

typedef enum {
    Running,
    Stopped,
    Remove,
} DownloadState;

typedef struct _DOWNLOAD_DATA
{
    /* Some random ID so both teamserver and agent knows what file it is */
    DWORD FileID;

    /* file handle opened/created using CreateFile */
    HANDLE hFile;

    /* What we have left to read. */
    DWORD Size;

    /* What we already read. */
    DWORD ReadSize;

    /* Current state of file transfer */
    DownloadState State;

    /* Next file in linked list */
    struct _DOWNLOAD_DATA* Next;
} DOWNLOAD_DATA, *PDOWNLOAD_DATA;

/* Add file to linked list with type (upload/download) */
PDOWNLOAD_DATA DownloadAdd( HANDLE hFile, DWORD MaxSize );

/* Get download data from linked list */
PDOWNLOAD_DATA DownloadGet( DWORD FileID );

BOOL DownloadRemove( DWORD FileID );

/* send file chunks to team server */
VOID DownloadPush();

#endif
