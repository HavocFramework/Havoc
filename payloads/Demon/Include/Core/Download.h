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

    /* The random task id associated with the requested download*/
    UINT32 RequestID;

    /* What we have left to read. */
    LONGLONG Size;

    /* What we already read. */
    LONGLONG ReadSize;

    /* Current state of file transfer */
    DownloadState State;

    /* Next file in linked list */
    struct _DOWNLOAD_DATA* Next;
} DOWNLOAD_DATA, *PDOWNLOAD_DATA;

/* This can be a BOF, a .NET binary or a generic file */
typedef struct _MEM_FILE
{
    /* Some random ID so both teamserver and agent knows what MemFile it is */
    ULONG32 ID;

    /* Size of the MemFile. */
    SIZE_T Size;

    /* What we already read. */
    SIZE_T ReadSize;

    /* Pointer to file contents */
    PVOID Data;

    /* Has the entire file been recieved? */
    BOOL IsCompleted;

    /* Next file in linked list */
    struct _MEM_FILE* Next;
} MEM_FILE, *PMEM_FILE;

/* Add file to linked list with type (upload/download) */
PDOWNLOAD_DATA DownloadAdd( HANDLE hFile, LONGLONG MaxSize );

/* Get download data from linked list */
PDOWNLOAD_DATA DownloadGet( DWORD FileID );

BOOL DownloadRemove( DWORD FileID );

/* send file chunks to team server */
VOID DownloadPush();

BOOL MemFileIsNew( ULONG32 ID );

PMEM_FILE GetMemFile( ULONG32 ID );

PMEM_FILE MemFileReadChunk( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize );

BOOL RemoveMemFile( ULONG32 ID );

/* Add a DataBlock to linked list */
PMEM_FILE NewMemFile( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize );

PMEM_FILE ProcessMemFileChunk( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize );

#endif
