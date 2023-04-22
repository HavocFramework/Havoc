#ifndef DEMON_JOBS_HPP
#define DEMON_JOBS_HPP

#include <windows.h>

#define JOB_TYPE_THREAD         0x1
#define JOB_TYPE_PROCESS        0x2
#define JOB_TYPE_TRACK_PROCESS  0x3

#define JOB_STATE_RUNNING    0x1
#define JOB_STATE_SUSPENDED  0x2
#define JOB_STATE_DEAD       0x3

typedef struct _JOB_DATA
{
    UINT32            RequestID;
    DWORD             JobID;
    SHORT             Type;
    SHORT             State;
    HANDLE            Handle;
    PVOID             Data;
    struct _JOB_DATA* Next;
} JOB_DATA, *PJOB_DATA;

/*!
 * JobAdd
 * Adds a job to the job linked list
 * @param JobID
 * @param Type
 * @param State
 * @param Data
 * @return
 */
VOID JobAdd( UINT32 RequestID, DWORD JobID, SHORT Type, SHORT State, HANDLE Handle, PVOID Data );

/*!
 * Check if all jobs are still running and exists
 * @return
 */
VOID JobCheckList();

/*!
 * JobSuspend
 * Suspends the specified job
 * @param ThreadID
 * @return
 */
BOOL JobSuspend( DWORD JobID );

/*!
 * JobSuspend
 * Suspends the specified job
 * @param ThreadID
 * @return
 */
BOOL JobResume( DWORD JobID );

/*!
 * JobKill
 * Kills the specified job
 * @param ThreadID
 * @return
 */
BOOL JobKill( DWORD JobID );

/*!
 * JobRemove
 * Remove the specified job
 * @param ThreadID
 * @return
 */
VOID JobRemove( DWORD JobID );

#endif
