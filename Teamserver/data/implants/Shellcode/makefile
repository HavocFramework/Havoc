CCX64	= x86_64-w64-mingw32-gcc
CCX86	= i686-w64-mingw32-gcc

CFLAGS	=  -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS 	+= -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS	+= -falign-labels=1 -fPIC -Wl,-TScripts/Linker.ld
CFLAGS	+= -Wl,-s,--no-seh,--enable-stdcall-fixup

EXECUTABLE_X64 = Bin/Shellcode.x64.exe
RAWBINARY_X64  = ../Shellcode.x64.bin

all: x64

x64: clean
	@ echo "[*] Compile x64 executable..."
	
	@ nasm -f win64 Source/Asm/x64/Asm.s -o Bin/Asm.x64.o
	@ $(CCX64) Source/*.c Bin/Asm.x64.o -o $(EXECUTABLE_X64) $(CFLAGS) $(LFLAGS) -IInclude -masm=intel

	@ echo "[*] Extract shellcode: $(RAWBINARY_X64)"
	@ python3 Scripts/extract.py -f $(EXECUTABLE_X64) -o $(RAWBINARY_X64)

	@ rm $(EXECUTABLE_X64)

clean:
	@ rm -rf Bin/*.o
	@ rm -rf Bin/*.bin
	@ rm -rf Bin/*.exe
