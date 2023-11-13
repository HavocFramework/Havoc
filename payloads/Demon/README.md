# Havoc Demon Agent

Havoc Demon Agent source code written in C and assembly  

# Directories

## src/asm
assembly code (return address stack spoofing)

## src/core
core functions ( connect to server, dynamically load win32 apis / syscalls )

## src/crypt
encryption / decryption functions

## src/inject 
injection functions and utilities

## src/main
Entry point of an PE executable 
- MainExe.c

Entry point of a Service executable
- MainSvc.c
    
Entry point of a Dll
- MainDll.c

### NOTE about the `CMakeLists.txt` file from the Developer
Do not modify it or use it. This is for only for developing and editing the Demon source code in Clion, it has no use for anyone else beside me (C5pider) or someone that uses Clion or any other IDE that supports CMake. It is only there to make Clion happy and show me references and to make my workflow faster that's it.