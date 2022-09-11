# Havoc Demon Agent

Havoc Demon Agent source code written in C 

# Build

```
make
```

# Directories

## Source/Asm
assembly code (return address stack spoofing)

## Source/Core
core functions ( connect to server, dynamically load win32 apis / syscalls )

## Source/Crypt
encryption / decryption functions

## Source/Extra
extra code ( KaynLdr Reflective Loader )

## Source/Inject 
injection functions and utilities

## Source/Loader
loaders ( COFF Loader + Beacon Api )

## Source/Main
Entry point of an PE executable 
- MainExe.c
    
Entry point of a Dll
- MainDll.c

Entry point of a Reflective Dll 
- MainReflectiveDll.c
