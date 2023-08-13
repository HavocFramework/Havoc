/*
	ntdll.h
	User Mode, 32bit & 64bit version
	Visual Studio 6.0 - Visual Studio 2010 and MingW compatible
	Intel C++ Compiler (ICL) 11.x - 12.x prefered

	(c) 2019 - Rokas Kupstys
	(c) 2009, 2010, 2011 - Fyyre
	(c) 2011 - 2012 EP_X0FF
	(c) 2011 - rndbit

	version 1.26 ( increment this if changes has global effect )
	please mark your changes date begin / date end comments

	last change 04/01/2012

	note: Please use _M_X86/_M_X64 for if(n)def/endif conditionals, instead of WIN32/WIN64.
*/

#if !defined(_NTDLL_)
#define _NTDLL_

#pragma warning( disable:4001 )	// level 4 error - nonstandard extension 'single line comment' was used
#pragma warning( disable:4201 )	// level 4 error - nonstandard extension used : nameless struct/union - ANSI C violation
#pragma warning( disable:4214 ) // level 4 error - nonstandard extension used : bit field types other than int - ANSI C violation

#if defined(__ICL)
#pragma warning ( disable : 344 )
#endif

#pragma pack( push, 8 )

#if defined(__cplusplus)
extern "C" {
#endif

#include <wtypes.h>
#include <basetsd.h>

#if !defined(NTSTATUS)
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

#if !defined(SECURITY_STATUS)
typedef LONG SECURITY_STATUS;
#endif

#define EXPORT_FN __declspec(dllexport)
#define IMPORT_FN __declspec(dllimport)

#define PAGE_SIZE 0x1000

#define EXTERNAL extern "C"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P)	(P)
#endif

#include "ntstatus.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30 == 1)
#define NT_WARNING(Status) ((ULONG)(Status) >> 30 == 2)
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)

#define ABSOLUTE_TIME(wait) (wait)
#define RELATIVE_TIME(wait) (-(wait))
#define NANOSECONDS(nanos)      \
    (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)    \
    (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)     \
    (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)        \
    (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define ARGUMENT_PRESENT(ArgumentPointer)    (\
	(CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )

#define RESTORE_LIST(ListEntry) \
	ListEntry.Flink = ListEntry.Flink; \
	ListEntry.Blink = ListEntry.Blink

#define UNLINK(x) (x).Blink->Flink = (x).Flink; \
	(x).Flink->Blink = (x).Blink;

#define ALIGN_TO_POWER2( x, n ) (((ULONG)(x) + ((n)-1)) & ~((ULONG)(n)-1))

#define POI(addr) *(ULONG *)(addr)

#define IS_PATH_SEPARATOR(ch) ((ch == '\\') || (ch == '/'))
#define IS_DOT(s) ( s[0] == '.' && ( IS_PATH_SEPARATOR(s[1]) || s[1] == '\0') )
#define IS_DOT_DOT(s) ( s[0] == '.' && s[1] == '.' && ( IS_PATH_SEPARATOR(s[2]) || s[2] == '\0') )

#define IS_PATH_SEPARATOR_U(ch) ((ch == (WCHAR)'\\') || (ch == (WCHAR)'/'))
#define IS_DOT_U(s) ( s[0] == (WCHAR)'.' && ( IS_PATH_SEPARATOR_U(s[1]) || s[1] == UNICODE_NULL) )
#define IS_DOT_DOT_U(s) ( s[0] == (WCHAR)'.' && s[1] == (WCHAR)'.' && ( IS_PATH_SEPARATOR_U(s[2]) || s[2] == UNICODE_NULL) )

#define jmp_length(y,x) ((x-y)-5)
#define stc_jc(y,x) ((x-y)-7)

#define MODIFYBYTE( _base, _offset, _byte ) { ((unsigned char *)_base)[_offset] = (unsigned char)_byte; }
#define MODIFYWORD( _base, _offset, _word ) { ((unsigned short *)_base)[_offset] = (unsigned short)_word; }
#define MODIFYDWORD( _base, _offset, _dword ) { ((unsigned long *)_base)[_offset] = (unsigned long)_dword; }
#define MODIFYQWORD( _base, _offset, _qword ) { ((unsigned long long *)_base)[_offset] = (unsigned long long)_qword; }

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

#define WRITE_JMP( from, to ) { ((PCHAR)from)[0] = (CHAR)0xE9; *((ULONG_PTR *)&(((PCHAR)(from))[1])) = (PCHAR)(to) - (PCHAR)(from) - 5; }
#define GET_JMP( from ) (((PCHAR)from)[0]==(CHAR)0xE9)? (*((ULONG_PTR *)&(((PCHAR)(from))[1])) + 5 + (ULONG_PTR)(from)) : 0

#define ASSERT( exp )	((void) 0)

//
// The following macros store and retrieve USHORTS and ULONGS from potentially unaligned addresses, avoiding alignment faults.
//

// 31.05.2011 - added the following macros
#define SHORT_SIZE		(sizeof(USHORT))
#define SHORT_MASK		(SHORT_SIZE - 1)
#define LONG_SIZE			(sizeof(LONG))
#define LONG_MASK			(LONG_SIZE - 1)
#define LOWBYTE_MASK	0x00FF

#define FIRSTBYTE(VALUE)  (VALUE & LOWBYTE_MASK)
#define SECONDBYTE(VALUE) ((VALUE >> 8) & LOWBYTE_MASK)
#define THIRDBYTE(VALUE)  ((VALUE >> 16) & LOWBYTE_MASK)
#define FOURTHBYTE(VALUE) ((VALUE >> 24) & LOWBYTE_MASK)

//
// if MIPS Big Endian, order of bytes is reversed.
//

#define SHORT_LEAST_SIGNIFICANT_BIT			0
#define SHORT_MOST_SIGNIFICANT_BIT			1

#define LONG_LEAST_SIGNIFICANT_BIT			0
#define LONG_3RD_MOST_SIGNIFICANT_BIT		1
#define LONG_2ND_MOST_SIGNIFICANT_BIT		2
#define LONG_MOST_SIGNIFICANT_BIT				3

//++
//
// VOID
// RtlStoreUshort (
//     PUSHORT ADDRESS
//     USHORT VALUE
//     )
//
// Routine Description:
//
// This macro stores a USHORT value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store USHORT value
//     VALUE - USHORT to store
//
// Return Value:
//
//     none.
//
//--

#define RtlStoreUshort(ADDRESS,VALUE)                     \
         if ((ULONG_PTR)ADDRESS & SHORT_MASK) {               \
             ((PUCHAR) ADDRESS)[SHORT_LEAST_SIGNIFICANT_BIT] = (UCHAR)(FIRSTBYTE(VALUE));    \
             ((PUCHAR) ADDRESS)[SHORT_MOST_SIGNIFICANT_BIT ] = (UCHAR)(SECONDBYTE(VALUE));   \
         }                                                \
         else {                                           \
             *((PUSHORT) ADDRESS) = (USHORT) VALUE;       \
         }


//++
//
// VOID
// RtlStoreUlong (
//     PULONG ADDRESS
//     ULONG VALUE
//     )
//
// Routine Description:
//
// This macro stores a ULONG value in at a particular address, avoiding
// alignment faults.
//
// Arguments:
//
//     ADDRESS - where to store ULONG value
//     VALUE - ULONG to store
//
// Return Value:
//
//     none.
//
// Note:
//     Depending on the machine, we might want to call storeushort in the
//     unaligned case.
//
//--

#define RtlStoreUlong(ADDRESS,VALUE)                      \
         if ((ULONG_PTR)ADDRESS & LONG_MASK) {                \
             ((PUCHAR) ADDRESS)[LONG_LEAST_SIGNIFICANT_BIT      ] = (UCHAR)(FIRSTBYTE(VALUE));    \
             ((PUCHAR) ADDRESS)[LONG_3RD_MOST_SIGNIFICANT_BIT   ] = (UCHAR)(SECONDBYTE(VALUE));   \
             ((PUCHAR) ADDRESS)[LONG_2ND_MOST_SIGNIFICANT_BIT   ] = (UCHAR)(THIRDBYTE(VALUE));    \
             ((PUCHAR) ADDRESS)[LONG_MOST_SIGNIFICANT_BIT       ] = (UCHAR)(FOURTHBYTE(VALUE));   \
         }                                                \
         else {                                           \
             *((PULONG) ADDRESS) = (ULONG) VALUE;         \
         }

//++
//
// VOID
// RtlRetrieveUshort (
//     PUSHORT DESTINATION_ADDRESS
//     PUSHORT SOURCE_ADDRESS
//     )
//
// Routine Description:
//
// This macro retrieves a USHORT value from the SOURCE address, avoiding
// alignment faults.  The DESTINATION address is assumed to be aligned.
//
// Arguments:
//
//     DESTINATION_ADDRESS - where to store USHORT value
//     SOURCE_ADDRESS - where to retrieve USHORT value from
//
// Return Value:
//
//     none.
//
//--

#define RtlRetrieveUshort(DEST_ADDRESS,SRC_ADDRESS)                   \
         if ((ULONG_PTR)SRC_ADDRESS & SHORT_MASK) {                       \
             ((PUCHAR) DEST_ADDRESS)[0] = ((PUCHAR) SRC_ADDRESS)[0];  \
             ((PUCHAR) DEST_ADDRESS)[1] = ((PUCHAR) SRC_ADDRESS)[1];  \
         }                                                            \
         else {                                                       \
             *((PUSHORT) DEST_ADDRESS) = *((PUSHORT) SRC_ADDRESS);    \
         }                                                            \

//++
//
// VOID
// RtlRetrieveUlong (
//     PULONG DESTINATION_ADDRESS
//     PULONG SOURCE_ADDRESS
//     )
//
// Routine Description:
//
// This macro retrieves a ULONG value from the SOURCE address, avoiding
// alignment faults.  The DESTINATION address is assumed to be aligned.
//
// Arguments:
//
//     DESTINATION_ADDRESS - where to store ULONG value
//     SOURCE_ADDRESS - where to retrieve ULONG value from
//
// Return Value:
//
//     none.
//
// Note:
//     Depending on the machine, we might want to call retrieveushort in the
//     unaligned case.
//
//--

#define RtlRetrieveUlong(DEST_ADDRESS,SRC_ADDRESS)                    \
         if ((ULONG_PTR)SRC_ADDRESS & LONG_MASK) {                        \
             ((PUCHAR) DEST_ADDRESS)[0] = ((PUCHAR) SRC_ADDRESS)[0];  \
             ((PUCHAR) DEST_ADDRESS)[1] = ((PUCHAR) SRC_ADDRESS)[1];  \
             ((PUCHAR) DEST_ADDRESS)[2] = ((PUCHAR) SRC_ADDRESS)[2];  \
             ((PUCHAR) DEST_ADDRESS)[3] = ((PUCHAR) SRC_ADDRESS)[3];  \
         }                                                            \
         else {                                                       \
             *((PULONG) DEST_ADDRESS) = *((PULONG) SRC_ADDRESS);      \
         }

//++
//
// PCHAR
// RtlOffsetToPointer (
//     PVOID Base,
//     ULONG Offset
//     )
//
// Routine Description:
//
// This macro generates a pointer which points to the byte that is 'Offset'
// bytes beyond 'Base'. This is useful for referencing fields within
// self-relative data structures.
//
// Arguments:
//
//     Base - The address of the base of the structure.
//
//     Offset - An unsigned integer offset of the byte whose address is to
//         be generated.
//
// Return Value:
//
//     A PCHAR pointer to the byte that is 'Offset' bytes beyond 'Base'.
//
//
//--

#define RtlOffsetToPointer(B,O)  ((PCHAR)( ((PCHAR)(B)) + ((ULONG_PTR)(O))  ))


//++
//
// ULONG
// RtlPointerToOffset (
//     PVOID Base,
//     PVOID Pointer
//     )
//
// Routine Description:
//
// This macro calculates the offset from Base to Pointer.  This is useful
// for producing self-relative offsets for structures.
//
// Arguments:
//
//     Base - The address of the base of the structure.
//
//     Pointer - A pointer to a field, presumably within the structure
//         pointed to by Base.  This value must be larger than that specified
//         for Base.
//
// Return Value:
//
//     A ULONG offset from Base to Pointer.
//
//
//--

#define RtlPointerToOffset(B,P)  ((ULONG)( ((PCHAR)(P)) - ((PCHAR)(B))  ))
// 31.05.2011 - end

//
// Data Types -- DOT NOT modify -- modification will break 32bit & 64bit compatibly.
//

typedef char CCHAR;
typedef short CSHORT;
typedef CCHAR *PCCHAR;
typedef CSHORT *PCSHORT;
typedef ULONG CLONG;
typedef ULONG *PCLONG;

typedef ULONG LOGICAL;
typedef ULONG *PLOGICAL;

typedef LONG KPRIORITY;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;

typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _CSTRING
{
	USHORT Length;
	USHORT MaximumLength;
	CONST char *Buffer;
} CSTRING;
typedef CSTRING *PCSTRING;
#define ANSI_NULL ((CHAR)0)

typedef STRING CANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, **PPUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING32;
typedef STRING32 *PSTRING32;

typedef STRING32 UNICODE_STRING32;
typedef UNICODE_STRING32 *PUNICODE_STRING32;
#define UNICODE_NULL ((WCHAR)0)

typedef STRING32 ANSI_STRING32;
typedef ANSI_STRING32 *PANSI_STRING32;

typedef struct _STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	ULONG_PTR	Buffer;
} STRING64;

typedef STRING64 *PSTRING64;

typedef STRING64 UNICODE_STRING64;
typedef UNICODE_STRING64 *PUNICODE_STRING64;

typedef STRING64 ANSI_STRING64;
typedef ANSI_STRING64 *PANSI_STRING64;

typedef USHORT RTL_ATOM;
typedef RTL_ATOM *PRTL_ATOM;

typedef UCHAR KIRQL;
typedef KIRQL *PKIRQL;

typedef CONST char *PCSZ;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

#if !defined( _WINNT_ )

typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;

#define FIELD_OFFSET(type, field)    ((LONG)&(((type *)0)->field))

#define CONTAINING_RECORD(address, type, field) ((type FAR *)( \
                                          (PCHAR)(address) - \
                                          (PCHAR)(&((type *)0)->field)))
#endif

typedef struct _TRIPLE_LIST_ENTRY
{
	struct _TRIPLE_LIST_ENTRY* Flink[ 3 ];
	struct _TRIPLE_LIST_ENTRY* Blink;
} TRIPLE_LIST_ENTRY, *PTRIPLE_LIST_ENTRY;

#define IN_REGION(x, Base, Size) (((ULONG)x >= (ULONG_PTR)Base) && ((ULONG)x <= (ULONG_PTR)Base + (ULONG)Size))

#ifndef RVATOVA
#define RVATOVA(base, offset) ((PVOID)((ULONG)base + (ULONG)(offset)))
#endif

#ifndef NOP_FUNCTION
#define NOP_FUNCTION (void)0
#endif
#define PAGED_CODE() NOP_FUNCTION;

#if defined(USE_LPC6432)
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif

#define OBJ_INHERIT             0x00000002L
#define OBJ_HANDLE_TAGBITS			0x00000003L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#define RTL_QUERY_PROCESS_MODULES       0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES    0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY  0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS     0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES  0x00000010
#define RTL_QUERY_PROCESS_LOCKS         0x00000020
#define RTL_QUERY_PROCESS_MODULES32     0x00000040
#define RTL_QUERY_PROCESS_NONINVASIVE   0x80000000

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}

//added 20.12.11
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#if defined(_WINNT_) && (_MSC_VER < 1300) && !defined(___PROCESSOR_NUMBER_DEFINED)
#define ___PROCESSOR_NUMBER_DEFINED
typedef struct _PROCESSOR_NUMBER {
	WORD Group;
	BYTE Number;
	BYTE Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;
#endif

#if _WIN32_WINNT >= 0x0501

#define ANSI_NULL ((CHAR)0)     
#define UNICODE_NULL ((WCHAR)0) 

#ifndef UNICODE_STRING_MAX_BYTES
#define UNICODE_STRING_MAX_BYTES ((USHORT) 65534)
#endif

#define UNICODE_STRING_MAX_CHARS (32767)

#define DECLARE_CONST_UNICODE_STRING(_variablename, _string) \
	const WCHAR _variablename ## _buffer[] = _string; \
	const UNICODE_STRING _variablename = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWSTR) _variablename ## _buffer };

#endif // _WIN32_WINNT >= 0x0501

#define IsListEmpty(ListHead) \
	((ListHead)->Flink == (ListHead))

#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveTailList(ListHead) \
    (ListHead)->Blink;\
    {RemoveEntryList((ListHead)->Blink)}

// VOID
// RemoveEntryList(
//     IN PLIST_ENTRY Entry
//     );
#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }


// VOID
// InsertTailList(
//     IN PLIST_ENTRY ListHead,
//     IN PLIST_ENTRY Entry
//     );
#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

// VOID
// InsertHeadList(
//     IN PLIST_ENTRY ListHead,
//     IN PLIST_ENTRY Entry
//     );
#define InsertHeadList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Flink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Flink = _EX_ListHead->Flink;\
    (Entry)->Flink = _EX_Flink;\
    (Entry)->Blink = _EX_ListHead;\
    _EX_Flink->Blink = (Entry);\
    _EX_ListHead->Flink = (Entry);\
    }

// BOOL
// COUNT_IS_ALIGNED(
//     IN DWORD Count,
//     IN DWORD Pow2      // undefined if this isn't a power of 2.
//     );
//
#define COUNT_IS_ALIGNED(Count,Pow2) \
        ( ( ( (Count) & (((Pow2)-1)) ) == 0) ? TRUE : FALSE )

// BOOL
// POINTER_IS_ALIGNED(
//     IN LPVOID Ptr,
//     IN DWORD Pow2      // undefined if this isn't a power of 2.
//     );
//
#define POINTER_IS_ALIGNED(Ptr,Pow2) \
        ( ( ( ((DWORD)(Ptr)) & (((Pow2)-1)) ) == 0) ? TRUE : FALSE )


#define ROUND_DOWN_COUNT(Count,Pow2) \
        ( (Count) & (~((Pow2)-1)) )

#define ROUND_DOWN_POINTER(Ptr,Pow2) \
        ( (LPVOID) ROUND_DOWN_COUNT( ((DWORD)(Ptr)), (Pow2) ) )


// If Count is not already aligned, then
// round Count up to an even multiple of "Pow2".  "Pow2" must be a power of 2.
//
// DWORD
// ROUND_UP_COUNT(
//     IN DWORD Count,
//     IN DWORD Pow2
//     );
#define ROUND_UP_COUNT(Count,Pow2) \
        ( ((Count)+(Pow2)-1) & (~((Pow2)-1)) )

// LPVOID
// ROUND_UP_POINTER(
//     IN LPVOID Ptr,
//     IN DWORD Pow2
//     );

// If Ptr is not already aligned, then round it up until it is.
#define ROUND_UP_POINTER(Ptr,Pow2) \
        ( (LPVOID) ( (((DWORD)(Ptr))+(Pow2)-1) & (~((Pow2)-1)) ) )

#define ALIGN_BYTE					1
#define ALIGN_CHAR					1
#define ALIGN_DESC_CHAR			sizeof(DESC_CHAR)
#define ALIGN_DWORD					4
#define ALIGN_LONG					4
#define ALIGN_LPBYTE				4
#define ALIGN_LPDWORD				4
#define ALIGN_LPSTR					4
#define ALIGN_LPTSTR				4
#define ALIGN_LPVOID				4
#define ALIGN_LPWORD				4
#define ALIGN_TCHAR					sizeof(TCHAR)
#define ALIGN_WCHAR					sizeof(WCHAR)
#define ALIGN_WORD					2
#define ALIGN_QUAD					8

#define ALIGN_WORST					8

//03.06.2011 - added
#define QUAD_ALIGN(VALUE) ( ((ULONG)(VALUE) + 7) & ~7 )
//03.06.2011 - end

// Usage: myPtr = ROUND_UP_POINTER(unalignedPtr, ALIGN_DWORD);

// 31.05.2011 - added
#define EXPORT_VA(x)     ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
#define IMPORT_VA(x)     ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
#define RELOC_VA(x)      ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
#define RESOURCE_VA(x)   ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)

#define EXPORT_SIZE(x)   ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
#define IMPORT_SIZE(x)   ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
#define RELOC_SIZE(x)    ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
#define RESOURCE_SIZE(x) ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size)
#define DEBUGDIR_VA(x)   ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)
#define DEBUGDIR_SIZE(x) ((x)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size)
// 31.05.2011 - end

#define IS_VALID_HANDLE(hHandle) ((HANDLE)hHandle != (HANDLE)0 && (HANDLE)hHandle != (HANDLE)0xFFFFFFFF)
#define SIZEOF_ARRAY(arr) ( sizeof(arr) / sizeof(arr[0]) )
// 09.06.2011 - begin

//21.12.2011 added
#if !defined(_FILESYSTEMFSCTL_)
#define _FILESYSTEMFSCTL_

#define FSCTL_REQUEST_OPLOCK_LEVEL_1    CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2    CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_REQUEST_BATCH_OPLOCK      CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE  CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPBATCH_ACK_CLOSE_PENDING CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_NOTIFY       CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_LOCK_VOLUME               CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_UNLOCK_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DISMOUNT_VOLUME           CTL_CODE(FILE_DEVICE_FILE_SYSTEM,  8, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                              9
#define FSCTL_IS_VOLUME_MOUNTED         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_PATHNAME_VALID         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 11, METHOD_BUFFERED, FILE_ANY_ACCESS) // PATHNAME_BUFFER,
#define FSCTL_MARK_VOLUME_DIRTY         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             13
#define FSCTL_QUERY_RETRIEVAL_POINTERS  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 14,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_GET_COMPRESSION           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SET_COMPRESSION           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
// decommissioned fsctl value                                             17
// decommissioned fsctl value                                             18
#define FSCTL_SET_BOOTLOADER_ACCESSED   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 19,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_OPLOCK_BREAK_ACK_NO_2     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_INVALIDATE_VOLUMES        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_FAT_BPB             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 22, METHOD_BUFFERED, FILE_ANY_ACCESS) // FSCTL_QUERY_FAT_BPB_BUFFER
#define FSCTL_REQUEST_FILTER_OPLOCK     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_FILESYSTEM_GET_STATISTICS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 24, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILESYSTEM_STATISTICS

#if (_WIN32_WINNT >= 0x0400)
#define FSCTL_GET_NTFS_VOLUME_DATA      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS) // NTFS_VOLUME_DATA_BUFFER
#define FSCTL_GET_NTFS_FILE_RECORD      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 26, METHOD_BUFFERED, FILE_ANY_ACCESS) // NTFS_FILE_RECORD_INPUT_BUFFER, NTFS_FILE_RECORD_OUTPUT_BUFFER
#define FSCTL_GET_VOLUME_BITMAP         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 27,  METHOD_NEITHER, FILE_ANY_ACCESS) // STARTING_LCN_INPUT_BUFFER, VOLUME_BITMAP_BUFFER
#define FSCTL_GET_RETRIEVAL_POINTERS    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 28,  METHOD_NEITHER, FILE_ANY_ACCESS) // STARTING_VCN_INPUT_BUFFER, RETRIEVAL_POINTERS_BUFFER
#define FSCTL_MOVE_FILE                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 29, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // MOVE_FILE_DATA,
#define FSCTL_IS_VOLUME_DIRTY           CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 30, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decomissioned fsctl value                                              31
#define FSCTL_ALLOW_EXTENDED_DASD_IO    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 32, METHOD_NEITHER,  FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0500)
// decommissioned fsctl value                                             33
// decommissioned fsctl value                                             34
#define FSCTL_FIND_FILES_BY_SID         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 35, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             36
// decommissioned fsctl value                                             37
#define FSCTL_SET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_GET_OBJECT_ID             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 39, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_DELETE_OBJECT_ID          CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 40, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_GET_REPARSE_POINT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS) // REPARSE_DATA_BUFFER
#define FSCTL_DELETE_REPARSE_POINT      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // REPARSE_DATA_BUFFER,
#define FSCTL_ENUM_USN_DATA             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 44,  METHOD_NEITHER, FILE_ANY_ACCESS) // MFT_ENUM_DATA,
#define FSCTL_SECURITY_ID_CHECK         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 45,  METHOD_NEITHER, FILE_READ_DATA)  // BULK_SECURITY_TEST_DATA,
#define FSCTL_READ_USN_JOURNAL          CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46,  METHOD_NEITHER, FILE_ANY_ACCESS) // READ_USN_JOURNAL_DATA, USN
#define FSCTL_SET_OBJECT_ID_EXTENDED    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 47, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_CREATE_OR_GET_OBJECT_ID   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 48, METHOD_BUFFERED, FILE_ANY_ACCESS) // FILE_OBJECTID_BUFFER
#define FSCTL_SET_SPARSE                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_ZERO_DATA             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 50, METHOD_BUFFERED, FILE_WRITE_DATA) // FILE_ZERO_DATA_INFORMATION,
#define FSCTL_QUERY_ALLOCATED_RANGES    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 51,  METHOD_NEITHER, FILE_READ_DATA)  // FILE_ALLOCATED_RANGE_BUFFER, FILE_ALLOCATED_RANGE_BUFFER
#define FSCTL_ENABLE_UPGRADE            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 52, METHOD_BUFFERED, FILE_WRITE_DATA)
// decommissioned fsctl value                                             52
#define FSCTL_SET_ENCRYPTION            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 53,  METHOD_NEITHER, FILE_ANY_ACCESS) // ENCRYPTION_BUFFER, DECRYPTION_STATUS_BUFFER
#define FSCTL_ENCRYPTION_FSCTL_IO       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 54,  METHOD_NEITHER, FILE_ANY_ACCESS)
#define FSCTL_WRITE_RAW_ENCRYPTED       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 55,  METHOD_NEITHER, FILE_SPECIAL_ACCESS) // ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_READ_RAW_ENCRYPTED        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 56,  METHOD_NEITHER, FILE_SPECIAL_ACCESS) // REQUEST_RAW_ENCRYPTED_DATA, ENCRYPTED_DATA_INFO, EXTENDED_ENCRYPTED_DATA_INFO
#define FSCTL_CREATE_USN_JOURNAL        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 57,  METHOD_NEITHER, FILE_ANY_ACCESS) // CREATE_USN_JOURNAL_DATA,
#define FSCTL_READ_FILE_USN_DATA        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 58,  METHOD_NEITHER, FILE_ANY_ACCESS) // Read the Usn Record for a file
#define FSCTL_WRITE_USN_CLOSE_RECORD    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 59,  METHOD_NEITHER, FILE_ANY_ACCESS) // Generate Close Usn Record
#define FSCTL_EXTEND_VOLUME             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 60, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_QUERY_USN_JOURNAL         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DELETE_USN_JOURNAL        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 62, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_MARK_HANDLE               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 63, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_COPYFILE              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 64, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_SIS_LINK_FILES            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 65, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
// decommissional fsctl value                                             66
// decommissioned fsctl value                                             67
// decommissioned fsctl value                                             68
#define FSCTL_RECALL_FILE               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 69, METHOD_NEITHER, FILE_ANY_ACCESS)
// decommissioned fsctl value                                             70
#define FSCTL_READ_FROM_PLEX            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 71, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define FSCTL_FILE_PREFETCH             CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // FILE_PREFETCH
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_MAKE_MEDIA_COMPATIBLE         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 76, METHOD_BUFFERED, FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_SET_DEFECT_MANAGEMENT         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 77, METHOD_BUFFERED, FILE_WRITE_DATA) // UDFS R/W
#define FSCTL_QUERY_SPARING_INFO            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 78, METHOD_BUFFERED, FILE_ANY_ACCESS) // UDFS R/W
#define FSCTL_QUERY_ON_DISK_VOLUME_INFO     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 79, METHOD_BUFFERED, FILE_ANY_ACCESS) // C/UDFS
#define FSCTL_SET_VOLUME_COMPRESSION_STATE  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 80, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // VOLUME_COMPRESSION_STATE
// decommissioned fsctl value                                                 80
#define FSCTL_TXFS_MODIFY_RM                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 81, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_QUERY_RM_INFORMATION     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 82, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
// decommissioned fsctl value                                                 83
#define FSCTL_TXFS_ROLLFORWARD_REDO         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 84, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_ROLLFORWARD_UNDO         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 85, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_START_RM                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 86, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_SHUTDOWN_RM              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 87, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_READ_BACKUP_INFORMATION  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 88, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 89, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_SECONDARY_RM      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 90, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_GET_METADATA_INFO        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 91, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_TXFS_GET_TRANSACTED_VERSION   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 92, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
// decommissioned fsctl value                                                 93
#define FSCTL_TXFS_SAVEPOINT_INFORMATION    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 94, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
#define FSCTL_TXFS_CREATE_MINIVERSION       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 95, METHOD_BUFFERED, FILE_WRITE_DATA) // TxF
// decommissioned fsctl value                                                 96
// decommissioned fsctl value                                                 97
// decommissioned fsctl value                                                 98
#define FSCTL_TXFS_TRANSACTION_ACTIVE       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 99, METHOD_BUFFERED, FILE_READ_DATA)  // TxF
#define FSCTL_SET_ZERO_ON_DEALLOCATION      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FSCTL_SET_REPAIR                    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_GET_REPAIR                    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 103, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_WAIT_FOR_REPAIR               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 104, METHOD_BUFFERED, FILE_ANY_ACCESS)
// decommissioned fsctl value                                                 105
#define FSCTL_INITIATE_REPAIR               CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 106, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSC_INTERNAL                  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 107, METHOD_NEITHER, FILE_ANY_ACCESS) // CSC internal implementation
#define FSCTL_SHRINK_VOLUME                 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 108, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) // SHRINK_VOLUME_INFORMATION
#define FSCTL_SET_SHORT_NAME_BEHAVIOR       CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 109, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_DFSR_SET_GHOST_HANDLE_STATE   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 110, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
//  Values 111 - 119 are reserved for FSRM.
//

#define FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES \
                                            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 120, METHOD_BUFFERED, FILE_READ_DATA) // TxF
#define FSCTL_TXFS_LIST_TRANSACTIONS        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 121, METHOD_BUFFERED, FILE_READ_DATA) // TxF
#define FSCTL_QUERY_PAGEFILE_ENCRYPTION     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 122, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_RESET_VOLUME_ALLOCATION_HINTS CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 123, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_QUERY_DEPENDENT_VOLUME        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 124, METHOD_BUFFERED, FILE_ANY_ACCESS)    // Dependency File System Filter
#define FSCTL_SD_GLOBAL_CHANGE              CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 125, METHOD_BUFFERED, FILE_ANY_ACCESS) // Update NTFS Security Descriptors
#endif /* _WIN32_WINNT >= 0x0601 */

#if (_WIN32_WINNT >= 0x0600)
#define FSCTL_TXFS_READ_BACKUP_INFORMATION2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 126, METHOD_BUFFERED, FILE_ANY_ACCESS) // TxF
#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_LOOKUP_STREAM_FROM_CLUSTER    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 127, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 128, METHOD_BUFFERED, FILE_ANY_ACCESS) // TxF
#define FSCTL_FILE_TYPE_NOTIFICATION        CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 129, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

//  Values 130 - 130 are available
//  Values 131 - 139 are reserved for FSRM.

#if (_WIN32_WINNT >= 0x0601)
#define FSCTL_GET_BOOT_AREA_INFO            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 140, METHOD_BUFFERED, FILE_ANY_ACCESS) // BOOT_AREA_INFO
#define FSCTL_GET_RETRIEVAL_POINTER_BASE    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 141, METHOD_BUFFERED, FILE_ANY_ACCESS) // RETRIEVAL_POINTER_BASE
#define FSCTL_SET_PERSISTENT_VOLUME_STATE   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 142, METHOD_BUFFERED, FILE_ANY_ACCESS)  // FILE_FS_PERSISTENT_VOLUME_INFORMATION
#define FSCTL_QUERY_PERSISTENT_VOLUME_STATE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 143, METHOD_BUFFERED, FILE_ANY_ACCESS)  // FILE_FS_PERSISTENT_VOLUME_INFORMATION

#define FSCTL_REQUEST_OPLOCK                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FSCTL_CSV_TUNNEL_REQUEST            CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 145, METHOD_BUFFERED, FILE_ANY_ACCESS) // CSV_TUNNEL_REQUEST
#define FSCTL_IS_CSV_FILE                   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 146, METHOD_BUFFERED, FILE_ANY_ACCESS) // IS_CSV_FILE

#define FSCTL_QUERY_FILE_SYSTEM_RECOGNITION CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 147, METHOD_BUFFERED, FILE_ANY_ACCESS) // 
#define FSCTL_CSV_GET_VOLUME_PATH_NAME      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 148, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 149, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 150,  METHOD_BUFFERED, FILE_ANY_ACCESS)
#define FSCTL_IS_FILE_ON_CSV_VOLUME         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 151,  METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _WIN32_WINNT >= 0x0601 */

#define FSCTL_MARK_AS_SYSTEM_HIVE           FSCTL_SET_BOOTLOADER_ACCESSED


#if(_WIN32_WINNT >= 0x0601)

typedef struct _CSV_NAMESPACE_INFO {

    ULONG         Version;
    ULONG         DeviceNumber;
    LARGE_INTEGER StartingOffset;
    ULONG         SectorSize;

} CSV_NAMESPACE_INFO, *PCSV_NAMESPACE_INFO;

#define CSV_NAMESPACE_INFO_V1 (sizeof(CSV_NAMESPACE_INFO))
#define CSV_INVALID_DEVICE_NUMBER 0xFFFFFFFF

#endif /* _WIN32_WINNT >= 0x0601 */

typedef struct _PATHNAME_BUFFER {

    ULONG PathNameLength;
    WCHAR Name[1];

} PATHNAME_BUFFER, *PPATHNAME_BUFFER;

typedef struct _FSCTL_QUERY_FAT_BPB_BUFFER {

    UCHAR First0x24BytesOfBootSector[0x24];

} FSCTL_QUERY_FAT_BPB_BUFFER, *PFSCTL_QUERY_FAT_BPB_BUFFER;

#if (_WIN32_WINNT >= 0x0400)

typedef struct {

    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    ULONG BytesPerSector;
    ULONG BytesPerCluster;
    ULONG BytesPerFileRecordSegment;
    ULONG ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength;
    LARGE_INTEGER MftStartLcn;
    LARGE_INTEGER Mft2StartLcn;
    LARGE_INTEGER MftZoneStart;
    LARGE_INTEGER MftZoneEnd;

} NTFS_VOLUME_DATA_BUFFER, *PNTFS_VOLUME_DATA_BUFFER;

typedef struct {

    ULONG ByteCount;

    USHORT MajorVersion;
    USHORT MinorVersion;

} NTFS_EXTENDED_VOLUME_DATA, *PNTFS_EXTENDED_VOLUME_DATA;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)

typedef struct {

    LARGE_INTEGER StartingLcn;

} STARTING_LCN_INPUT_BUFFER, *PSTARTING_LCN_INPUT_BUFFER;

typedef struct {

    LARGE_INTEGER StartingLcn;
    LARGE_INTEGER BitmapSize;
    UCHAR Buffer[1];

} VOLUME_BITMAP_BUFFER, *PVOLUME_BITMAP_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)

typedef struct {

    LARGE_INTEGER StartingVcn;

} STARTING_VCN_INPUT_BUFFER, *PSTARTING_VCN_INPUT_BUFFER;

typedef struct RETRIEVAL_POINTERS_BUFFER {

    ULONG ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct {
        LARGE_INTEGER NextVcn;
        LARGE_INTEGER Lcn;
    } Extents[1];

} RETRIEVAL_POINTERS_BUFFER, *PRETRIEVAL_POINTERS_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)

typedef struct {

    LARGE_INTEGER FileReferenceNumber;

} NTFS_FILE_RECORD_INPUT_BUFFER, *PNTFS_FILE_RECORD_INPUT_BUFFER;

typedef struct {

    LARGE_INTEGER FileReferenceNumber;
    ULONG FileRecordLength;
    UCHAR FileRecordBuffer[1];

} NTFS_FILE_RECORD_OUTPUT_BUFFER, *PNTFS_FILE_RECORD_OUTPUT_BUFFER;
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0400)

typedef struct {

    HANDLE FileHandle;
    LARGE_INTEGER StartingVcn;
    LARGE_INTEGER StartingLcn;
    ULONG ClusterCount;

} MOVE_FILE_DATA, *PMOVE_FILE_DATA;

typedef struct {

    HANDLE FileHandle;
    LARGE_INTEGER SourceFileRecord;
    LARGE_INTEGER TargetFileRecord;

} MOVE_FILE_RECORD_DATA, *PMOVE_FILE_RECORD_DATA;


#if defined(_WIN64)

typedef struct _MOVE_FILE_DATA32 {

    UINT32 FileHandle;
    LARGE_INTEGER StartingVcn;
    LARGE_INTEGER StartingLcn;
    ULONG ClusterCount;

} MOVE_FILE_DATA32, *PMOVE_FILE_DATA32;
#endif
#endif /* _WIN32_WINNT >= 0x0400 */

#if (_WIN32_WINNT >= 0x0500)

typedef struct {
    ULONG Restart;
    SID Sid;
} FIND_BY_SID_DATA, *PFIND_BY_SID_DATA;

typedef struct {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FIND_BY_SID_OUTPUT, *PFIND_BY_SID_OUTPUT;

#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)

typedef struct {

    ULONGLONG StartFileReferenceNumber;
    USN LowUsn;
    USN HighUsn;

} MFT_ENUM_DATA, *PMFT_ENUM_DATA;

typedef struct {

    ULONGLONG MaximumSize;
    ULONGLONG AllocationDelta;

} CREATE_USN_JOURNAL_DATA, *PCREATE_USN_JOURNAL_DATA;

typedef struct {

    USN StartUsn;
    ULONG ReasonMask;
    ULONG ReturnOnlyOnClose;
    ULONGLONG Timeout;
    ULONGLONG BytesToWaitFor;
    ULONGLONG UsnJournalID;

} READ_USN_JOURNAL_DATA, *PREAD_USN_JOURNAL_DATA;

typedef struct {

    ULONG RecordLength;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONGLONG FileReferenceNumber;
    ULONGLONG ParentFileReferenceNumber;
    USN Usn;
    LARGE_INTEGER TimeStamp;
    ULONG Reason;
    ULONG SourceInfo;
    ULONG SecurityId;
    ULONG FileAttributes;
    USHORT FileNameLength;
    USHORT FileNameOffset;
    WCHAR FileName[1];

} USN_RECORD, *PUSN_RECORD;

#define USN_PAGE_SIZE                    (0x1000)

#define USN_REASON_DATA_OVERWRITE        (0x00000001)
#define USN_REASON_DATA_EXTEND           (0x00000002)
#define USN_REASON_DATA_TRUNCATION       (0x00000004)
#define USN_REASON_NAMED_DATA_OVERWRITE  (0x00000010)
#define USN_REASON_NAMED_DATA_EXTEND     (0x00000020)
#define USN_REASON_NAMED_DATA_TRUNCATION (0x00000040)
#define USN_REASON_FILE_CREATE           (0x00000100)
#define USN_REASON_FILE_DELETE           (0x00000200)
#define USN_REASON_EA_CHANGE             (0x00000400)
#define USN_REASON_SECURITY_CHANGE       (0x00000800)
#define USN_REASON_RENAME_OLD_NAME       (0x00001000)
#define USN_REASON_RENAME_NEW_NAME       (0x00002000)
#define USN_REASON_INDEXABLE_CHANGE      (0x00004000)
#define USN_REASON_BASIC_INFO_CHANGE     (0x00008000)
#define USN_REASON_HARD_LINK_CHANGE      (0x00010000)
#define USN_REASON_COMPRESSION_CHANGE    (0x00020000)
#define USN_REASON_ENCRYPTION_CHANGE     (0x00040000)
#define USN_REASON_OBJECT_ID_CHANGE      (0x00080000)
#define USN_REASON_REPARSE_POINT_CHANGE  (0x00100000)
#define USN_REASON_STREAM_CHANGE         (0x00200000)
#define USN_REASON_TRANSACTED_CHANGE     (0x00400000)
#define USN_REASON_CLOSE                 (0x80000000)

typedef struct {

    ULONGLONG UsnJournalID;
    USN FirstUsn;
    USN NextUsn;
    USN LowestValidUsn;
    USN MaxUsn;
    ULONGLONG MaximumSize;
    ULONGLONG AllocationDelta;

} USN_JOURNAL_DATA, *PUSN_JOURNAL_DATA;

typedef struct {

    ULONGLONG UsnJournalID;
    ULONG DeleteFlags;

} DELETE_USN_JOURNAL_DATA, *PDELETE_USN_JOURNAL_DATA;

#define USN_DELETE_FLAG_DELETE              (0x00000001)
#define USN_DELETE_FLAG_NOTIFY              (0x00000002)

#define USN_DELETE_VALID_FLAGS              (0x00000003)

typedef struct {

    ULONG UsnSourceInfo;
    HANDLE VolumeHandle;
    ULONG HandleInfo;

} MARK_HANDLE_INFO, *PMARK_HANDLE_INFO;

#if defined(_WIN64)

typedef struct {

    ULONG UsnSourceInfo;
    UINT32 VolumeHandle;
    ULONG HandleInfo;

} MARK_HANDLE_INFO32, *PMARK_HANDLE_INFO32;
#endif

#define USN_SOURCE_DATA_MANAGEMENT          (0x00000001)
#define USN_SOURCE_AUXILIARY_DATA           (0x00000002)
#define USN_SOURCE_REPLICATION_MANAGEMENT   (0x00000004)

#define MARK_HANDLE_PROTECT_CLUSTERS        (0x00000001)
#define MARK_HANDLE_TXF_SYSTEM_LOG          (0x00000004)
#define MARK_HANDLE_NOT_TXF_SYSTEM_LOG      (0x00000008)

#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0601)

#define MARK_HANDLE_REALTIME                (0x00000020)
#define MARK_HANDLE_NOT_REALTIME            (0x00000040)

#define NO_8DOT3_NAME_PRESENT               (0x00000001)
#define REMOVED_8DOT3_NAME                  (0x00000002)

#define PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED        (0x00000001)

#endif /* _WIN32_WINNT >= 0x0601 */


#if (_WIN32_WINNT >= 0x0500)
typedef struct {

    ACCESS_MASK DesiredAccess;
    ULONG SecurityIds[1];

} BULK_SECURITY_TEST_DATA, *PBULK_SECURITY_TEST_DATA;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)

#define VOLUME_IS_DIRTY                  (0x00000001)
#define VOLUME_UPGRADE_SCHEDULED         (0x00000002)
#define VOLUME_SESSION_OPEN              (0x00000004)
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)

typedef struct _FILE_PREFETCH {
    ULONG Type;
    ULONG Count;
    ULONGLONG Prefetch[1];
} FILE_PREFETCH, *PFILE_PREFETCH;

typedef struct _FILE_PREFETCH_EX {
    ULONG Type;
    ULONG Count;
    PVOID Context;
    ULONGLONG Prefetch[1];
} FILE_PREFETCH_EX, *PFILE_PREFETCH_EX;

#define FILE_PREFETCH_TYPE_FOR_CREATE       0x1
#define FILE_PREFETCH_TYPE_FOR_DIRENUM      0x2
#define FILE_PREFETCH_TYPE_FOR_CREATE_EX    0x3
#define FILE_PREFETCH_TYPE_FOR_DIRENUM_EX   0x4

#define FILE_PREFETCH_TYPE_MAX              0x4

#endif /* _WIN32_WINNT >= 0x0500 */

typedef struct _FILESYSTEM_STATISTICS {

    USHORT FileSystemType;
    USHORT Version;                     // currently version 1

    ULONG SizeOfCompleteStructure;      // must by a mutiple of 64 bytes

    ULONG UserFileReads;
    ULONG UserFileReadBytes;
    ULONG UserDiskReads;
    ULONG UserFileWrites;
    ULONG UserFileWriteBytes;
    ULONG UserDiskWrites;

    ULONG MetaDataReads;
    ULONG MetaDataReadBytes;
    ULONG MetaDataDiskReads;
    ULONG MetaDataWrites;
    ULONG MetaDataWriteBytes;
    ULONG MetaDataDiskWrites;
} FILESYSTEM_STATISTICS, *PFILESYSTEM_STATISTICS;

// values for FS_STATISTICS.FileSystemType

#define FILESYSTEM_STATISTICS_TYPE_NTFS     1
#define FILESYSTEM_STATISTICS_TYPE_FAT      2
#define FILESYSTEM_STATISTICS_TYPE_EXFAT    3
typedef struct _FAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;

    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;

    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} FAT_STATISTICS, *PFAT_STATISTICS;

typedef struct _EXFAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;

    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;

    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} EXFAT_STATISTICS, *PEXFAT_STATISTICS;

typedef struct _NTFS_STATISTICS {

    ULONG LogFileFullExceptions;
    ULONG OtherExceptions;

		ULONG MftReads;
    ULONG MftReadBytes;
    ULONG MftWrites;
    ULONG MftWriteBytes;
    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } MftWritesUserLevel;

    USHORT MftWritesFlushForLogFileFull;
    USHORT MftWritesLazyWriter;
    USHORT MftWritesUserRequest;

    ULONG Mft2Writes;
    ULONG Mft2WriteBytes;
    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } Mft2WritesUserLevel;

    USHORT Mft2WritesFlushForLogFileFull;
    USHORT Mft2WritesLazyWriter;
    USHORT Mft2WritesUserRequest;

    ULONG RootIndexReads;
    ULONG RootIndexReadBytes;
    ULONG RootIndexWrites;
    ULONG RootIndexWriteBytes;

    ULONG BitmapReads;
    ULONG BitmapReadBytes;
    ULONG BitmapWrites;
    ULONG BitmapWriteBytes;

    USHORT BitmapWritesFlushForLogFileFull;
    USHORT BitmapWritesLazyWriter;
    USHORT BitmapWritesUserRequest;

    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
    } BitmapWritesUserLevel;

    ULONG MftBitmapReads;
    ULONG MftBitmapReadBytes;
    ULONG MftBitmapWrites;
    ULONG MftBitmapWriteBytes;

    USHORT MftBitmapWritesFlushForLogFileFull;
    USHORT MftBitmapWritesLazyWriter;
    USHORT MftBitmapWritesUserRequest;

    struct {
        USHORT Write;
        USHORT Create;
        USHORT SetInfo;
        USHORT Flush;
    } MftBitmapWritesUserLevel;

    ULONG UserIndexReads;
    ULONG UserIndexReadBytes;
    ULONG UserIndexWrites;
    ULONG UserIndexWriteBytes;
    ULONG LogFileReads;
    ULONG LogFileReadBytes;
    ULONG LogFileWrites;
    ULONG LogFileWriteBytes;

    struct {
        ULONG Calls;                // number of individual calls to allocate clusters
        ULONG Clusters;             // number of clusters allocated
        ULONG Hints;                // number of times a hint was specified

        ULONG RunsReturned;         // number of runs used to satisify all the requests

        ULONG HintsHonored;         // number of times the hint was useful
        ULONG HintsClusters;        // number of clusters allocated via the hint
        ULONG Cache;                // number of times the cache was useful other than the hint
        ULONG CacheClusters;        // number of clusters allocated via the cache other than the hint
        ULONG CacheMiss;            // number of times the cache wasn't useful
        ULONG CacheMissClusters;    // number of clusters allocated without the cache
    } Allocate;

} NTFS_STATISTICS, *PNTFS_STATISTICS;

#if (_WIN32_WINNT >= 0x0500)

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _FILE_OBJECTID_BUFFER {

    UCHAR ObjectId[16];

    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        } DUMMYSTRUCTNAME;
        UCHAR ExtendedInfo[48];
    } DUMMYUNIONNAME;

} FILE_OBJECTID_BUFFER, *PFILE_OBJECTID_BUFFER;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 ) /* nonstandard extension used : nameless struct/union */
#endif

#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)

typedef struct _FILE_SET_SPARSE_BUFFER {
    BOOLEAN SetSparse;
} FILE_SET_SPARSE_BUFFER, *PFILE_SET_SPARSE_BUFFER;


#endif /* _WIN32_WINNT >= 0x0500 */



#if (_WIN32_WINNT >= 0x0500)

typedef struct _FILE_ZERO_DATA_INFORMATION {

    LARGE_INTEGER FileOffset;
    LARGE_INTEGER BeyondFinalZero;

} FILE_ZERO_DATA_INFORMATION, *PFILE_ZERO_DATA_INFORMATION;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)

typedef struct _FILE_ALLOCATED_RANGE_BUFFER {

    LARGE_INTEGER FileOffset;
    LARGE_INTEGER Length;

} FILE_ALLOCATED_RANGE_BUFFER, *PFILE_ALLOCATED_RANGE_BUFFER;
#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)

typedef struct _ENCRYPTION_BUFFER {

    ULONG EncryptionOperation;
    UCHAR Private[1];

} ENCRYPTION_BUFFER, *PENCRYPTION_BUFFER;

#define FILE_SET_ENCRYPTION         0x00000001
#define FILE_CLEAR_ENCRYPTION       0x00000002
#define STREAM_SET_ENCRYPTION       0x00000003
#define STREAM_CLEAR_ENCRYPTION     0x00000004

#define MAXIMUM_ENCRYPTION_VALUE    0x00000004

typedef struct _DECRYPTION_STATUS_BUFFER {

    BOOLEAN NoEncryptedStreams;

} DECRYPTION_STATUS_BUFFER, *PDECRYPTION_STATUS_BUFFER;

#define ENCRYPTION_FORMAT_DEFAULT        (0x01)

#define COMPRESSION_FORMAT_SPARSE        (0x4000)

typedef struct _REQUEST_RAW_ENCRYPTED_DATA {

    LONGLONG FileOffset;
    ULONG Length;

} REQUEST_RAW_ENCRYPTED_DATA, *PREQUEST_RAW_ENCRYPTED_DATA;

typedef struct _ENCRYPTED_DATA_INFO {

    ULONGLONG StartingFileOffset;

    ULONG OutputBufferOffset;

    ULONG BytesWithinFileSize;

    ULONG BytesWithinValidDataLength;

    USHORT CompressionFormat;

    UCHAR DataUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;

    UCHAR EncryptionFormat;

		USHORT NumberOfDataBlocks;

    ULONG DataBlockSize[ANYSIZE_ARRAY];

} ENCRYPTED_DATA_INFO;
typedef ENCRYPTED_DATA_INFO *PENCRYPTED_DATA_INFO;
#endif /* _WIN32_WINNT >= 0x0500 */


#if (_WIN32_WINNT >= 0x0500)

typedef struct _PLEX_READ_DATA_REQUEST {

    LARGE_INTEGER ByteOffset;
    ULONG ByteLength;
    ULONG PlexNumber;

} PLEX_READ_DATA_REQUEST, *PPLEX_READ_DATA_REQUEST;
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0500)

typedef struct _SI_COPYFILE {
    ULONG SourceFileNameLength;
    ULONG DestinationFileNameLength;
    ULONG Flags;
    WCHAR FileNameBuffer[1];
} SI_COPYFILE, *PSI_COPYFILE;

#define COPYFILE_SIS_LINK       0x0001              // Copy only if source is SIS
#define COPYFILE_SIS_REPLACE    0x0002              // Replace destination if it exists, otherwise don't.
#define COPYFILE_SIS_FLAGS      0x0003
#endif /* _WIN32_WINNT >= 0x0500 */

#if (_WIN32_WINNT >= 0x0600)

typedef struct _FILE_MAKE_COMPATIBLE_BUFFER {
    BOOLEAN CloseDisc;
} FILE_MAKE_COMPATIBLE_BUFFER, *PFILE_MAKE_COMPATIBLE_BUFFER;


typedef struct _FILE_SET_DEFECT_MGMT_BUFFER {
    BOOLEAN Disable;
} FILE_SET_DEFECT_MGMT_BUFFER, *PFILE_SET_DEFECT_MGMT_BUFFER;


typedef struct _FILE_QUERY_SPARING_BUFFER {
    ULONG SparingUnitBytes;
    BOOLEAN SoftwareSparing;
    ULONG TotalSpareBlocks;
    ULONG FreeSpareBlocks;
} FILE_QUERY_SPARING_BUFFER, *PFILE_QUERY_SPARING_BUFFER;


typedef struct _FILE_QUERY_ON_DISK_VOL_INFO_BUFFER {
    LARGE_INTEGER DirectoryCount;       // -1 = unknown
    LARGE_INTEGER FileCount;            // -1 = unknown
    USHORT FsFormatMajVersion;          // -1 = unknown or n/a
    USHORT FsFormatMinVersion;          // -1 = unknown or n/a
    WCHAR FsFormatName[ 12];
    LARGE_INTEGER FormatTime;
    LARGE_INTEGER LastUpdateTime;
    WCHAR CopyrightInfo[ 34];
    WCHAR AbstractInfo[ 34];
    WCHAR FormattingImplementationInfo[ 34];
    WCHAR LastModifyingImplementationInfo[ 34];
} FILE_QUERY_ON_DISK_VOL_INFO_BUFFER, *PFILE_QUERY_ON_DISK_VOL_INFO_BUFFER;


#define SET_REPAIR_ENABLED                                      (0x00000001)
#define SET_REPAIR_VOLUME_BITMAP_SCAN                           (0x00000002)
#define SET_REPAIR_DELETE_CROSSLINK                             (0x00000004)
#define SET_REPAIR_WARN_ABOUT_DATA_LOSS                         (0x00000008)
#define SET_REPAIR_DISABLED_AND_BUGCHECK_ON_CORRUPT             (0x00000010)
#define SET_REPAIR_VALID_MASK                                   (0x0000001F)

typedef enum _SHRINK_VOLUME_REQUEST_TYPES
{
    ShrinkPrepare = 1,
    ShrinkCommit,
    ShrinkAbort

} SHRINK_VOLUME_REQUEST_TYPES, *PSHRINK_VOLUME_REQUEST_TYPES;

typedef struct _SHRINK_VOLUME_INFORMATION
{
    SHRINK_VOLUME_REQUEST_TYPES ShrinkRequestType;
    ULONGLONG Flags;
    LONGLONG NewNumberOfSectors;

} SHRINK_VOLUME_INFORMATION, *PSHRINK_VOLUME_INFORMATION;

#define TXFS_RM_FLAG_LOGGING_MODE                           0x00000001
#define TXFS_RM_FLAG_RENAME_RM                              0x00000002
#define TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX                0x00000004
#define TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN                0x00000008
#define TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS    0x00000010
#define TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT           0x00000020
#define TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE             0x00000040
#define TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX             0x00000080
#define TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN             0x00000100
#define TXFS_RM_FLAG_GROW_LOG                               0x00000400
#define TXFS_RM_FLAG_SHRINK_LOG                             0x00000800
#define TXFS_RM_FLAG_ENFORCE_MINIMUM_SIZE                   0x00001000
#define TXFS_RM_FLAG_PRESERVE_CHANGES                       0x00002000
#define TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                 0x00004000
#define TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START          0x00008000
#define TXFS_RM_FLAG_PREFER_CONSISTENCY                     0x00010000
#define TXFS_RM_FLAG_PREFER_AVAILABILITY                    0x00020000

#define TXFS_LOGGING_MODE_SIMPLE        (0x0001)
#define TXFS_LOGGING_MODE_FULL          (0x0002)

#define TXFS_TRANSACTION_STATE_NONE         0x00
#define TXFS_TRANSACTION_STATE_ACTIVE       0x01
#define TXFS_TRANSACTION_STATE_PREPARED     0x02
#define TXFS_TRANSACTION_STATE_NOTACTIVE    0x03

#define TXFS_MODIFY_RM_VALID_FLAGS                                      \
                (TXFS_RM_FLAG_LOGGING_MODE                          |   \
                 TXFS_RM_FLAG_RENAME_RM                             |   \
                 TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX               |   \
                 TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN               |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS   |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT          |   \
                 TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN            |   \
                 TXFS_RM_FLAG_SHRINK_LOG                            |   \
                 TXFS_RM_FLAG_GROW_LOG                              |   \
                 TXFS_RM_FLAG_ENFORCE_MINIMUM_SIZE                  |   \
                 TXFS_RM_FLAG_PRESERVE_CHANGES                      |   \
                 TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                |   \
                 TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START         |   \
                 TXFS_RM_FLAG_PREFER_CONSISTENCY                    |   \
                 TXFS_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_MODIFY_RM {

    //
    //  TXFS_RM_FLAG_* flags
    //

    ULONG Flags;

    //
    //  Maximum log container count if TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MAX is set.
    //

    ULONG LogContainerCountMax;

    //
    //  Minimum log container count if TXFS_RM_FLAG_LOG_CONTAINER_COUNT_MIN is set.
    //

    ULONG LogContainerCountMin;

    //
    //  Target log container count for TXFS_RM_FLAG_SHRINK_LOG or _GROW_LOG.
    //

    ULONG LogContainerCount;

    //
    //  When the log is full, increase its size by this much.  Indicated as either a percent of
    //  the log size or absolute container count, depending on which of the TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_*
    //  flags is set.
    //

    ULONG LogGrowthIncrement;

    //
    //  Sets autoshrink policy if TXFS_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE is set.  Autoshrink
    //  makes the log shrink so that no more than this percentage of the log is free at any time.
    //

    ULONG LogAutoShrinkPercentage;

    //
    //  Reserved.
    //

    ULONGLONG Reserved;

    //
    //  If TXFS_RM_FLAG_LOGGING_MODE is set, this must contain one of TXFS_LOGGING_MODE_SIMPLE
    //  or TXFS_LOGGING_MODE_FULL.
    //

    USHORT LoggingMode;

} TXFS_MODIFY_RM,
 *PTXFS_MODIFY_RM;

#define TXFS_RM_STATE_NOT_STARTED       0
#define TXFS_RM_STATE_STARTING          1
#define TXFS_RM_STATE_ACTIVE            2
#define TXFS_RM_STATE_SHUTTING_DOWN     3

#define TXFS_QUERY_RM_INFORMATION_VALID_FLAGS                           \
                (TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS   |   \
                 TXFS_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT          |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX            |   \
                 TXFS_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN            |   \
                 TXFS_RM_FLAG_RESET_RM_AT_NEXT_START                |   \
                 TXFS_RM_FLAG_DO_NOT_RESET_RM_AT_NEXT_START         |   \
                 TXFS_RM_FLAG_PREFER_CONSISTENCY                    |   \
                 TXFS_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_QUERY_RM_INFORMATION {

	ULONG BytesRequired;
	
	ULONGLONG TailLsn;
	ULONGLONG CurrentLsn;
	ULONGLONG ArchiveTailLsn;
	ULONGLONG LogContainerSize;
	LARGE_INTEGER HighestVirtualClock;
	ULONG LogContainerCount;
	ULONG LogContainerCountMax;
	ULONG LogContainerCountMin;
	ULONG LogGrowthIncrement;
	ULONG LogAutoShrinkPercentage;
	ULONG Flags;

    //
    //  Exactly one of TXFS_LOGGING_MODE_SIMPLE or TXFS_LOGGING_MODE_FULL.
    //

    USHORT LoggingMode;

    //
    //  Reserved.
    //

    USHORT Reserved;

    //
    //  Activity state of the RM.  May be exactly one of the above-defined TXF_RM_STATE_ values.
    //

    ULONG RmState;

    //
    //  Total capacity of the log in bytes.
    //

    ULONGLONG LogCapacity;

    //
    //  Amount of free space in the log in bytes.
    //

    ULONGLONG LogFree;

    //
    //  Size of $Tops in bytes.
    //

    ULONGLONG TopsSize;

    //
    //  Amount of space in $Tops in use.
    //

    ULONGLONG TopsUsed;

    //
    //  Number of transactions active in the RM at the time of the call.
    //

    ULONGLONG TransactionCount;

    //
    //  Total number of single-phase commits that have happened the RM.
    //

    ULONGLONG OnePCCount;

    //
    //  Total number of two-phase commits that have happened the RM.
    //

    ULONGLONG TwoPCCount;

    //
    //  Number of times the log has filled up.
    //

    ULONGLONG NumberLogFileFull;

    //
    //  Age of oldest active transaction in the RM, in milliseconds.
    //

    ULONGLONG OldestTransactionAge;

		GUID RMName;

    ULONG TmLogPathOffset;

} TXFS_QUERY_RM_INFORMATION,
 *PTXFS_QUERY_RM_INFORMATION;

#define TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_REDO_LSN        0x01
#define TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_VIRTUAL_CLOCK   0x02

#define TXFS_ROLLFORWARD_REDO_VALID_FLAGS                               \
                (TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_REDO_LSN |         \
                 TXFS_ROLLFORWARD_REDO_FLAG_USE_LAST_VIRTUAL_CLOCK)

typedef struct _TXFS_ROLLFORWARD_REDO_INFORMATION {
    LARGE_INTEGER  LastVirtualClock;
    ULONGLONG LastRedoLsn;
    ULONGLONG HighestRecoveryLsn;
    ULONG Flags;
} TXFS_ROLLFORWARD_REDO_INFORMATION,
 *PTXFS_ROLLFORWARD_REDO_INFORMATION;

#define TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MAX              0x00000001
#define TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MIN              0x00000002
#define TXFS_START_RM_FLAG_LOG_CONTAINER_SIZE                   0x00000004
#define TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS  0x00000008
#define TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT         0x00000010
#define TXFS_START_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE           0x00000020
#define TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX           0x00000040
#define TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MIN           0x00000080

#define TXFS_START_RM_FLAG_RECOVER_BEST_EFFORT                  0x00000200
#define TXFS_START_RM_FLAG_LOGGING_MODE                         0x00000400
#define TXFS_START_RM_FLAG_PRESERVE_CHANGES                     0x00000800

#define TXFS_START_RM_FLAG_PREFER_CONSISTENCY                   0x00001000
#define TXFS_START_RM_FLAG_PREFER_AVAILABILITY                  0x00002000

#define TXFS_START_RM_VALID_FLAGS                                           \
                (TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MAX             |   \
                 TXFS_START_RM_FLAG_LOG_CONTAINER_COUNT_MIN             |   \
                 TXFS_START_RM_FLAG_LOG_CONTAINER_SIZE                  |   \
                 TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_NUM_CONTAINERS |   \
                 TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_PERCENT        |   \
                 TXFS_START_RM_FLAG_LOG_AUTO_SHRINK_PERCENTAGE          |   \
                 TXFS_START_RM_FLAG_RECOVER_BEST_EFFORT                 |   \
                 TXFS_START_RM_FLAG_LOG_NO_CONTAINER_COUNT_MAX          |   \
                 TXFS_START_RM_FLAG_LOGGING_MODE                        |   \
                 TXFS_START_RM_FLAG_PRESERVE_CHANGES                    |   \
                 TXFS_START_RM_FLAG_PREFER_CONSISTENCY                  |   \
                 TXFS_START_RM_FLAG_PREFER_AVAILABILITY)

typedef struct _TXFS_START_RM_INFORMATION {

    //
    //  TXFS_START_RM_FLAG_* flags.
    //

    ULONG Flags;

    //
    //  RM log container size, in bytes.  This parameter is optional.
    //

    ULONGLONG LogContainerSize;

    //
    //  RM minimum log container count.  This parameter is optional.
    //

    ULONG LogContainerCountMin;

    //
    //  RM maximum log container count.  This parameter is optional.
    //

    ULONG LogContainerCountMax;

    //
    //  RM log growth increment in number of containers or percent, as indicated
    //  by TXFS_START_RM_FLAG_LOG_GROWTH_INCREMENT_* flag.  This parameter is
    //  optional.
    //

    ULONG LogGrowthIncrement;

    //
    //  RM log auto shrink percentage.  This parameter is optional.
    //

    ULONG LogAutoShrinkPercentage;

    //
    //  Offset from the beginning of this structure to the log path for the KTM
    //  instance to be used by this RM.  This must be a two-byte (WCHAR) aligned
    //  value.  This parameter is required.
    //

    ULONG TmLogPathOffset;

    //
    //  Length in bytes of log path for the KTM instance to be used by this RM.
    //  This parameter is required.
    //

    USHORT TmLogPathLength;

    //
    //  Logging mode for this RM.  One of TXFS_LOGGING_MODE_SIMPLE or
    //  TXFS_LOGGING_MODE_FULL (mutually exclusive).  This parameter is optional,
    //  and will default to TXFS_LOGGING_MODE_SIMPLE.
    //

    USHORT LoggingMode;

    //
    //  Length in bytes of the path to the log to be used by the RM.  This parameter
    //  is required.
    //

    USHORT LogPathLength;

    //
    //  Reserved.
    //

    USHORT Reserved;

    //
    //  The path to the log (in Unicode characters) to be used by the RM goes here.
    //  This parameter is required.
    //

    WCHAR LogPath[1];

} TXFS_START_RM_INFORMATION,
 *PTXFS_START_RM_INFORMATION;

//
//  Structures for FSCTL_TXFS_GET_METADATA_INFO
//

typedef struct _TXFS_GET_METADATA_INFO_OUT {

    //
    //  Returns the TxfId of the file referenced by the handle used to call this routine.
    //

    struct {
        LONGLONG LowPart;
        LONGLONG HighPart;
    } TxfFileId;

    //
    //  The GUID of the transaction that has the file locked, if applicable.
    //

    GUID LockingTransaction;

    //
    //  Returns the LSN for the most recent log record we've written for the file.
    //

    ULONGLONG LastLsn;

    //
    //  Transaction state, a TXFS_TRANSACTION_STATE_* value.
    //

    ULONG TransactionState;

} TXFS_GET_METADATA_INFO_OUT, *PTXFS_GET_METADATA_INFO_OUT;

#define TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_CREATED   0x00000001
#define TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_DELETED   0x00000002

typedef struct _TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY {

    //
    //  Offset in bytes from the beginning of the TXFS_LIST_TRANSACTION_LOCKED_FILES
    //  structure to the next TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY.
    //

    ULONGLONG Offset;

    //
    //  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY_FLAG_* flags to indicate whether the
    //  current name was deleted or created in the transaction.
    //

    ULONG NameFlags;

    //
    //  NTFS File ID of the file.
    //

    LONGLONG FileId;

    //
    //  Reserved.
    //

    ULONG Reserved1;
    ULONG Reserved2;
    LONGLONG Reserved3;

    //
    //  NULL-terminated Unicode path to this file, relative to RM root.
    //

    WCHAR FileName[1];
} TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY, *PTXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY;


typedef struct _TXFS_LIST_TRANSACTION_LOCKED_FILES {

    //
    //  GUID name of the KTM transaction that files should be enumerated from.
    //

    GUID KtmTransaction;

    //
    //  On output, the number of files involved in the transaction on this RM.
    //

    ULONGLONG NumberOfFiles;

    //
    //  The length of the buffer required to obtain the complete list of files.
    //  This value may change from call to call as the transaction locks more files.
    //

    ULONGLONG BufferSizeRequired;

    //
    //  Offset in bytes from the beginning of this structure to the first
    //  TXFS_LIST_TRANSACTION_LOCKED_FILES_ENTRY.
    //

    ULONGLONG Offset;
} TXFS_LIST_TRANSACTION_LOCKED_FILES, *PTXFS_LIST_TRANSACTION_LOCKED_FILES;

//
//  Structures for FSCTL_TXFS_LIST_TRANSACTIONS
//

typedef struct _TXFS_LIST_TRANSACTIONS_ENTRY {

    //
    //  Transaction GUID.
    //

    GUID TransactionId;

    //
    //  Transaction state, a TXFS_TRANSACTION_STATE_* value.
    //

    ULONG TransactionState;

    //
    //  Reserved fields
    //

    ULONG Reserved1;
    ULONG Reserved2;
    LONGLONG Reserved3;
} TXFS_LIST_TRANSACTIONS_ENTRY, *PTXFS_LIST_TRANSACTIONS_ENTRY;

typedef struct _TXFS_LIST_TRANSACTIONS {

    //
    //  On output, the number of transactions involved in this RM.
    //

    ULONGLONG NumberOfTransactions;

    //
    //  The length of the buffer required to obtain the complete list of
    //  transactions.  Note that this value may change from call to call
    //  as transactions enter and exit the system.
    //

    ULONGLONG BufferSizeRequired;
} TXFS_LIST_TRANSACTIONS, *PTXFS_LIST_TRANSACTIONS;


#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _TXFS_READ_BACKUP_INFORMATION_OUT {
    union {

        //
        //  Used to return the required buffer size if return code is STATUS_BUFFER_OVERFLOW
        //

        ULONG BufferLength;

        //
        //  On success the data is copied here.
        //

        UCHAR Buffer[1];
    } DUMMYUNIONNAME;
} TXFS_READ_BACKUP_INFORMATION_OUT, *PTXFS_READ_BACKUP_INFORMATION_OUT;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 )
#endif

typedef struct _TXFS_WRITE_BACKUP_INFORMATION {
    UCHAR Buffer[1];
} TXFS_WRITE_BACKUP_INFORMATION, *PTXFS_WRITE_BACKUP_INFORMATION;

#define TXFS_TRANSACTED_VERSION_NONTRANSACTED   0xFFFFFFFE
#define TXFS_TRANSACTED_VERSION_UNCOMMITTED     0xFFFFFFFF

typedef struct _TXFS_GET_TRANSACTED_VERSION {

    //
    //  The version that this handle is opened to.  This will be
    //  TXFS_TRANSACTED_VERSION_UNCOMMITTED for nontransacted and
    //  transactional writer handles.
    //

    ULONG ThisBaseVersion;

    //
    //  The most recent committed version available.
    //

    ULONG LatestVersion;

    //
    //  If this is a handle to a miniversion, the ID of the miniversion.
    //  If it is not a handle to a minivers, this field will be 0.
    //

    USHORT ThisMiniVersion;

    //
    //  The first available miniversion.  Unless the miniversions are
    //  visible to the transaction bound to this handle, this field will be zero.
    //

    USHORT FirstMiniVersion;

    //
    //  The latest available miniversion.  Unless the miniversions are
    //  visible to the transaction bound to this handle, this field will be zero.
    //

    USHORT LatestMiniVersion;

} TXFS_GET_TRANSACTED_VERSION, *PTXFS_GET_TRANSACTED_VERSION;


#define TXFS_SAVEPOINT_SET                      0x00000001

//
//  Roll back to a specified savepoint.
//

#define TXFS_SAVEPOINT_ROLLBACK                 0x00000002

//
//  Clear (make unavailable for rollback) the most recently set savepoint
//  that has not yet been cleared.
//

#define TXFS_SAVEPOINT_CLEAR                    0x00000004

//
//  Clear all savepoints from the transaction.
//

#define TXFS_SAVEPOINT_CLEAR_ALL                0x00000010

typedef struct _TXFS_SAVEPOINT_INFORMATION {
    HANDLE KtmTransaction;
    ULONG ActionCode;
    ULONG SavepointId;
} TXFS_SAVEPOINT_INFORMATION, *PTXFS_SAVEPOINT_INFORMATION;


typedef struct _TXFS_CREATE_MINIVERSION_INFO {

    USHORT StructureVersion;
    USHORT StructureLength;
    ULONG BaseVersion;
    USHORT MiniVersion;
} TXFS_CREATE_MINIVERSION_INFO, *PTXFS_CREATE_MINIVERSION_INFO;


typedef struct _TXFS_TRANSACTION_ACTIVE_INFO {
	BOOLEAN TransactionsActiveAtSnapshot;

} TXFS_TRANSACTION_ACTIVE_INFO, *PTXFS_TRANSACTION_ACTIVE_INFO;

#endif /* _WIN32_WINNT >= 0x0600 */

#if (_WIN32_WINNT >= 0x0601)

typedef struct _BOOT_AREA_INFO {

    ULONG               BootSectorCount;  // the count of boot sectors present on the file system
    struct {
        LARGE_INTEGER   Offset;
    } BootSectors[2];                     // variable number of boot sectors.

} BOOT_AREA_INFO, *PBOOT_AREA_INFO;

typedef struct _RETRIEVAL_POINTER_BASE {

    LARGE_INTEGER       FileAreaOffset; // sector offset to the first allocatable unit on the filesystem
} RETRIEVAL_POINTER_BASE, *PRETRIEVAL_POINTER_BASE;

typedef struct _FILE_FS_PERSISTENT_VOLUME_INFORMATION {

    ULONG VolumeFlags;
    ULONG FlagMask;
    ULONG Version;
    ULONG Reserved;

} FILE_FS_PERSISTENT_VOLUME_INFORMATION, *PFILE_FS_PERSISTENT_VOLUME_INFORMATION;

typedef struct _FILE_SYSTEM_RECOGNITION_INFORMATION {

    CHAR FileSystem[9];

} FILE_SYSTEM_RECOGNITION_INFORMATION, *PFILE_SYSTEM_RECOGNITION_INFORMATION;

#define OPLOCK_LEVEL_CACHE_READ         (0x00000001)
#define OPLOCK_LEVEL_CACHE_HANDLE       (0x00000002)
#define OPLOCK_LEVEL_CACHE_WRITE        (0x00000004)

#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST               (0x00000001)
#define REQUEST_OPLOCK_INPUT_FLAG_ACK                   (0x00000002)
#define REQUEST_OPLOCK_INPUT_FLAG_COMPLETE_ACK_ON_CLOSE (0x00000004)

#define REQUEST_OPLOCK_CURRENT_VERSION          1

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {

    //
    //  This should be set to REQUEST_OPLOCK_CURRENT_VERSION.
    //

    USHORT StructureVersion;

    USHORT StructureLength;

    //
    //  One or more OPLOCK_LEVEL_CACHE_* values to indicate the desired level of the oplock.
    //

    ULONG RequestedOplockLevel;

    //
    //  REQUEST_OPLOCK_INPUT_FLAG_* flags.
    //

    ULONG Flags;

} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

#define REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED     (0x00000001)
#define REQUEST_OPLOCK_OUTPUT_FLAG_MODES_PROVIDED   (0x00000002)

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {

    USHORT StructureVersion;

    USHORT StructureLength;

    ULONG OriginalOplockLevel;

    ULONG NewOplockLevel;

    ULONG Flags;

    ACCESS_MASK AccessMode;

    USHORT ShareMode;

} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;


#define SD_GLOBAL_CHANGE_TYPE_MACHINE_SID   1

typedef struct _SD_CHANGE_MACHINE_SID_INPUT {

    USHORT CurrentMachineSIDOffset;
    USHORT CurrentMachineSIDLength;

    USHORT NewMachineSIDOffset;
    USHORT NewMachineSIDLength;

} SD_CHANGE_MACHINE_SID_INPUT, *PSD_CHANGE_MACHINE_SID_INPUT;

typedef struct _SD_CHANGE_MACHINE_SID_OUTPUT {

    //
    //  How many entries were successfully changed in the $Secure stream
    //

    ULONGLONG NumSDChangedSuccess;

    //
    //  How many entires failed the update in the $Secure stream
    //

    ULONGLONG NumSDChangedFail;

    //
    //  How many entires are unused in the current security stream
    //

    ULONGLONG NumSDUnused;

    //
    //  The total number of entries processed in the $Secure stream
    //

    ULONGLONG NumSDTotal;

    //
    //  How many entries were successfully changed in the $MFT file
    //

    ULONGLONG NumMftSDChangedSuccess;

    //
    //  How many entries failed the update in the $MFT file
    //

    ULONGLONG NumMftSDChangedFail;

    //
    //  Total number of entriess process in the $MFT file
    //

    ULONGLONG NumMftSDTotal;

} SD_CHANGE_MACHINE_SID_OUTPUT, *PSD_CHANGE_MACHINE_SID_OUTPUT;

//
//  Generic INPUT & OUTPUT structures for FSCTL_SD_GLOBAL_CHANGE
//

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4201)       // unnamed struct

typedef struct _SD_GLOBAL_CHANGE_INPUT
{
    //
    //  Input flags (none currently defined)
    //

    ULONG Flags;

    //
    //  Specifies which type of change we are doing and pics which member
    //  of the below union is in use.
    //

    ULONG ChangeType;

    union {

        SD_CHANGE_MACHINE_SID_INPUT SdChange;
    };

} SD_GLOBAL_CHANGE_INPUT, *PSD_GLOBAL_CHANGE_INPUT;

typedef struct _SD_GLOBAL_CHANGE_OUTPUT
{

    //
    //  Output State Flags (none currently defined)
    //

    ULONG Flags;

    //
    //  Specifies which below union to use
    //

    ULONG ChangeType;

    union {

        SD_CHANGE_MACHINE_SID_OUTPUT SdChange;
    };

} SD_GLOBAL_CHANGE_OUTPUT, *PSD_GLOBAL_CHANGE_OUTPUT;

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning( default : 4201 ) /* nonstandard extension used : nameless struct/union */
#endif

//
//  Flag to indicate the encrypted file is sparse
//

#define ENCRYPTED_DATA_INFO_SPARSE_FILE    1

typedef struct _EXTENDED_ENCRYPTED_DATA_INFO {

    ULONG ExtendedCode;
    ULONG Length;
    ULONG Flags;
    ULONG Reserved;

} EXTENDED_ENCRYPTED_DATA_INFO, *PEXTENDED_ENCRYPTED_DATA_INFO;


typedef struct _LOOKUP_STREAM_FROM_CLUSTER_INPUT {
    ULONG         Flags;
    ULONG         NumberOfClusters;
    LARGE_INTEGER Cluster[1];
} LOOKUP_STREAM_FROM_CLUSTER_INPUT, *PLOOKUP_STREAM_FROM_CLUSTER_INPUT;

typedef struct _LOOKUP_STREAM_FROM_CLUSTER_OUTPUT {
    ULONG         Offset;
    ULONG         NumberOfMatches;
    ULONG         BufferSizeRequired;
} LOOKUP_STREAM_FROM_CLUSTER_OUTPUT, *PLOOKUP_STREAM_FROM_CLUSTER_OUTPUT;

#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_PAGE_FILE          0x00000001
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_DENY_DEFRAG_SET    0x00000002
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_FS_SYSTEM_FILE     0x00000004
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_FLAG_TXF_SYSTEM_FILE    0x00000008

#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_MASK          0xff000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_DATA          0x01000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_INDEX         0x02000000
#define LOOKUP_STREAM_FROM_CLUSTER_ENTRY_ATTRIBUTE_SYSTEM        0x03000000

typedef struct _LOOKUP_STREAM_FROM_CLUSTER_ENTRY {
    ULONG         OffsetToNext;
    ULONG         Flags;
    LARGE_INTEGER Reserved;
    LARGE_INTEGER Cluster;
    WCHAR         FileName[1];
} LOOKUP_STREAM_FROM_CLUSTER_ENTRY, *PLOOKUP_STREAM_FROM_CLUSTER_ENTRY;

typedef struct _FILE_TYPE_NOTIFICATION_INPUT {

    ULONG Flags;
    ULONG NumFileTypeIDs;
    GUID FileTypeID[1];

} FILE_TYPE_NOTIFICATION_INPUT, *PFILE_TYPE_NOTIFICATION_INPUT;

#define FILE_TYPE_NOTIFICATION_FLAG_USAGE_BEGIN     0x00000001      //Set when adding the specified usage on the given file
#define FILE_TYPE_NOTIFICATION_FLAG_USAGE_END       0x00000002      //Set when removing the specified usage on the given file

DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_PAGE_FILE,         0x0d0a64a1, 0x38fc, 0x4db8, 0x9f, 0xe7, 0x3f, 0x43, 0x52, 0xcd, 0x7c, 0x5c );
DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_HIBERNATION_FILE,  0xb7624d64, 0xb9a3, 0x4cf8, 0x80, 0x11, 0x5b, 0x86, 0xc9, 0x40, 0xe7, 0xb7 );
DEFINE_GUID( FILE_TYPE_NOTIFICATION_GUID_CRASHDUMP_FILE,    0x9d453eb7, 0xd2a6, 0x4dbd, 0xa2, 0xe3, 0xfb, 0xd0, 0xed, 0x91, 0x09, 0xa9 );
#endif /* _WIN32_WINNT >= 0x0601 */

#endif // _FILESYSTEMFSCTL_

// 21.12.2011 - end

// 09.06.2011 - end

typedef enum _SYSDBG_COMMAND
{
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
	SysDbgRegisterForUmBreakInfo,
	SysDbgGetUmBreakPid,
	SysDbgClearUmBreakPid,
	SysDbgGetUmAttachPid,
	SysDbgClearUmAttachPid
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _SYSDBG_VIRTUAL
{
	PVOID Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef struct _SYSDBG_PHYSICAL
{
	PHYSICAL_ADDRESS Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_PHYSICAL, *PSYSDBG_PHYSICAL;

typedef struct _SYSDBG_CONTROL_SPACE
{
	ULONG64 Address;
	PVOID Buffer;
	ULONG Request;
	ULONG Processor;
} SYSDBG_CONTROL_SPACE, *PSYSDBG_CONTROL_SPACE;

typedef enum _INTERFACE_TYPE
{
	UnknownInterfaceType = 1
} INTERFACE_TYPE ;

typedef struct _SYSDBG_IO_SPACE
{
	ULONG64 Address;
	PVOID Buffer;
	ULONG Request;
	enum _INTERFACE_TYPE InterfaceType;
	ULONG BusNumber;
	ULONG AddressSpace;
} SYSDBG_IO_SPACE, *PSYSDBG_IO_SPACE;

typedef struct _SYSDBG_MSR
{
	ULONG Msr;
	ULONG64 Data;
} SYSDBG_MSR, *PSYSDBG_MSR;

typedef enum _BUS_DATA_TYPE
{
    ConfigurationSpaceUndefined = -1,
    Cmos,
    EisaConfiguration,
    Pos,
    CbusConfiguration,
    PCIConfiguration,
    VMEConfiguration,
    NuBusConfiguration,
    PCMCIAConfiguration,
    MPIConfiguration,
    MPSAConfiguration,
    PNPISAConfiguration,
    SgiInternalConfiguration,
    MaximumBusDataType
} BUS_DATA_TYPE, *PBUS_DATA_TYPE;

typedef struct _SYSDBG_BUS_DATA
{
	ULONG Address;
	PVOID Buffer;
	ULONG Request;
	enum _BUS_DATA_TYPE BusDataType;
	ULONG BusNumber;
	ULONG SlotNumber;
} SYSDBG_BUS_DATA, *PSYSDBG_BUS_DATA;

typedef struct _SYSDBG_TRIAGE_DUMP
{
	ULONG Flags;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParam1;
	ULONG_PTR BugCheckParam2;
	ULONG_PTR BugCheckParam3;
	ULONG_PTR BugCheckParam4;
	ULONG ProcessHandles;
	ULONG ThreadHandles;
	PHANDLE Handles;
} SYSDBG_TRIAGE_DUMP, *PSYSDBG_TRIAGE_DUMP;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,				// WOW64
	SystemEmulationProcessorInformation,		// WOW64
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPatchInformation,
	SystemVerifierFaultsInformation,
	SystemSystemPartitionInformation,
	SystemSystemDiskInformation,
	SystemProcessorPerformanceDistribution,
	SystemNumaProximityNodeInformation,
	SystemDynamicTimeZoneInformation,
	SystemCodeIntegrityInformation,
	SystemProcessorMicrocodeUpdateInformation,
	SystemProcessorBrandString,
	SystemVirtualAddressInformation,
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
	EventTraceKernelVersionInformation,
	EventTraceGroupMaskInformation,
	EventTracePerformanceInformation,
	EventTraceTimeProfileInformation,
	EventTraceSessionSecurityInformation,
	MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS, *PEVENT_TRACE_INFORMATION_CLASS;

#define LOCK_QUEUE_WAIT 1
#define LOCK_QUEUE_WAIT_BIT 0

#define LOCK_QUEUE_OWNER 2
#define LOCK_QUEUE_OWNER_BIT 1

#define LOCK_QUEUE_TIMER_LOCK_SHIFT 4
#define LOCK_QUEUE_TIMER_TABLE_LOCKS (1 << (8 - LOCK_QUEUE_TIMER_LOCK_SHIFT))

typedef enum _KSPIN_LOCK_QUEUE_NUMBER {
	LockQueueDispatcherLock,
	LockQueueUnusedSpare1,
	LockQueuePfnLock,
	LockQueueSystemSpaceLock,
	LockQueueVacbLock,
	LockQueueMasterLock,
	LockQueueNonPagedPoolLock,
	LockQueueIoCancelLock,
	LockQueueWorkQueueLock,
	LockQueueIoVpbLock,
	LockQueueIoDatabaseLock,
	LockQueueIoCompletionLock,
	LockQueueNtfsStructLock,
	LockQueueAfdWorkQueueLock,
	LockQueueBcbLock,
	LockQueueMmNonPagedPoolLock,
	LockQueueUnusedSpare16,
	LockQueueTimerTableLock,
	LockQueueMaximumLock = LockQueueTimerTableLock + LOCK_QUEUE_TIMER_TABLE_LOCKS
} KSPIN_LOCK_QUEUE_NUMBER, *PKSPIN_LOCK_QUEUE_NUMBER;

typedef enum _KPROFILE_SOURCE {
	ProfileTime,
	ProfileAlignmentFixup,
	ProfileTotalIssues,
	ProfilePipelineDry,
	ProfileLoadInstructions,
	ProfilePipelineFrozen,
	ProfileBranchInstructions,
	ProfileTotalNonissues,
	ProfileDcacheMisses,
	ProfileIcacheMisses,
	ProfileCacheMisses,
	ProfileBranchMispredictions,
	ProfileStoreInstructions,
	ProfileFpInstructions,
	ProfileIntegerInstructions,
	Profile2Issue,
	Profile3Issue,
	Profile4Issue,
	ProfileSpecialInstructions,
	ProfileTotalCycles,
	ProfileIcacheIssues,
	ProfileDcacheAccesses,
	ProfileMemoryBarrierCycles,
	ProfileLoadLinkedIssues,
	ProfileMaximum
} KPROFILE_SOURCE;

typedef enum _PROCESSINFOCLASS
{
  ProcessBasicInformation,
  ProcessQuotaLimits,
  ProcessIoCounters,
  ProcessVmCounters,
  ProcessTimes,
  ProcessBasePriority,
  ProcessRaisePriority,
  ProcessDebugPort,
  ProcessExceptionPort,
  ProcessAccessToken,
  ProcessLdtInformation,
  ProcessLdtSize,
  ProcessDefaultHardErrorMode,
  ProcessIoPortHandlers,
  ProcessPooledUsageAndLimits,
  ProcessWorkingSetWatch,
  ProcessUserModeIOPL,
  ProcessEnableAlignmentFaultFixup,
  ProcessPriorityClass,
  ProcessWx86Information,
  ProcessHandleCount,
  ProcessAffinityMask,
  ProcessPriorityBoost,
  ProcessDeviceMap,
  ProcessSessionInformation,
  ProcessForegroundInformation,
  ProcessWow64Information,
  ProcessImageFileName,
  ProcessLUIDDeviceMapsEnabled,
  ProcessBreakOnTermination,
  ProcessDebugObjectHandle,
  ProcessDebugFlags,
  ProcessHandleTracing,
  ProcessIoPriority,
  ProcessExecuteFlags,
  ProcessTlsInformation,
  ProcessCookie,
  ProcessImageInformation,
  ProcessCycleTime,
  ProcessPagePriority,
  ProcessInstrumentationCallback,
  ProcessThreadStackAllocation,
  ProcessWorkingSetWatchEx,
  ProcessImageFileNameWin32,
  ProcessImageFileMapping,
  ProcessAffinityUpdateMode,
  ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
  MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,          // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,      // UMS
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	MaxThreadInfoClass
} THREADINFOCLASS;


typedef enum _PROCESS_TLS_INFORMATION_TYPE
{
  ProcessTlsReplaceIndex,
  ProcessTlsReplaceVector,
  MaxProcessTlsOperation
} PROCESS_TLS_INFORMATION_TYPE;


#define PROCESS_TERMINATE         (0x0001)  
#define PROCESS_CREATE_THREAD     (0x0002)  
#define PROCESS_SET_SESSIONID     (0x0004)  
#define PROCESS_VM_OPERATION      (0x0008)  
#define PROCESS_VM_READ           (0x0010)  
#define PROCESS_VM_WRITE          (0x0020)
#define PROCESS_DUP_HANDLE        (0x0040)
#define PROCESS_CREATE_PROCESS    (0x0080)  
#define PROCESS_SET_QUOTA         (0x0100)  
#define PROCESS_SET_INFORMATION   (0x0200)  
#define PROCESS_QUERY_INFORMATION (0x0400)  
#define PROCESS_SET_PORT          (0x0800)
#define PROCESS_SUSPEND_RESUME    (0x0800)  

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ZwCurrentProcess() NtCurrentProcess()
#define ZwCurrentThread()	 NtCurrentThread()

// 28.05.2011 - rndbit
#define NtLastError() ( NtCurrentTeb()->LastErrorValue )
#define NtLastStatus()	( NtCurrentTeb()->LastStatusValue )

#if defined(_M_X86)
#define NtCurrentPID() __readfsdword(0x20)
#else
#define NtCurrentPID() __readgsqword(0x20)
#endif

#define THREAD_TERMINATE               (0x0001)  
#define THREAD_SUSPEND_RESUME          (0x0002)  
#define THREAD_ALERT                   (0x0004)
#define THREAD_GET_CONTEXT             (0x0008)  
#define THREAD_SET_CONTEXT             (0x0010)  
#define THREAD_SET_INFORMATION         (0x0020)  
#define THREAD_QUERY_INFORMATION       (0x0040)  
#define THREAD_SET_THREAD_TOKEN        (0x0080)
#define THREAD_IMPERSONATE             (0x0100)
#define THREAD_DIRECT_IMPERSONATION    (0x0200)

#define JOB_OBJECT_ASSIGN_PROCESS						(0x0001)
#define JOB_OBJECT_SET_ATTRIBUTES						(0x0002)
#define JOB_OBJECT_QUERY										(0x0004)
#define JOB_OBJECT_TERMINATE								(0x0008)
#define JOB_OBJECT_SET_SECURITY_ATTRIBUTES  (0x0010)
#ifndef _WINNT_
#define JOB_OBJECT_ALL_ACCESS								(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1F )
#endif

#define PEB_STDIO_HANDLE_NATIVE     0
#define PEB_STDIO_HANDLE_SUBSYS     1
#define PEB_STDIO_HANDLE_PM         2
#define PEB_STDIO_HANDLE_RESERVED   3

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

#define FOREGROUND_BASE_PRIORITY  9
#define NORMAL_BASE_PRIORITY      8

#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS ( 0x0001 )
#endif

typedef enum _FILE_INFORMATION_CLASS
{
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation,
  FileBothDirectoryInformation,
  FileBasicInformation,
  FileStandardInformation,
  FileInternalInformation,
  FileEaInformation,
  FileAccessInformation,
  FileNameInformation,
  FileRenameInformation,
  FileLinkInformation,
  FileNamesInformation,
  FileDispositionInformation,
  FilePositionInformation,
  FileFullEaInformation,
  FileModeInformation,
  FileAlignmentInformation,
  FileAllInformation,
  FileAllocationInformation,
  FileEndOfFileInformation,
  FileAlternateNameInformation,
  FileStreamInformation,
  FilePipeInformation,
  FilePipeLocalInformation,
  FilePipeRemoteInformation,
  FileMailslotQueryInformation,
  FileMailslotSetInformation,
  FileCompressionInformation,
  FileObjectIdInformation,
  FileCompletionInformation,
  FileMoveClusterInformation,
  FileQuotaInformation,
  FileReparsePointInformation,
  FileNetworkOpenInformation,
  FileAttributeTagInformation,
  FileTrackingInformation,
  FileIdBothDirectoryInformation,
  FileIdFullDirectoryInformation,
  FileValidDataLengthInformation,
  FileShortNameInformation,
  FileIoCompletionNotificationInformation,
  FileIoStatusBlockRangeInformation,
  FileIoPriorityHintInformation,
  FileSfioReserveInformation,
  FileSfioVolumeInformation,
  FileHardLinkInformation,
  FileProcessIdsUsingFileInformation,
  FileNormalizedNameInformation,
  FileNetworkPhysicalNameInformation,
  FileIdGlobalTxDirectoryInformation,
  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _FSINFOCLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsVolumeFlagsInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE, *PPOOL_TYPE;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _REG_NOTIFY_CLASS
{
  RegNtDeleteKey,
  RegNtPreDeleteKey,
  RegNtSetValueKey,
  RegNtPreSetValueKey,
  RegNtDeleteValueKey,
  RegNtPreDeleteValueKey,
  RegNtSetInformationKey,
  RegNtPreSetInformationKey,
  RegNtRenameKey,
  RegNtPreRenameKey,
  RegNtEnumerateKey,
  RegNtPreEnumerateKey,
  RegNtEnumerateValueKey,
  RegNtPreEnumerateValueKey,
  RegNtQueryKey,
  RegNtPreQueryKey,
  RegNtQueryValueKey,
  RegNtPreQueryValueKey,
  RegNtQueryMultipleValueKey,
  RegNtPreQueryMultipleValueKey,
  RegNtPreCreateKey,
  RegNtPostCreateKey,
  RegNtPreOpenKey,
  RegNtPostOpenKey,
  RegNtKeyHandleClose,
  RegNtPreKeyHandleClose,
  RegNtPostDeleteKey,
  RegNtPostSetValueKey,
  RegNtPostDeleteValueKey,
  RegNtPostSetInformationKey,
  RegNtPostRenameKey,
  RegNtPostEnumerateKey,
  RegNtPostEnumerateValueKey,
  RegNtPostQueryKey,
  RegNtPostQueryValueKey,
  RegNtPostQueryMultipleValueKey,
  RegNtPostKeyHandleClose,
  RegNtPreCreateKeyEx,
  RegNtPostCreateKeyEx,
  RegNtPreOpenKeyEx,
  RegNtPostOpenKeyEx,
  RegNtPreFlushKey,
  RegNtPostFlushKey,
  RegNtPreLoadKey,
  RegNtPostLoadKey,
  RegNtPreUnLoadKey,
  RegNtPostUnLoadKey,
  RegNtPreQueryKeySecurity,
  RegNtPostQueryKeySecurity,
  RegNtPreSetKeySecurity,
  RegNtPostSetKeySecurity,
  RegNtCallbackObjectContextCleanup,
  MaxRegNtNotifyClass
} REG_NOTIFY_CLASS, *PREG_NOTIFY_CLASS;

typedef enum _HAL_QUERY_INFORMATION_CLASS
{
  HalInstalledBusInformation,
  HalProfileSourceInformation,
  HalInformationClassUnused1,
  HalPowerInformation,
  HalProcessorSpeedInformation,
  HalCallbackInformation,
  HalMapRegisterInformation,
  HalMcaLogInformation,
  HalFrameBufferCachingInformation,
  HalDisplayBiosInformation,
  HalProcessorFeatureInformation,
  HalNumaTopologyInterface,
  HalErrorInformation,
  HalCmcLogInformation,
  HalCpeLogInformation,
  HalQueryMcaInterface,
  HalQueryAMLIIllegalIOPortAddresses,
  HalQueryMaxHotPlugMemoryAddress,
  HalPartitionIpiInterface,
  HalPlatformInformation,
  HalQueryProfileSourceList,
  HalInitLogInformation,
  HalFrequencyInformation,
  HalProcessorBrandString
} HAL_QUERY_INFORMATION_CLASS, *PHAL_QUERY_INFORMATION_CLASS;


#if defined(_WINNT_) && (_MSC_VER < 1300) && !defined(_WINDOWS_)
typedef enum POWER_INFORMATION_LEVEL {
  SystemPowerPolicyAc = 0x0,
  SystemPowerPolicyDc = 0x1,
  VerifySystemPolicyAc = 0x2,
  VerifySystemPolicyDc = 0x3,
  SystemPowerCapabilities = 0x4,
  SystemBatteryState = 0x5,
  SystemPowerStateHandler = 0x6,
  ProcessorStateHandler = 0x7,
  SystemPowerPolicyCurrent = 0x8,
  AdministratorPowerPolicy = 0x9,
  SystemReserveHiberFile = 0xa,
  ProcessorInformation = 0xb,
  SystemPowerInformation = 0xc,
  ProcessorStateHandler2 = 0xd,
  LastWakeTime = 0xe,
  LastSleepTime = 0xf,
  SystemExecutionState = 0x10,
  SystemPowerStateNotifyHandler = 0x11,
  ProcessorPowerPolicyAc = 0x12,
  ProcessorPowerPolicyDc = 0x13,
  VerifyProcessorPowerPolicyAc = 0x14,
  VerifyProcessorPowerPolicyDc = 0x15,
  ProcessorPowerPolicyCurrent = 0x16,
  SystemPowerStateLogging = 0x17,
  SystemPowerLoggingEntry = 0x18,
  SetPowerSettingValue = 0x19,
  NotifyUserPowerSetting = 0x1a,
  GetPowerTransitionVetoes = 0x1b,
  SetPowerTransitionVeto = 0x1c,
  SystemVideoState = 0x1d,
  TraceApplicationPowerMessage = 0x1e,
  TraceApplicationPowerMessageEnd = 0x1f,
  ProcessorPerfStates = 0x20,
  ProcessorIdleStates = 0x21,
  ProcessorThrottleStates = 0x22,
  SystemWakeSource = 0x23,
  SystemHiberFileInformation = 0x24,
  TraceServicePowerMessage = 0x25,
  ProcessorLoad = 0x26,
  PowerShutdownNotification = 0x27,
  MonitorCapabilities = 0x28
};
#endif

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI *PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);

typedef struct _X86_FLOATING_SAVE_AREA
{
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[ 80 ];
	ULONG Cr0NpxState;
} X86_FLOATING_SAVE_AREA, *PX86_FLOATING_SAVE_AREA;

typedef struct _X86_CONTEXT
{
	ULONG ContextFlags;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	X86_FLOATING_SAVE_AREA FloatSave;
	ULONG SegGs;
	ULONG SegFs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Ebp;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG Esp;
	ULONG SegSs;
} X86_CONTEXT, *PX86_CONTEXT;

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000


#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036

#define WIN32_CLIENT_INFO_LENGTH 62

#define PIO_APC_ROUTINE_DEFINED

typedef struct _PORT_VIEW {
	ULONG Length;
	LPC_HANDLE SectionHandle;
	ULONG SectionOffset;
	LPC_SIZE_T ViewSize;
	LPC_PVOID ViewBase;
	LPC_PVOID ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW {
	ULONG Length;
	LPC_SIZE_T ViewSize;
	LPC_PVOID ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

#define IO_COMPLETION_QUERY_STATE   0x0001
#define IO_COMPLETION_MODIFY_STATE  0x0002  
#define IO_COMPLETION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 

typedef enum _IO_COMPLETION_INFORMATION_CLASS {
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

typedef enum _PORT_INFORMATION_CLASS {
	PortBasicInformation
} PORT_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

//added 21/03/2011
typedef struct _MEMORY_WORKING_SET_BLOCK
{
	ULONG_PTR Protection : 5;
	ULONG_PTR ShareCount : 3;
	ULONG_PTR Shared : 1;
	ULONG_PTR Node : 3;
#if defined(_M_X64)
	ULONG_PTR VirtualPage : 52;
#else
	ULONG VirtualPage : 20;
#endif
} MEMORY_WORKING_SET_BLOCK, *PMEMORY_WORKING_SET_BLOCK;

typedef struct _MEMORY_WORKING_SET_INFORMATION
{
	ULONG_PTR NumberOfEntries;
	MEMORY_WORKING_SET_BLOCK WorkingSetInfo[1];
} MEMORY_WORKING_SET_INFORMATION, *PMEMORY_WORKING_SET_INFORMATION;

typedef struct _MEMORY_WORKING_SET_EX_BLOCK
{
	ULONG_PTR Valid : 1;
	ULONG_PTR ShareCount : 3;
	ULONG_PTR Win32Protection : 11;
	ULONG_PTR Shared : 1;
	ULONG_PTR Node : 6;
	ULONG_PTR Locked : 1;
	ULONG_PTR LargePage : 1;
	ULONG_PTR Priority : 3;
	ULONG_PTR Reserved : 5;

#if defined(_M_X64)
	ULONG_PTR ReservedUlong : 32;
#endif
} MEMORY_WORKING_SET_EX_BLOCK, *PMEMORY_WORKING_SET_EX_BLOCK;

typedef struct _MEMORY_REGION_INFORMATION
{
	PVOID AllocationBase;
	ULONG AllocationProtect;
	ULONG RegionType;
	SIZE_T RegionSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;

typedef struct _MEMORY_WORKING_SET_EX_INFORMATION
{
	PVOID VirtualAddress;
	union
	{
		MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
		ULONG Long;
	};
} MEMORY_WORKING_SET_EX_INFORMATION, *PMEMORY_WORKING_SET_EX_INFORMATION;

typedef
VOID
(*PTIMER_APC_ROUTINE) (
    IN PVOID TimerContext,
    IN ULONG TimerLowValue,
    IN LONG TimerHighValue
    );

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS;

typedef struct _ATOM_BASIC_INFORMATION
{
	USHORT UsageCount;
	USHORT Flags;
	USHORT NameLength;
	WCHAR Name[1];
} ATOM_BASIC_INFORMATION, *PATOM_BASIC_INFORMATION;

typedef struct _ATOM_TABLE_INFORMATION
{
	ULONG NumberOfAtoms;
	RTL_ATOM Atoms[1];
} ATOM_TABLE_INFORMATION, *PATOM_TABLE_INFORMATION;

#define SEMAPHORE_QUERY_STATE       0x0001
#define SEMAPHORE_MODIFY_STATE      0x0002

#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

typedef enum _SEMAPHORE_INFORMATION_CLASS {
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef struct _SEMAPHORE_BASIC_INFORMATION {
	LONG CurrentCount;
	LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION, *PSEMAPHORE_BASIC_INFORMATION;

#define MUTANT_QUERY_STATE      0x0001

#define MUTANT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|\
	MUTANT_QUERY_STATE)

typedef enum _MUTANT_INFORMATION_CLASS {
	MutantBasicInformation
} MUTANT_INFORMATION_CLASS;

typedef struct _MUTANT_BASIC_INFORMATION {
	LONG CurrentCount;
	BOOLEAN OwnedByCaller;
	BOOLEAN AbandonedState;
} MUTANT_BASIC_INFORMATION, *PMUTANT_BASIC_INFORMATION;

#define TIMER_QUERY_STATE       0x0001
#define TIMER_MODIFY_STATE      0x0002

#define TIMER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|\
	TIMER_QUERY_STATE|TIMER_MODIFY_STATE)
typedef enum _TIMER_INFORMATION_CLASS {
	TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef struct _TIMER_BASIC_INFORMATION {
	LARGE_INTEGER RemainingTime;
	BOOLEAN TimerState;
} TIMER_BASIC_INFORMATION, *PTIMER_BASIC_INFORMATION;

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation,
	MaxSectionInfoClass
} SECTION_INFORMATION_CLASS;

#define OBJ_NAME_PATH_SEPARATOR ((WCHAR)L'\\')
#define OBJ_MAX_REPARSE_ATTEMPTS 32
#define OBJECT_TYPE_CREATE (0x0001)
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[ 3 ];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
	ULONG NumberOfTypes;
	OBJECT_TYPE_INFORMATION TypeInformation;
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

typedef enum _PLUGPLAY_EVENT_CATEGORY {
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE {
	PNP_VetoTypeUnknown,            // Name is unspecified
	PNP_VetoLegacyDevice,           // Name is an Instance Path
	PNP_VetoPendingClose,           // Name is an Instance Path
	PNP_VetoWindowsApp,             // Name is a Module
	PNP_VetoWindowsService,         // Name is a Service
	PNP_VetoOutstandingOpen,        // Name is an Instance Path
	PNP_VetoDevice,                 // Name is an Instance Path
	PNP_VetoDriver,                 // Name is a Driver Service Name
	PNP_VetoIllegalDeviceRequest,   // Name is an Instance Path
	PNP_VetoInsufficientPower,      // Name is unspecified
	PNP_VetoNonDisableable,         // Name is an Instance Path
	PNP_VetoLegacyDriver,           // Name is a Service
	PNP_VetoInsufficientRights      // Name is unspecified
}   PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _PLUGPLAY_EVENT_BLOCK {
	//
	// Common event data
	//
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union {

		struct {
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;

		struct {
			WCHAR DeviceIds[1];
		} TargetDevice;

		struct {
			WCHAR DeviceId[1];
		} InstallDevice;

		struct {
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;

		struct {
			PVOID Notification;
		} ProfileNotification;

		struct {
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;

		struct {
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<NULL>VetoName<NULL><NULL>
		} VetoNotification;

		struct {
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;

		struct {
			WCHAR ParentId[1];
		} InvalidIDNotification;

	} u;

} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

#define MDL_HASH_TABLE_SIZE 64
#define MDL_HASH_MASK	(MDL_HASH_TABLE_SIZE-1)
#define MDL_HASH_INDEX(wch) ((RtlUpcaseUnicodeChar((wch)) - (WCHAR)'A') & MDL_HASH_MASK)

#if !defined(_WINNT_)
#define HEAP_MAKE_TAG_FLAGS( b, o ) ((ULONG)((b) + ((o) << 18)))
#endif
#define RTL_HEAP_MAKE_TAG HEAP_MAKE_TAG_FLAGS

typedef struct _TIME_FIELDS {
	CSHORT Year;        // range [1601...]
	CSHORT Month;       // range [1..12]
	CSHORT Day;         // range [1..31]
	CSHORT Hour;        // range [0..23]
	CSHORT Minute;      // range [0..59]
	CSHORT Second;      // range [0..59]
	CSHORT Milliseconds;// range [0..999]
	CSHORT Weekday;     // range [0..6] == [Sunday..Saturday]
} TIME_FIELDS;
typedef TIME_FIELDS *PTIME_FIELDS;

typedef struct _RTL_TIME_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[ 32 ];
	TIME_FIELDS StandardStart;
	LONG StandardBias;
	WCHAR DaylightName[ 32 ];
	TIME_FIELDS DaylightStart;
	LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

typedef struct _RTL_BITMAP_RUN {
	ULONG StartingIndex;
	ULONG NumberOfBits;
} RTL_BITMAP_RUN;
typedef RTL_BITMAP_RUN *PRTL_BITMAP_RUN;

typedef struct _PARSE_MESSAGE_CONTEXT {
	ULONG fFlags;
	ULONG cwSavColumn;
	SIZE_T iwSrc;
	SIZE_T iwDst;
	SIZE_T iwDstSpace;
	va_list lpvArgStart;
} PARSE_MESSAGE_CONTEXT, *PPARSE_MESSAGE_CONTEXT;

typedef enum _RTL_RXACT_OPERATION {
	RtlRXactOperationDelete = 1,        // Causes sub-key to be deleted
	RtlRXactOperationSetValue,          // Sets sub-key value (creates key(s) if necessary)
	RtlRXactOperationDelAttribute,
	RtlRXactOperationSetAttribute
} RTL_RXACT_OPERATION, *PRTL_RXACT_OPERATION;

typedef struct _RTL_RXACT_LOG {
	ULONG OperationCount;
	ULONG LogSize;
	ULONG LogSizeInUse;
#if defined(_M_X64)
	ULONG Alignment;
#endif
} RTL_RXACT_LOG, *PRTL_RXACT_LOG;

typedef struct _RTL_RXACT_CONTEXT {
	HANDLE RootRegistryKey;
	HANDLE RXactKey;
	BOOLEAN HandlesValid;
	PRTL_RXACT_LOG RXactLog;
} RTL_RXACT_CONTEXT, *PRTL_RXACT_CONTEXT;

#define MAXIMUM_LEADBYTES   12

typedef struct _CPTABLEINFO {
	USHORT CodePage;                    // code page number
	USHORT MaximumCharacterSize;        // max length (bytes) of a char
	USHORT DefaultChar;                 // default character (MB)
	USHORT UniDefaultChar;              // default character (Unicode)
	USHORT TransDefaultChar;            // translation of default char (Unicode)
	USHORT TransUniDefaultChar;         // translation of Unic default char (MB)
	USHORT DBCSCodePage;                // Non 0 for DBCS code pages
	UCHAR  LeadByte[MAXIMUM_LEADBYTES]; // lead byte ranges
	PUSHORT MultiByteTable;             // pointer to MB translation table
	PVOID   WideCharTable;              // pointer to WC translation table
	PUSHORT DBCSRanges;                 // pointer to DBCS ranges
	PUSHORT DBCSOffsets;                // pointer to DBCS offsets
} CPTABLEINFO, *PCPTABLEINFO;

typedef struct _NLSTABLEINFO {
	CPTABLEINFO OemTableInfo;
	CPTABLEINFO AnsiTableInfo;
	PUSHORT UpperCaseTable;             // 844 format upcase table
	PUSHORT LowerCaseTable;             // 844 format lower case table
} NLSTABLEINFO, *PNLSTABLEINFO;

#define RTL_RANGE_LIST_SHARED_OK           0x00000001
#define RTL_RANGE_LIST_NULL_CONFLICT_OK    0x00000002

typedef struct _RTL_RANGE {
	ULONGLONG Start;    // Read only
	ULONGLONG End;      // Read only
	PVOID UserData;     // Read/Write
	PVOID Owner;        // Read/Write
	UCHAR Attributes;    // Read/Write
	UCHAR Flags;       // Read only
} RTL_RANGE, *PRTL_RANGE;

typedef
	BOOLEAN
	(*PRTL_CONFLICT_RANGE_CALLBACK) (
	IN PVOID Context,
	IN PRTL_RANGE Range
	);

typedef enum _EVENT_INFORMATION_CLASS {
	EventBasicInformation
} EVENT_INFORMATION_CLASS;


typedef enum _PLUGPLAY_CONTROL_CLASS {
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef
VOID
(*PPS_APC_ROUTINE) (
    IN OPTIONAL PVOID ApcArgument1,
    IN OPTIONAL PVOID ApcArgument2,
    IN OPTIONAL PVOID ApcArgument3
    );

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

//
// Value entry query structures
// 14.09.11

typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataOffset;
    ULONG   DataLength;
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable size
//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG   TitleIndex;
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 {
    ULONG   Type;
    ULONG   DataLength;
    UCHAR   Data[1];            // Variable size
} KEY_VALUE_PARTIAL_INFORMATION_ALIGN64, *PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING ValueName;
    ULONG           DataLength;
    ULONG           DataOffset;
    ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

//
// end of value info
//

typedef enum _KEY_SET_INFORMATION_CLASS {
	KeyWriteTimeInformation,
	KeyUserFlagsInformation,
	MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

#define SE_CREATE_TOKEN_NAME								TEXT("SeCreateTokenPrivilege")
#define SE_ASSIGNPRIMARYTOKEN_NAME					TEXT("SeAssignPrimaryTokenPrivilege")
#define SE_LOCK_MEMORY_NAME									TEXT("SeLockMemoryPrivilege")
#define SE_INCREASE_QUOTA_NAME							TEXT("SeIncreaseQuotaPrivilege")
#define SE_UNSOLICITED_INPUT_NAME						TEXT("SeUnsolicitedInputPrivilege")
#define SE_MACHINE_ACCOUNT_NAME							TEXT("SeMachineAccountPrivilege")
#define SE_TCB_NAME													TEXT("SeTcbPrivilege")
#define SE_SECURITY_NAME										TEXT("SeSecurityPrivilege")
#define SE_TAKE_OWNERSHIP_NAME							TEXT("SeTakeOwnershipPrivilege")
#define SE_LOAD_DRIVER_NAME									TEXT("SeLoadDriverPrivilege")
#define SE_SYSTEM_PROFILE_NAME							TEXT("SeSystemProfilePrivilege")
#define SE_SYSTEMTIME_NAME									TEXT("SeSystemtimePrivilege")
#define SE_PROF_SINGLE_PROCESS_NAME					TEXT("SeProfileSingleProcessPrivilege")
#define SE_INC_BASE_PRIORITY_NAME						TEXT("SeIncreaseBasePriorityPrivilege")
#define SE_CREATE_PAGEFILE_NAME							TEXT("SeCreatePagefilePrivilege")
#define SE_CREATE_PERMANENT_NAME						TEXT("SeCreatePermanentPrivilege")
#define SE_BACKUP_NAME											TEXT("SeBackupPrivilege")
#define SE_RESTORE_NAME											TEXT("SeRestorePrivilege")
#define SE_SHUTDOWN_NAME										TEXT("SeShutdownPrivilege")
#define SE_DEBUG_NAME												TEXT("SeDebugPrivilege")
#define SE_AUDIT_NAME												TEXT("SeAuditPrivilege")
#define SE_SYSTEM_ENVIRONMENT_NAME					TEXT("SeSystemEnvironmentPrivilege")
#define SE_CHANGE_NOTIFY_NAME								TEXT("SeChangeNotifyPrivilege")
#define SE_REMOTE_SHUTDOWN_NAME							TEXT("SeRemoteShutdownPrivilege")
#define SE_UNDOCK_NAME											TEXT("SeUndockPrivilege")
#define SE_SYNC_AGENT_NAME									TEXT("SeSyncAgentPrivilege")
#define SE_ENABLE_DELEGATION_NAME						TEXT("SeEnableDelegationPrivilege")
#define SE_MANAGE_VOLUME_NAME								TEXT("SeManageVolumePrivilege")
#define SE_IMPERSONATE_NAME									TEXT("SeImpersonatePrivilege")
// #define SE_CREATE_GLOBAL_PRIVILEGE					TEXT("SeCreateGlobalPrivilege")
// #define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE	TEXT("SeTrustedCredmanAccessPrivilege")
// #define SE_RELABEL_PRIVILEGE								TEXT("SeReLabelPrivilege")
#define SE_CREATE_GLOBAL_NAME								TEXT("SeCreateGlobalPrivilege")

// Privileges

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)

#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _CLIENT_ID32
{
	ULONG UniqueProcess;
	ULONG UniqueThread;
} CLIENT_ID32, *PCLIENT_ID32;

typedef struct _CLIENT_ID64
{
	ULONGLONG UniqueProcess;
	ULONGLONG UniqueThread;
} CLIENT_ID64, *PCLIENT_ID64;

#include <pshpack4.h>

typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

#include <poppack.h>

//
// FILE_INFORMATION
//
//readded 17.09.11 EP_X0FF

typedef struct _FILE_BASIC_INFORMATION {                    // ntddk wdm nthal
	LARGE_INTEGER CreationTime;                             // ntddk wdm nthal
	LARGE_INTEGER LastAccessTime;                           // ntddk wdm nthal
	LARGE_INTEGER LastWriteTime;                            // ntddk wdm nthal
	LARGE_INTEGER ChangeTime;                               // ntddk wdm nthal
	ULONG FileAttributes;                                   // ntddk wdm nthal
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;         // ntddk wdm nthal

typedef struct _FILE_STANDARD_INFORMATION
{
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	UCHAR DeletePending;
	UCHAR Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {                 // ntddk wdm nthal
    LARGE_INTEGER CurrentByteOffset;                        // ntddk wdm nthal
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;   // ntddk wdm nthal
                                                            // ntddk wdm nthal
typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_ALIGNMENT_INFORMATION {                // ntddk nthal
    ULONG AlignmentRequirement;                             // ntddk nthal
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION; // ntddk nthal
                                                            // ntddk nthal
typedef struct _FILE_NAME_INFORMATION {                     // ntddk
    ULONG FileNameLength;                                   // ntddk
    WCHAR FileName[1];                                      // ntddk
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;           // ntddk

typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {                 // ntddk wdm nthal
    LARGE_INTEGER CreationTime;                                 // ntddk wdm nthal
    LARGE_INTEGER LastAccessTime;                               // ntddk wdm nthal
    LARGE_INTEGER LastWriteTime;                                // ntddk wdm nthal
    LARGE_INTEGER ChangeTime;                                   // ntddk wdm nthal
    LARGE_INTEGER AllocationSize;                               // ntddk wdm nthal
    LARGE_INTEGER EndOfFile;                                    // ntddk wdm nthal
    ULONG FileAttributes;                                       // ntddk wdm nthal
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;   // ntddk wdm nthal
                                                                // ntddk wdm nthal
typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {               // ntddk nthal
    ULONG FileAttributes;                                       // ntddk nthal
    ULONG ReparseTag;                                           // ntddk nthal
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;  // ntddk nthal
                                                                // ntddk nthal
typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;

typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {                  // ntddk nthal
    BOOLEAN DeleteFile;                                         // ntddk nthal
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION; // ntddk nthal
                                                                // ntddk nthal
typedef struct _FILE_END_OF_FILE_INFORMATION {                  // ntddk nthal
    LARGE_INTEGER EndOfFile;                                    // ntddk nthal
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION; // ntddk nthal
                                                                // ntddk nthal
typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {                                    // ntddk nthal
    LARGE_INTEGER ValidDataLength;                                                      // ntddk nthal
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;             // ntddk nthal

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

typedef struct _FILE_MOVE_CLUSTER_INFORMATION {
    ULONG ClusterCount;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, *PFILE_MOVE_CLUSTER_INFORMATION;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_STREAM_INFORMATION {
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_TRACKING_INFORMATION {
    HANDLE DestinationFile;
    ULONG ObjectInformationLength;
    CHAR ObjectInformation[1];
} FILE_TRACKING_INFORMATION, *PFILE_TRACKING_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;

typedef struct _FILE_PIPE_INFORMATION {
     ULONG ReadMode;
     ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION {
     ULONG NamedPipeType;
     ULONG NamedPipeConfiguration;
     ULONG MaximumInstances;
     ULONG CurrentInstances;
     ULONG InboundQuota;
     ULONG ReadDataAvailable;
     ULONG OutboundQuota;
     ULONG WriteQuotaAvailable;
     ULONG NamedPipeState;
     ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;

typedef struct _FILE_PIPE_REMOTE_INFORMATION {
     LARGE_INTEGER CollectDataTime;
     ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;

typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
    ULONG MaximumMessageSize;
    ULONG MailslotQuota;
    ULONG NextMessageSize;
    ULONG MessagesAvailable;
    LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_MAILSLOT_SET_INFORMATION {
    PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;

typedef struct _FILE_REPARSE_POINT_INFORMATION {
    LONGLONG FileReference;
    ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;

//
// NtQuery(Set)EaFile
//
// The offset for the start of EaValue is EaName[EaNameLength + 1]
//

// begin_ntddk begin_wdm

typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

// end_ntddk end_wdm

typedef struct _FILE_GET_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

//
// NtQuery(Set)QuotaInformationFile
//

typedef struct _FILE_GET_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID Sid;
} FILE_GET_QUOTA_INFORMATION, *PFILE_GET_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;

//
// NtQueryDirectoryFile return types:
//
//      FILE_DIRECTORY_INFORMATION
//      FILE_FULL_DIR_INFORMATION
//      FILE_ID_FULL_DIR_INFORMATION
//      FILE_BOTH_DIR_INFORMATION
//      FILE_ID_BOTH_DIR_INFORMATION
//      FILE_NAMES_INFORMATION
//      FILE_OBJECTID_INFORMATION
//

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_OBJECTID_INFORMATION {
    LONGLONG FileReference;
    UCHAR ObjectId[16];
    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        } ;
        UCHAR ExtendedInfo[48];
    };
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;


//
// SYSTEM_INFORMATION
//

typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
	UNICODE_STRING DriverName;
	PVOID ImageAddress;
	PVOID SectionPointer;
	PVOID EntryPoint;
	PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
	ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
	ULONG AlignmentFixupCount;
	ULONG ExceptionDispatchCount;
	ULONG FloatingEmulationCount;
	ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

//
// taken from http://www.acc.umu.se/~bosse/ntifs.h - contents are questionable.
//

typedef enum _THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;

//FIXED 21.02.2011 size for x64/x86
typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   CreateTime;
	ULONG           WaitTime;
	PVOID           StartAddress;
	CLIENT_ID       ClientId;
	KPRIORITY       Priority;
	KPRIORITY       BasePriority;
	ULONG           ContextSwitchCount;
	THREAD_STATE    State;
	KWAIT_REASON    WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	ULONG_PTR Reserved1;
	ULONG_PTR Reserved2;
	ULONG_PTR Reserved3;
	ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_POOL_ENTRY {
	BOOLEAN Allocated;
	BOOLEAN Spare0;
	USHORT AllocatorBackTraceIndex;
	ULONG Size;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
		PVOID ProcessChargedQuota;
	};
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION {
	SIZE_T TotalSize;
	PVOID FirstEntry;
	USHORT EntryOverhead;
	BOOLEAN PoolTagPresent;
	BOOLEAN Spare0;
	ULONG NumberOfEntries;
	SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

typedef struct _SYSTEM_POOLTAG {
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	SIZE_T PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;     // Set to 1 if entry is nonpaged.
	};
	SIZE_T SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_POOLTAG_INFORMATION
{
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[ 1 ];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION {
	SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[ 1 ];
} SYSTEM_SESSION_POOLTAG_INFORMATION, *PSYSTEM_SESSION_POOLTAG_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ 1 ];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG UniqueProcessId;
	ULONG HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_SPECIAL_POOL_INFORMATION
{
	ULONG PoolTag;
	ULONG Flags;
} SYSTEM_SPECIAL_POOL_INFORMATION, *PSYSTEM_SPECIAL_POOL_INFORMATION;

typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfObjects;
	ULONG NumberOfHandles;
	ULONG TypeIndex;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG PoolType;
	UCHAR SecurityRequired;
	UCHAR WaitableObject;
	UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_HIBERFILE_INFORMATION
{
	ULONG NumberOfMcbPairs;
	LARGE_INTEGER Mcb[ 1 ];
} SYSTEM_HIBERFILE_INFORMATION, *PSYSTEM_HIBERFILE_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG  RegistryQuotaAllowed;
	ULONG  RegistryQuotaUsed;
	SIZE_T PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION {
	ULONG ContextSwitches;
	ULONG FindAny;
	ULONG FindLast;
	ULONG FindIdeal;
	ULONG IdleAny;
	ULONG IdleCurrent;
	ULONG IdleLast;
	ULONG IdleIdeal;
	ULONG PreemptAny;
	ULONG PreemptCurrent;
	ULONG PreemptLast;
	ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION {
	SIZE_T NextEntryOffset;
	ULONG SessionId;
	ULONG ViewFailures;
	SIZE_T NumberOfBytesAvailable;
	SIZE_T NumberOfBytesAvailableContiguous;
} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, *PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION {
	ULONG ContextSwitches;
	ULONG DpcCount;
	ULONG DpcRate;
	ULONG TimeIncrement;
	ULONG DpcBypassCount;
	ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION {
	ULONG Spare;
	ULONG DpcQueueDepth;
	ULONG MinimumDpcRate;
	ULONG AdjustDpcThreshold;
	ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION {
	USHORT CurrentDepth;
	USHORT MaximumDepth;
	ULONG TotalAllocates;
	ULONG AllocateMisses;
	ULONG TotalFrees;
	ULONG FreeMisses;
	ULONG Type;
	ULONG Tag;
	ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION {
	ULONG VetoType;
	UNICODE_STRING VetoList;
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
	ULONG SegmentNotPresent;
	ULONG VdmOpcode0F;
	ULONG OpcodeESPrefix;
	ULONG OpcodeCSPrefix;
	ULONG OpcodeSSPrefix;
	ULONG OpcodeDSPrefix;
	ULONG OpcodeFSPrefix;
	ULONG OpcodeGSPrefix;
	ULONG OpcodeOPER32Prefix;
	ULONG OpcodeADDR32Prefix;
	ULONG OpcodeINSB;
	ULONG OpcodeINSW;
	ULONG OpcodeOUTSB;
	ULONG OpcodeOUTSW;
	ULONG OpcodePUSHF;
	ULONG OpcodePOPF;
	ULONG OpcodeINTnn;
	ULONG OpcodeINTO;
	ULONG OpcodeIRET;
	ULONG OpcodeINBimm;
	ULONG OpcodeINWimm;
	ULONG OpcodeOUTBimm;
	ULONG OpcodeOUTWimm;
	ULONG OpcodeINB;
	ULONG OpcodeINW;
	ULONG OpcodeOUTB;
	ULONG OpcodeOUTW;
	ULONG OpcodeLOCKPrefix;
	ULONG OpcodeREPNEPrefix;
	ULONG OpcodeREPPrefix;
	ULONG OpcodeHLT;
	ULONG OpcodeCLI;
	ULONG OpcodeSTI;
	ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

#if defined(_M_X64)
typedef ULONG SYSINF_PAGE_COUNT;
#else
typedef SIZE_T SYSINF_PAGE_COUNT;
#endif

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	SYSINF_PAGE_COUNT NumberOfPhysicalPages;
	SYSINF_PAGE_COUNT LowestPhysicalPageNumber;
	SYSINF_PAGE_COUNT HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_INFORMATION {
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;          // Checked Build
	LARGE_INTEGER InterruptTime;    // Checked Build
	ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION {
	ULONGLONG IdleTime;
	ULONGLONG C1Time;
	ULONGLONG C2Time;
	ULONGLONG C3Time;
	ULONG     C1Transitions;
	ULONG     C2Transitions;
	ULONG     C3Transitions;
	ULONG     Padding;
} SYSTEM_PROCESSOR_IDLE_INFORMATION, *PSYSTEM_PROCESSOR_IDLE_INFORMATION;

typedef struct _SYSTEM_NUMA_INFORMATION {
	ULONG HighestNodeNumber;
	ULONG Reserved;
	union {
		ULONG64 ActiveProcessorsAffinityMask[ 16 ];
		ULONG64 AvailableMemory[ 16 ];
	};
} SYSTEM_NUMA_INFORMATION, *PSYSTEM_NUMA_INFORMATION;

#if !defined(_WINNT_)

typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
{
	RelationProcessorCore,
	RelationNumaNode,
	RelationCache,
	RelationProcessorPackage
} LOGICAL_PROCESSOR_RELATIONSHIP;

typedef enum _PROCESSOR_CACHE_TYPE
{
	CacheUnified,
	CacheInstruction,
	CacheData,
	CacheTrace
} PROCESSOR_CACHE_TYPE;

#define CACHE_FULLY_ASSOCIATIVE 0xFF

typedef struct _CACHE_DESCRIPTOR
{
	BYTE   Level;
	BYTE   Associativity;
	WORD   LineSize;
	DWORD  Size;
	PROCESSOR_CACHE_TYPE Type;
} CACHE_DESCRIPTOR, *PCACHE_DESCRIPTOR;

typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
	ULONG_PTR   ProcessorMask;
	LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
	union {
		struct {
			BYTE  Flags;
		} ProcessorCore;
		struct {
			DWORD NodeNumber;
		} NumaNode;
		CACHE_DESCRIPTOR Cache;
		ULONGLONG  Reserved[2];
	};
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

#define PROCESSOR_INTEL_386     386
#define PROCESSOR_INTEL_486     486
#define PROCESSOR_INTEL_PENTIUM 586
#define PROCESSOR_INTEL_IA64    2200
#define PROCESSOR_AMD_X8664     8664
#define PROCESSOR_MIPS_R4000    4000    // incl R4101 & R3910 for Windows CE
#define PROCESSOR_ALPHA_21064   21064
#define PROCESSOR_PPC_601       601
#define PROCESSOR_PPC_603       603
#define PROCESSOR_PPC_604       604
#define PROCESSOR_PPC_620       620
#define PROCESSOR_HITACHI_SH3   10003   // Windows CE
#define PROCESSOR_HITACHI_SH3E  10004   // Windows CE
#define PROCESSOR_HITACHI_SH4   10005   // Windows CE
#define PROCESSOR_MOTOROLA_821  821     // Windows CE
#define PROCESSOR_SHx_SH3       103     // Windows CE
#define PROCESSOR_SHx_SH4       104     // Windows CE
#define PROCESSOR_STRONGARM     2577    // Windows CE - 0xA11
#define PROCESSOR_ARM720        1824    // Windows CE - 0x720
#define PROCESSOR_ARM820        2080    // Windows CE - 0x820
#define PROCESSOR_ARM920        2336    // Windows CE - 0x920
#define PROCESSOR_ARM_7TDMI     70001   // Windows CE
#define PROCESSOR_OPTIL         0x494f  // MSIL

#define PROCESSOR_ARCHITECTURE_INTEL            0
#define PROCESSOR_ARCHITECTURE_MIPS             1
#define PROCESSOR_ARCHITECTURE_ALPHA            2
#define PROCESSOR_ARCHITECTURE_PPC              3
#define PROCESSOR_ARCHITECTURE_SHX              4
#define PROCESSOR_ARCHITECTURE_ARM              5
#define PROCESSOR_ARCHITECTURE_IA64             6
#define PROCESSOR_ARCHITECTURE_ALPHA64          7
#define PROCESSOR_ARCHITECTURE_MSIL             8
#define PROCESSOR_ARCHITECTURE_AMD64            9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64    10

#define PROCESSOR_ARCHITECTURE_UNKNOWN 0xFFFF

#define PF_FLOATING_POINT_PRECISION_ERRATA  0   
#define PF_FLOATING_POINT_EMULATED          1   
#define PF_COMPARE_EXCHANGE_DOUBLE          2   
#define PF_MMX_INSTRUCTIONS_AVAILABLE       3   
#define PF_PPC_MOVEMEM_64BIT_OK             4   
#define PF_ALPHA_BYTE_INSTRUCTIONS          5   
#define PF_XMMI_INSTRUCTIONS_AVAILABLE      6   
#define PF_3DNOW_INSTRUCTIONS_AVAILABLE     7   
#define PF_RDTSC_INSTRUCTION_AVAILABLE      8   
#define PF_PAE_ENABLED                      9   
#define PF_XMMI64_INSTRUCTIONS_AVAILABLE   10   
#define PF_SSE_DAZ_MODE_AVAILABLE          11   
#define PF_NX_ENABLED                      12   
#define PF_SSE3_INSTRUCTIONS_AVAILABLE     13   
#define PF_COMPARE_EXCHANGE128             14   
#define PF_COMPARE64_EXCHANGE128           15   
#define PF_CHANNELS_ENABLED                16   

typedef struct _MEMORY_BASIC_INFORMATION
{
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

#endif /*_WINNT_*/

typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION {
	UCHAR			CurrentFrequency;
	UCHAR			ThermalLimitFrequency;
	UCHAR			ConstantThrottleFrequency;
	UCHAR			DegradedThrottleFrequency;
	UCHAR			LastBusyFrequency;
	UCHAR			LastC3Frequency;
	UCHAR			LastAdjustedBusyFrequency;
	UCHAR			ProcessorMinThrottle;
	UCHAR			ProcessorMaxThrottle;
	ULONG			NumberOfFrequencies;
	ULONG			PromotionCount;
	ULONG			DemotionCount;
	ULONG			ErrorCount;
	ULONG			RetryCount;
	ULONG64   CurrentFrequencyTime;
	ULONG64   CurrentProcessorTime;
	ULONG64   CurrentProcessorIdleTime;
	ULONG64   LastProcessorTime;
	ULONG64   LastProcessorIdleTime;
} SYSTEM_PROCESSOR_POWER_INFORMATION, *PSYSTEM_PROCESSOR_POWER_INFORMATION;

typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION {
	ULONG TimeAdjustment;
	ULONG TimeIncrement;
	BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION {
	ULONG TimeAdjustment;
	BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleProcessTime;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG IoReadOperationCount;
	ULONG IoWriteOperationCount;
	ULONG IoOtherOperationCount;
	ULONG AvailablePages;
	SYSINF_PAGE_COUNT CommittedPages;
	SYSINF_PAGE_COUNT CommitLimit;
	SYSINF_PAGE_COUNT PeakCommitment;
	ULONG PageFaultCount;
	ULONG CopyOnWriteCount;
	ULONG TransitionCount;
	ULONG CacheTransitionCount;
	ULONG DemandZeroCount;
	ULONG PageReadCount;
	ULONG PageReadIoCount;
	ULONG CacheReadCount;
	ULONG CacheIoCount;
	ULONG DirtyPagesWriteCount;
	ULONG DirtyWriteIoCount;
	ULONG MappedPagesWriteCount;
	ULONG MappedWriteIoCount;
	ULONG PagedPoolPages;
	ULONG NonPagedPoolPages;
	ULONG PagedPoolAllocs;
	ULONG PagedPoolFrees;
	ULONG NonPagedPoolAllocs;
	ULONG NonPagedPoolFrees;
	ULONG FreeSystemPtes;
	ULONG ResidentSystemCodePage;
	ULONG TotalSystemDriverPages;
	ULONG TotalSystemCodePages;
	ULONG NonPagedPoolLookasideHits;
	ULONG PagedPoolLookasideHits;
	ULONG AvailablePagedPoolPages;
	ULONG ResidentSystemCachePage;
	ULONG ResidentPagedPoolPage;
	ULONG ResidentSystemDriverPage;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadResourceMiss;
	ULONG CcFastReadNotPossible;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG ContextSwitches;
	ULONG FirstLevelTbFills;
	ULONG SecondLevelTbFills;
	ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION {
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_MEMORY_INFO {
	PUCHAR StringOffset;
	USHORT ValidCount;
	USHORT TransitionCount;
	USHORT ModifiedCount;
	USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION {
	ULONG InfoSize;
	ULONG_PTR StringStart;
	SYSTEM_MEMORY_INFO Memory[ 1 ];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION {
	ULONG Length;
	ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_DEVICE_INFORMATION {
	ULONG NumberOfDisks;
	ULONG NumberOfFloppies;
	ULONG NumberOfCdRoms;
	ULONG NumberOfTapes;
	ULONG NumberOfSerialPorts;
	ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

typedef struct _SYSTEM_FLAGS_INFORMATION {
	ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

typedef struct _SYSTEM_CALL_TIME_INFORMATION {
	ULONG Length;
	ULONG TotalCalls;
	LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION {
	ULONG NextEntryOffset;
	PVOID Object;
	HANDLE CreatorUniqueProcess;
	USHORT CreatorBackTraceIndex;
	USHORT Flags;
	LONG PointerCount;
	LONG HandleCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	HANDLE ExclusiveProcessId;
	PVOID SecurityDescriptor;
	OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

typedef struct _SYSTEM_PAGEFILE_INFORMATION {
	ULONG NextEntryOffset;
	ULONG TotalSize;
	ULONG TotalInUse;
	ULONG PeakUsage;
	UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION {
	ULONG NextEntryOffset;
	ULONG Level;
	UNICODE_STRING DriverName;

	ULONG RaiseIrqls;
	ULONG AcquireSpinLocks;
	ULONG SynchronizeExecutions;
	ULONG AllocationsAttempted;

	ULONG AllocationsSucceeded;
	ULONG AllocationsSucceededSpecialPool;
	ULONG AllocationsWithNoTag;
	ULONG TrimRequests;

	ULONG Trims;
	ULONG AllocationsFailed;
	ULONG AllocationsFailedDeliberately;
	ULONG Loads;

	ULONG Unloads;
	ULONG UnTrackedPool;
	ULONG CurrentPagedPoolAllocations;
	ULONG CurrentNonPagedPoolAllocations;

	ULONG PeakPagedPoolAllocations;
	ULONG PeakNonPagedPoolAllocations;

	SIZE_T PagedPoolUsageInBytes;
	SIZE_T NonPagedPoolUsageInBytes;
	SIZE_T PeakPagedPoolUsageInBytes;
	SIZE_T PeakNonPagedPoolUsageInBytes;

} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

typedef struct _SYSTEM_VERIFIER_INFORMATION_EX
{
	ULONG VerifyMode;
	ULONG OptionChanges;
	UNICODE_STRING PreviousBucketName;
	ULONG Reserved[ 4 ];
} SYSTEM_VERIFIER_INFORMATION_EX, *PSYSTEM_VERIFIER_INFORMATION_EX;

#define MM_WORKING_SET_MAX_HARD_ENABLE      0x1
#define MM_WORKING_SET_MAX_HARD_DISABLE     0x2
#define MM_WORKING_SET_MIN_HARD_ENABLE      0x4
#define MM_WORKING_SET_MIN_HARD_DISABLE     0x8

typedef struct _SYSTEM_FILECACHE_INFORMATION {
	SIZE_T CurrentSize;
	SIZE_T PeakSize;
	ULONG PageFaultCount;
	SIZE_T MinimumWorkingSet;
	SIZE_T MaximumWorkingSet;
	SIZE_T CurrentSizeIncludingTransitionInPages;
	SIZE_T PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

#define FLG_HOTPATCH_KERNEL             0x80000000
#define FLG_HOTPATCH_RELOAD_NTDLL       0x40000000
#define FLG_HOTPATCH_NAME_INFO          0x20000000
#define FLG_HOTPATCH_RENAME_INFO        0x10000000
#define FLG_HOTPATCH_MAP_ATOMIC_SWAP    0x08000000
#define FLG_HOTPATCH_WOW64              0x04000000

#define FLG_HOTPATCH_ACTIVE             0x00000001
#define FLG_HOTPATCH_STATUS_FLAGS       FLG_HOTPATCH_ACTIVE

#define FLG_HOTPATCH_VERIFICATION_ERROR 0x00800000

typedef struct _HOTPATCH_HOOK_DESCRIPTOR
{
	ULONG_PTR TargetAddress;
	PVOID MappedAddress;
	ULONG CodeOffset;
	ULONG CodeSize;
	ULONG OrigCodeOffset;
	ULONG ValidationOffset;
	ULONG ValidationSize;
} HOTPATCH_HOOK_DESCRIPTOR, *PHOTPATCH_HOOK_DESCRIPTOR;

typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION {

	ULONG Flags;
	ULONG InfoSize;

	union
	{
		struct
		{
			ULONG DescriptorsCount;
			HOTPATCH_HOOK_DESCRIPTOR CodeDescriptors[1]; // variable size structure
		} CodeInfo;
		
		struct
		{
			USHORT NameOffset;
			USHORT NameLength;
		} KernelInfo;
		
		struct
		{
			USHORT NameOffset;
			USHORT NameLength;
			USHORT TargetNameOffset;
			USHORT TargetNameLength;
		} UserModeInfo;
		
		struct
		{
			HANDLE FileHandle1;
			PIO_STATUS_BLOCK IoStatusBlock1;
			PFILE_RENAME_INFORMATION RenameInformation1;
			ULONG RenameInformationLength1;
			HANDLE FileHandle2;
			PIO_STATUS_BLOCK IoStatusBlock2;
			PFILE_RENAME_INFORMATION RenameInformation2;
			ULONG RenameInformationLength2;
		} RenameInfo;

		struct
		{
			HANDLE ParentDirectory;
			HANDLE ObjectHandle1;
			HANDLE ObjectHandle2;
		} AtomicSwap;
	};

} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;

typedef struct _KERNEL_USER_TIMES {
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;
typedef KERNEL_USER_TIMES *PKERNEL_USER_TIMES;

typedef enum _WATCHDOG_HANDLER_ACTION
{
	WdActionSetTimeoutValue,
	WdActionQueryTimeoutValue,
	WdActionResetTimer,
	WdActionStopTimer,
	WdActionStartTimer,
	WdActionSetTriggerAction,
	WdActionQueryTriggerAction,
	WdActionQueryState,
	WdActionSleep,
	WdActionWake
} WATCHDOG_HANDLER_ACTION;

typedef enum _WATCHDOG_INFORMATION_CLASS {
	WdInfoTimeoutValue,
	WdInfoResetTimer,
	WdInfoStopTimer,
	WdInfoStartTimer,
	WdInfoTriggerAction,
	WdInfoState
} WATCHDOG_INFORMATION_CLASS;

typedef
	NTSTATUS
	(*PWD_HANDLER)(
	IN WATCHDOG_HANDLER_ACTION Action,
	IN PVOID Context,
	IN OUT PULONG DataValue,
	IN BOOLEAN NoLocks
	);

typedef struct _SYSTEM_WATCHDOG_HANDLER_INFORMATION {
	PWD_HANDLER WdHandler;
	PVOID       Context;
} SYSTEM_WATCHDOG_HANDLER_INFORMATION, *PSYSTEM_WATCHDOG_HANDLER_INFORMATION;

#define WDSTATE_FIRED               0x00000001
#define WDSTATE_HARDWARE_ENABLED    0x00000002
#define WDSTATE_STARTED             0x00000004
#define WDSTATE_HARDWARE_PRESENT    0x00000008

typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION {
	WATCHDOG_INFORMATION_CLASS  WdInfoClass;
	ULONG                       DataValue;
} SYSTEM_WATCHDOG_TIMER_INFORMATION, *PSYSTEM_WATCHDOG_TIMER_INFORMATION;

#define GDI_MAX_HANDLE_COUNT 0x4000

#define GDI_HANDLE_INDEX_SHIFT 0
#define GDI_HANDLE_INDEX_BITS 16
#define GDI_HANDLE_INDEX_MASK 0xffff

#define GDI_HANDLE_TYPE_SHIFT 16
#define GDI_HANDLE_TYPE_BITS 5
#define GDI_HANDLE_TYPE_MASK 0x1f

#define GDI_HANDLE_ALTTYPE_SHIFT 21
#define GDI_HANDLE_ALTTYPE_BITS 2
#define GDI_HANDLE_ALTTYPE_MASK 0x3

#define GDI_HANDLE_STOCK_SHIFT 23
#define GDI_HANDLE_STOCK_BITS 1
#define GDI_HANDLE_STOCK_MASK 0x1

#define GDI_HANDLE_UNIQUE_SHIFT 24
#define GDI_HANDLE_UNIQUE_BITS 8
#define GDI_HANDLE_UNIQUE_MASK 0xff

#define GDI_HANDLE_INDEX(Handle) ((ULONG)(Handle) & GDI_HANDLE_INDEX_MASK)
#define GDI_HANDLE_TYPE(Handle) (((ULONG)(Handle) >> GDI_HANDLE_TYPE_SHIFT) & GDI_HANDLE_TYPE_MASK)
#define GDI_HANDLE_ALTTYPE(Handle) (((ULONG)(Handle) >> GDI_HANDLE_ALTTYPE_SHIFT) & GDI_HANDLE_ALTTYPE_MASK)
#define GDI_HANDLE_STOCK(Handle) (((ULONG)(Handle) >> GDI_HANDLE_STOCK_SHIFT)) & GDI_HANDLE_STOCK_MASK)

#define GDI_MAKE_HANDLE(Index, Unique) ((ULONG)(((ULONG)(Unique) << GDI_HANDLE_INDEX_BITS) | (ULONG)(Index)))

// GDI server-side types

#define GDI_DEF_TYPE 0
#define GDI_DC_TYPE 1
#define GDI_DD_DIRECTDRAW_TYPE 2
#define GDI_DD_SURFACE_TYPE 3
#define GDI_RGN_TYPE 4
#define GDI_SURF_TYPE 5
#define GDI_CLIENTOBJ_TYPE 6
#define GDI_PATH_TYPE 7
#define GDI_PAL_TYPE 8
#define GDI_ICMLCS_TYPE 9
#define GDI_LFONT_TYPE 10
#define GDI_RFONT_TYPE 11
#define GDI_PFE_TYPE 12
#define GDI_PFT_TYPE 13
#define GDI_ICMCXF_TYPE 14
#define GDI_ICMDLL_TYPE 15
#define GDI_BRUSH_TYPE 16
#define GDI_PFF_TYPE 17 // unused
#define GDI_CACHE_TYPE 18 // unused
#define GDI_SPACE_TYPE 19
#define GDI_DBRUSH_TYPE 20 // unused
#define GDI_META_TYPE 21
#define GDI_EFSTATE_TYPE 22
#define GDI_BMFD_TYPE 23 // unused
#define GDI_VTFD_TYPE 24 // unused
#define GDI_TTFD_TYPE 25 // unused
#define GDI_RC_TYPE 26 // unused
#define GDI_TEMP_TYPE 27 // unused
#define GDI_DRVOBJ_TYPE 28
#define GDI_DCIOBJ_TYPE 29 // unused
#define GDI_SPOOL_TYPE 30

// GDI client-side types

#define GDI_CLIENT_TYPE_FROM_HANDLE(Handle) ((ULONG)(Handle) & ((GDI_HANDLE_ALTTYPE_MASK << GDI_HANDLE_ALTTYPE_SHIFT) | \
	(GDI_HANDLE_TYPE_MASK << GDI_HANDLE_TYPE_SHIFT)))
#define GDI_CLIENT_TYPE_FROM_UNIQUE(Unique) GDI_CLIENT_TYPE_FROM_HANDLE((ULONG)(Unique) << 16)

#define GDI_ALTTYPE_1 (1 << GDI_HANDLE_ALTTYPE_SHIFT)
#define GDI_ALTTYPE_2 (2 << GDI_HANDLE_ALTTYPE_SHIFT)
#define GDI_ALTTYPE_3 (3 << GDI_HANDLE_ALTTYPE_SHIFT)

#define GDI_CLIENT_BITMAP_TYPE (GDI_SURF_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_BRUSH_TYPE (GDI_BRUSH_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_CLIENTOBJ_TYPE (GDI_CLIENTOBJ_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_DC_TYPE (GDI_DC_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_FONT_TYPE (GDI_LFONT_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_PALETTE_TYPE (GDI_PAL_TYPE << GDI_HANDLE_TYPE_SHIFT)
#define GDI_CLIENT_REGION_TYPE (GDI_RGN_TYPE << GDI_HANDLE_TYPE_SHIFT)

#define GDI_CLIENT_ALTDC_TYPE (GDI_CLIENT_DC_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_DIBSECTION_TYPE (GDI_CLIENT_BITMAP_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_EXTPEN_TYPE (GDI_CLIENT_BRUSH_TYPE | GDI_ALTTYPE_2)
#define GDI_CLIENT_METADC16_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_3)
#define GDI_CLIENT_METAFILE_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_2)
#define GDI_CLIENT_METAFILE16_TYPE (GDI_CLIENT_CLIENTOBJ_TYPE | GDI_ALTTYPE_1)
#define GDI_CLIENT_PEN_TYPE (GDI_CLIENT_BRUSH_TYPE | GDI_ALTTYPE_1)

typedef struct _GDI_HANDLE_ENTRY
{
	union
	{
		PVOID Object;
		PVOID NextFree;
	};
	union
	{
		struct
		{
			USHORT ProcessId;
			USHORT Lock : 1;
			USHORT Count : 15;
		};
		ULONG Value;
	} Owner;
	USHORT Unique;
	UCHAR Type;
	UCHAR Flags;
	PVOID UserPointer;
} GDI_HANDLE_ENTRY, *PGDI_HANDLE_ENTRY;

typedef struct _GDI_SHARED_MEMORY
{
	GDI_HANDLE_ENTRY Handles[GDI_MAX_HANDLE_COUNT];
} GDI_SHARED_MEMORY, *PGDI_SHARED_MEMORY;

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define WOW64_SYSTEM_DIRECTORY "SysWOW64"
#define WOW64_SYSTEM_DIRECTORY_U L"SysWOW64"
#define WOW64_X86_TAG " (x86)"
#define WOW64_X86_TAG_U L" (x86)"

typedef enum _WOW64_SHARED_INFORMATION
{
	SharedNtdll32LdrInitializeThunk = 0,
	SharedNtdll32KiUserExceptionDispatcher = 1,
	SharedNtdll32KiUserApcDispatcher = 2,
	SharedNtdll32KiUserCallbackDispatcher = 3,
	SharedNtdll32LdrHotPatchRoutine = 4,
	SharedNtdll32ExpInterlockedPopEntrySListFault = 5,
	SharedNtdll32ExpInterlockedPopEntrySListResume = 6,
	SharedNtdll32ExpInterlockedPopEntrySListEnd = 7,
	SharedNtdll32RtlUserThreadStart = 8,
	SharedNtdll32pQueryProcessDebugInformationRemote = 9,
	SharedNtdll32EtwpNotificationThread = 10,
	SharedNtdll32BaseAddress = 11,
	Wow64SharedPageEntriesCount = 12
} WOW64_SHARED_INFORMATION;

// 21.12.2011 added
#define SET_LAST_STATUS(S)NtCurrentTeb()->LastErrorValue = RtlNtStatusToDosError(NtCurrentTeb()->LastStatusValue = (ULONG)(S))
// 21.12.2011 - end

// 32-bit definitions

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
typedef struct LIST_ENTRY32 {
    DWORD Flink;
    DWORD Blink;
} LIST_ENTRY32;
typedef LIST_ENTRY32 *PLIST_ENTRY32;

typedef struct LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} LIST_ENTRY64;
typedef LIST_ENTRY64 *PLIST_ENTRY64;
#endif

#define WOW64_POINTER(Type) ULONG

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	WOW64_POINTER(HANDLE) SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	WOW64_POINTER(PVOID) EntryInProgress;
	BOOLEAN ShutdownInProgress;
	WOW64_POINTER(HANDLE) ShutdownThreadId;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP32 FIELD_OFFSET( LDR_DATA_TABLE_ENTRY32, ForwarderLinks )

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	WOW64_POINTER(PVOID) DllBase;
	WOW64_POINTER(PVOID) EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		struct
		{
			WOW64_POINTER(PVOID) SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		WOW64_POINTER(PVOID) LoadedImports;
	};
	WOW64_POINTER(PVOID) EntryPointActivationContext;
	WOW64_POINTER(PVOID) PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	WOW64_POINTER(PVOID) ContextInformation;
	WOW64_POINTER(ULONG_PTR) OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _CURDIR32
{
	UNICODE_STRING32 DosPath;
	WOW64_POINTER(HANDLE) Handle;
} CURDIR32, *PCURDIR32;

typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, *PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	WOW64_POINTER(HANDLE) ConsoleHandle;
	ULONG ConsoleFlags;
	WOW64_POINTER(HANDLE) StandardInput;
	WOW64_POINTER(HANDLE) StandardOutput;
	WOW64_POINTER(HANDLE) StandardError;

	CURDIR32 CurrentDirectory;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	WOW64_POINTER(PVOID) Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING32 WindowTitle;
	UNICODE_STRING32 DesktopInfo;
	UNICODE_STRING32 ShellInfo;
	UNICODE_STRING32 RuntimeData;
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG EnvironmentSize;
	ULONG EnvironmentVersion;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	WOW64_POINTER(HANDLE) Mutant;

	WOW64_POINTER(PVOID) ImageBaseAddress;
	WOW64_POINTER(PPEB_LDR_DATA) Ldr;
	WOW64_POINTER(PRTL_USER_PROCESS_PARAMETERS) ProcessParameters;
	WOW64_POINTER(PVOID) SubSystemData;
	WOW64_POINTER(PVOID) ProcessHeap;
	WOW64_POINTER(PRTL_CRITICAL_SECTION) FastPebLock;
	WOW64_POINTER(PVOID) AtlThunkSListPtr;
	WOW64_POINTER(PVOID) IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		WOW64_POINTER(PVOID) KernelCallbackTable;
		WOW64_POINTER(PVOID) UserSharedInfoPtr;
	};
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	WOW64_POINTER(PVOID) ApiSetMap;
	ULONG TlsExpansionCounter;
	WOW64_POINTER(PVOID) TlsBitmap;
	ULONG TlsBitmapBits[2];
	WOW64_POINTER(PVOID) ReadOnlySharedMemoryBase;
	WOW64_POINTER(PVOID) HotpatchInformation;
	WOW64_POINTER(PPVOID) ReadOnlyStaticServerData;
	WOW64_POINTER(PVOID) AnsiCodePageData;
	WOW64_POINTER(PVOID) OemCodePageData;
	WOW64_POINTER(PVOID) UnicodeCaseTableData;

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	WOW64_POINTER(SIZE_T) HeapSegmentReserve;
	WOW64_POINTER(SIZE_T) HeapSegmentCommit;
	WOW64_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
	WOW64_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	WOW64_POINTER(PPVOID) ProcessHeaps;

	WOW64_POINTER(PVOID) GdiSharedHandleTable;
	WOW64_POINTER(PVOID) ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	WOW64_POINTER(PRTL_CRITICAL_SECTION) LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	WOW64_POINTER(ULONG_PTR) ImageProcessAffinityMask;
	GDI_HANDLE_BUFFER32 GdiHandleBuffer;
	WOW64_POINTER(PVOID) PostProcessInitRoutine;

	WOW64_POINTER(PVOID) TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	// Rest of structure not included.
} PEB32, *PPEB32;

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH32
{
	ULONG Offset;
	WOW64_POINTER(ULONG_PTR) HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH32, *PGDI_TEB_BATCH32;

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
//
// 32 and 64 bit specific version for wow64 and the debugger
//
typedef struct _NT_TIB32 {
    DWORD ExceptionList;
    DWORD StackBase;
    DWORD StackLimit;
    DWORD SubSystemTib;
    union {
        DWORD FiberData;
        DWORD Version;
    };
    DWORD ArbitraryUserPointer;
    DWORD Self;
} NT_TIB32, *PNT_TIB32;

typedef struct _NT_TIB64 {
    DWORD64 ExceptionList;
    DWORD64 StackBase;
    DWORD64 StackLimit;
    DWORD64 SubSystemTib;
    union {
        DWORD64 FiberData;
        DWORD Version;
    };
    DWORD64 ArbitraryUserPointer;
    DWORD64 Self;
} NT_TIB64, *PNT_TIB64;
#endif

typedef struct _TEB32
{
	NT_TIB32 NtTib;

	WOW64_POINTER(PVOID) EnvironmentPointer;
	CLIENT_ID32 ClientId;
	WOW64_POINTER(PVOID) ActiveRpcHandle;
	WOW64_POINTER(PVOID) ThreadLocalStoragePointer;
	WOW64_POINTER(PPEB) ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	WOW64_POINTER(PVOID) CsrClientThread;
	WOW64_POINTER(PVOID) Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	WOW64_POINTER(PVOID) WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	WOW64_POINTER(PVOID) SystemReserved1[54];
	NTSTATUS ExceptionCode;
	WOW64_POINTER(PVOID) ActivationContextStackPointer;
	BYTE SpareBytes[36];
	ULONG TxFsContext;

	GDI_TEB_BATCH32 GdiTebBatch;
	CLIENT_ID32 RealClientId;
	WOW64_POINTER(HANDLE) GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	WOW64_POINTER(PVOID) GdiThreadLocalInfo;
	WOW64_POINTER(ULONG_PTR) Win32ClientInfo[62];
	WOW64_POINTER(PVOID) glDispatchTable[233];
	WOW64_POINTER(ULONG_PTR) glReserved1[29];
	WOW64_POINTER(PVOID) glReserved2;
	WOW64_POINTER(PVOID) glSectionInfo;
	WOW64_POINTER(PVOID) glSection;
	WOW64_POINTER(PVOID) glTable;
	WOW64_POINTER(PVOID) glCurrentRC;
	WOW64_POINTER(PVOID) glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING32 StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	WOW64_POINTER(PVOID) DeallocationStack;
	WOW64_POINTER(PVOID) TlsSlots[64];
	LIST_ENTRY32 TlsLinks;
} TEB32, *PTEB32;

typedef
	VOID
	(*PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _TIB
{
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;

	union
	{
		PVOID FiberData;
		ULONG Version;
	};

	PVOID ArbitraryUserPointer;
	struct _TIB *Self;
} TIB;
typedef TIB *PTIB;

//
// inifile mapping
//

typedef struct _NLS_USER_INFO
{

	/*<thisrel this+0x0>*/ /*|0xa0|*/ WCHAR iCountry[80];
	/*<thisrel this+0xa0>*/ /*|0xa0|*/ WCHAR sCountry[80];
	/*<thisrel this+0x140>*/ /*|0xa0|*/ WCHAR sList[80];
	/*<thisrel this+0x1e0>*/ /*|0xa0|*/ WCHAR iMeasure[80];
	/*<thisrel this+0x280>*/ /*|0xa0|*/ WCHAR iPaperSize[80];
	/*<thisrel this+0x320>*/ /*|0xa0|*/ WCHAR sDecimal[80];
	/*<thisrel this+0x3c0>*/ /*|0xa0|*/ WCHAR sThousand[80];
	/*<thisrel this+0x460>*/ /*|0xa0|*/ WCHAR sGrouping[80];
	/*<thisrel this+0x500>*/ /*|0xa0|*/ WCHAR iDigits[80];
	/*<thisrel this+0x5a0>*/ /*|0xa0|*/ WCHAR iLZero[80];
	/*<thisrel this+0x640>*/ /*|0xa0|*/ WCHAR iNegNumber[80];
	/*<thisrel this+0x6e0>*/ /*|0xa0|*/ WCHAR sNativeDigits[80];
	/*<thisrel this+0x780>*/ /*|0xa0|*/ WCHAR iDigitSubstitution[80];
	/*<thisrel this+0x820>*/ /*|0xa0|*/ WCHAR sCurrency[80];
	/*<thisrel this+0x8c0>*/ /*|0xa0|*/ WCHAR sMonDecSep[80];
	/*<thisrel this+0x960>*/ /*|0xa0|*/ WCHAR sMonThouSep[80];
	/*<thisrel this+0xa00>*/ /*|0xa0|*/ WCHAR sMonGrouping[80];
	/*<thisrel this+0xaa0>*/ /*|0xa0|*/ WCHAR iCurrDigits[80];
	/*<thisrel this+0xb40>*/ /*|0xa0|*/ WCHAR iCurrency[80];
	/*<thisrel this+0xbe0>*/ /*|0xa0|*/ WCHAR iNegCurr[80];
	/*<thisrel this+0xc80>*/ /*|0xa0|*/ WCHAR sPosSign[80];
	/*<thisrel this+0xd20>*/ /*|0xa0|*/ WCHAR sNegSign[80];
	/*<thisrel this+0xdc0>*/ /*|0xa0|*/ WCHAR sTimeFormat[80];
	/*<thisrel this+0xe60>*/ /*|0xa0|*/ WCHAR s1159[80];
	/*<thisrel this+0xf00>*/ /*|0xa0|*/ WCHAR s2359[80];
	/*<thisrel this+0xfa0>*/ /*|0xa0|*/ WCHAR sShortDate[80];
	/*<thisrel this+0x1040>*/ /*|0xa0|*/ WCHAR sYearMonth[80];
	/*<thisrel this+0x10e0>*/ /*|0xa0|*/ WCHAR sLongDate[80];
	/*<thisrel this+0x1180>*/ /*|0xa0|*/ WCHAR iCalType[80];
	/*<thisrel this+0x1220>*/ /*|0xa0|*/ WCHAR iFirstDay[80];
	/*<thisrel this+0x12c0>*/ /*|0xa0|*/ WCHAR iFirstWeek[80];
	/*<thisrel this+0x1360>*/ /*|0xa0|*/ WCHAR sLocale[80];
	/*<thisrel this+0x1400>*/ /*|0xaa|*/ WCHAR sLocaleName[85];
	/*<thisrel this+0x14ac>*/ /*|0x4|*/ ULONG UserLocaleId;
	/*<thisrel this+0x14b0>*/ /*|0x8|*/ struct _LUID InteractiveUserLuid;
	/*<thisrel this+0x14b8>*/ /*|0x44|*/ UCHAR InteractiveUserSid[68];
	/*<thisrel this+0x14fc>*/ /*|0x4|*/ ULONG ulCacheUpdateCount;
} NLS_USER_INFO, *PNLS_USER_INFO;	// <size 0x1500>

typedef struct _INIFILE_MAPPING_TARGET
{
	struct _INIFILE_MAPPING_TARGET* Next;
	struct _UNICODE_STRING RegistryPath;
} INIFILE_MAPPING_TARGET, *PINIFILE_MAPPING_TARGET;

typedef struct _INIFILE_MAPPING_VARNAME
{
	struct _INIFILE_MAPPING_VARNAME* Next;
	UNICODE_STRING Name;
	ULONG MappingFlags;
	struct _INIFILE_MAPPING_TARGET* MappingTarget;
} INIFILE_MAPPING_VARNAME, *PINIFILE_MAPPING_VARNAME;

typedef struct _INIFILE_MAPPING_APPNAME
{
	struct _INIFILE_MAPPING_APPNAME* Next;
	UNICODE_STRING Name;
	struct _INIFILE_MAPPING_VARNAME* VariableNames;
	struct _INIFILE_MAPPING_VARNAME* DefaultVarNameMapping;
} INIFILE_MAPPING_APPNAME, *PINIFILE_MAPPING_APPNAME;

typedef struct _INIFILE_MAPPING_FILENAME
{
	struct _INIFILE_MAPPING_FILENAME* Next;
	UNICODE_STRING Name;
	struct _INIFILE_MAPPING_APPNAME* ApplicationNames;
	struct _INIFILE_MAPPING_APPNAME* DefaultAppNameMapping;
} INIFILE_MAPPING_FILENAME, *PINIFILE_MAPPING_FILENAME;

typedef struct _INIFILE_MAPPING
{
	struct _INIFILE_MAPPING_FILENAME* FileNames;
	struct _INIFILE_MAPPING_FILENAME* DefaultFileNameMapping;
	struct _INIFILE_MAPPING_FILENAME* WinIniFileMapping;
	ULONG Reserved;
} INIFILE_MAPPING, *PINIFILE_MAPPING;

#define PORT_CONNECT (0x0001)

#define PORT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)

typedef struct _PORT_MESSAGE
{
	union {
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;

		ULONG Length;

	} u1;

	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;

	union
	{
		LPC_CLIENT_ID ClientId;
		double DoNotUseThisField;       // Force quadword alignment
	};

	ULONG MessageId;
	union
	{
		LPC_SIZE_T ClientViewSize;          // Only valid on LPC_CONNECTION_REQUEST message
		ULONG CallbackId;                   // Only valid on LPC_REQUEST message
	};
	//  UCHAR Data[];
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_DATA_ENTRY {
	LPC_PVOID Base;
	ULONG Size;
} PORT_DATA_ENTRY, *PPORT_DATA_ENTRY;

typedef struct _PORT_DATA_INFORMATION {
	ULONG CountDataEntries;
	PORT_DATA_ENTRY DataEntries[1];
} PORT_DATA_INFORMATION, *PPORT_DATA_INFORMATION;

	//
	// csrss & csrsrv related
	//

	typedef ULONG CSR_API_NUMBER;

#define CSR_API_PORT_NAME L"ApiPort"

	//
	// This structure is filled in by the client prior to connecting to the CSR
	// server.  The CSR server will fill in the OUT fields if prior to accepting
	// the connection.
	//

	typedef struct _CSR_API_CONNECTINFO {
		HANDLE ObjectDirectory;
		PVOID SharedSectionBase;
		PVOID SharedStaticServerData;
		PVOID SharedSectionHeap;
		ULONG DebugFlags;
		ULONG SizeOfPebData;
		ULONG SizeOfTebData;
		ULONG NumberOfServerDllNames;
		HANDLE ServerProcessId;
	} CSR_API_CONNECTINFO, *PCSR_API_CONNECTINFO;

	//
	// Message format for messages sent from the client to the server
	//

	typedef struct _CSR_CLIENTCONNECT_MSG
	{
		ULONG ServerDllIndex;
		PVOID ConnectionInformation;
		ULONG ConnectionInformationLength;
	} CSR_CLIENTCONNECT_MSG, *PCSR_CLIENTCONNECT_MSG;	// <size 0xc>

#define CSR_NORMAL_PRIORITY_CLASS   0x00000010
#define CSR_IDLE_PRIORITY_CLASS     0x00000020
#define CSR_HIGH_PRIORITY_CLASS     0x00000040
#define CSR_REALTIME_PRIORITY_CLASS 0x00000080

	typedef struct _CSR_CAPTURE_HEADER {
		ULONG Length;
		PVOID RelatedCaptureBuffer;
		ULONG CountMessagePointers;
		PCHAR FreeSpace;
		ULONG_PTR MessagePointerOffsets[1]; // Offsets within CSR_API_MSG of pointers
	} CSR_CAPTURE_HEADER, *PCSR_CAPTURE_HEADER;

#define WINSS_OBJECT_DIRECTORY_NAME     L"\\Windows"

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
	(CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSR_APINUMBER_TO_SERVERDLLINDEX( ApiNumber ) \
	((ULONG)((ULONG)(ApiNumber) >> 16))

#define CSR_APINUMBER_TO_APITABLEINDEX( ApiNumber ) \
	((ULONG)((USHORT)(ApiNumber)))
	
typedef struct _CSR_NT_SESSION
{
	struct _LIST_ENTRY SessionLink;
	ULONG SessionId;
	ULONG ReferenceCount;
	STRING RootDirectory;
} CSR_NT_SESSION, *PCSR_NT_SESSION;

typedef struct _CSR_API_MSG
{
	PORT_MESSAGE h;
	union
	{
		CSR_API_CONNECTINFO ConnectionRequest;
		struct
		{
			PCSR_CAPTURE_HEADER CaptureBuffer;
			CSR_API_NUMBER ApiNumber;
			ULONG ReturnValue;
			ULONG Reserved;
			union
			{
				CSR_CLIENTCONNECT_MSG ClientConnect;
				ULONG_PTR ApiMessageData[ 46 ];
			} u;
		};
	};
} CSR_API_MSG, *PCSR_API_MSG;

typedef
ULONG (*PCSR_CALLBACK_ROUTINE)(
	IN OUT PCSR_API_MSG ReplyMsg
	);

typedef struct _CSR_CALLBACK_INFO
{
	ULONG ApiNumberBase;
	ULONG MaxApiNumber;
	PCSR_CALLBACK_ROUTINE *CallbackDispatchTable;
} CSR_CALLBACK_INFO, *PCSR_CALLBACK_INFO;

// end csrss


//
// Time Zone
//

typedef struct _RTL_DYNAMIC_TIME_ZONE_INFORMATION {
	struct _RTL_TIME_ZONE_INFORMATION tzi;
	WCHAR TimeZoneKeyName[ 128 ];
	UCHAR DynamicDaylightTimeDisabled;
} RTL_DYNAMIC_TIME_ZONE_INFORMATION, *PRTL_DYNAMIC_TIME_ZONE_INFORMATION;	// <size 0x1b0>

//
// basesrv api
//

typedef struct _BASESRV_API_CONNECTINFO
{
	ULONG ExpectedVersion;
	HANDLE DefaultObjectDirectory;
	ULONG WindowsVersion;
	ULONG CurrentVersion;
	ULONG DebugFlags;
	WCHAR WindowsDirectory[ MAX_PATH ];
	WCHAR WindowsSystemDirectory[ MAX_PATH ];
} BASESRV_API_CONNECTINFO, *PBASESRV_API_CONNECTINFO;

typedef enum _BASESRV_API_NUMBER {
	BasepCreateProcess = BASESRV_FIRST_API_NUMBER,
	BasepCreateThread,
	BasepGetTempFile,
	BasepExitProcess,
	BasepDebugProcess,
	BasepCheckVDM,
	BasepUpdateVDMEntry,
	BasepGetNextVDMCommand,
	BasepExitVDM,
	BasepIsFirstVDM,
	BasepGetVDMExitCode,
	BasepSetReenterCount,
	BasepSetProcessShutdownParam,
	BasepGetProcessShutdownParam,
	BasepSetVDMCurDirs,
	BasepGetVDMCurDirs,
	BasepBatNotification,
	BasepRegisterWowExec,
	BasepSoundSentryNotification,
	BasepRefreshIniFileMapping,
	BasepDefineDosDevice,
	BasepSetTermsrvAppInstallMode,
	BasepSetTermsrvClientTimeZone,
	BasepSxsCreateActivationContext,
	BasepDebugProcessStop,
	BasepRegisterThread,
	BasepDeferredCreateProcess,
	BasepNlsGetUserInfo,
	BasepNlsSetUserInfo,
	BasepNlsUpdateCacheCount,
	BasepMaxApiNumber
} BASESRV_API_NUMBER, *PBASESRV_API_NUMBER;

typedef struct _BASE_NLS_SET_USER_INFO_MSG
{
	ULONG LCType;
	USHORT* pData;
	ULONG DataLength;
} BASE_NLS_SET_USER_INFO_MSG, *PBASE_NLS_SET_USER_INFO_MSG;

typedef struct _BASE_NLS_GET_USER_INFO_MSG
{
	struct _NLS_USER_INFO* pData;
	ULONG DataLength;
} BASE_NLS_GET_USER_INFO_MSG, *PBASE_NLS_GET_USER_INFO_MSG;

typedef struct _BASE_NLS_UPDATE_CACHE_COUNT_MSG
{
	ULONG Reserved;
} BASE_NLS_UPDATE_CACHE_COUNT_MSG, *PBASE_NLS_UPDATE_CACHE_COUNT_MSG;

typedef struct _BASE_UPDATE_VDM_ENTRY_MSG
{
	ULONG iTask;
	ULONG BinaryType;
	PVOID ConsoleHandle;
	PVOID VDMProcessHandle;
	PVOID WaitObjectForParent;
	USHORT EntryIndex;
	USHORT VDMCreationState;
} BASE_UPDATE_VDM_ENTRY_MSG, *PBASE_UPDATE_VDM_ENTRY_MSG;

typedef struct _BASE_GET_NEXT_VDM_COMMAND_MSG
{
	ULONG iTask;
	PVOID ConsoleHandle;
	PVOID WaitObjectForVDM;
	PVOID StdIn;
	PVOID StdOut;
	PVOID StdErr;
	ULONG CodePage;
	ULONG dwCreationFlags;
	ULONG ExitCode;
	PCHAR CmdLine;
	PCHAR AppName;
	PCHAR PifFile;
	PCHAR CurDirectory;
	PCHAR Env;
	ULONG EnvLen;
	struct _STARTUPINFOA* StartupInfo;
	PCHAR Desktop;
	ULONG DesktopLen;
	PCHAR Title;
	ULONG TitleLen;
	PCHAR Reserved;
	ULONG ReservedLen;
	USHORT CurrentDrive;
	USHORT CmdLen;
	USHORT AppLen;
	USHORT PifLen;
	USHORT CurDirectoryLen;
	USHORT VDMState;
	UCHAR fComingFromBat;
} BASE_GET_NEXT_VDM_COMMAND_MSG, *PBASE_GET_NEXT_VDM_COMMAND_MSG;

typedef struct _BASE_SHUTDOWNPARAM_MSG
{
	ULONG ShutdownLevel;
	ULONG ShutdownFlags;
} BASE_SHUTDOWNPARAM_MSG, *PBASE_SHUTDOWNPARAM_MSG;

typedef struct _BASE_GETTEMPFILE_MSG
{
	ULONG uUnique;
} BASE_GETTEMPFILE_MSG, *PBASE_GETTEMPFILE_MSG;

typedef struct _BASE_DEBUGPROCESS_MSG
{
	ULONG dwProcessId;
	CLIENT_ID DebuggerClientId;
	PVOID AttachCompleteRoutine;
} BASE_DEBUGPROCESS_MSG, *PBASE_DEBUGPROCESS_MSG;	// <size 0x10>

typedef struct _BASE_CHECKVDM_MSG
{
	ULONG  iTask;
	HANDLE ConsoleHandle;
	ULONG  BinaryType;
	HANDLE WaitObjectForParent;
	HANDLE StdIn;
	HANDLE StdOut;
	HANDLE StdErr;
	ULONG  CodePage;
	ULONG  dwCreationFlags;
	PCHAR  CmdLine;
	PCHAR  AppName;
	PCHAR  PifFile;
	PCHAR  CurDirectory;
	PCHAR  Env;
	ULONG  EnvLen;
	LPSTARTUPINFOA StartupInfo;
	PCHAR  Desktop;
	ULONG  DesktopLen;
	PCHAR  Title;
	ULONG  TitleLen;
	PCHAR  Reserved;
	ULONG  ReservedLen;
	USHORT CmdLen;
	USHORT AppLen;
	USHORT PifLen;
	USHORT CurDirectoryLen;
	USHORT CurDrive;
	USHORT VDMState;
	struct _LUID* UserLuid;
} BASE_CHECKVDM_MSG, *PBASE_CHECKVDM_MSG;

typedef struct _BASE_GET_VDM_EXIT_CODE_MSG
{
	PVOID ConsoleHandle;
	PVOID hParent;
	ULONG ExitCode;
} BASE_GET_VDM_EXIT_CODE_MSG, *PBASE_GET_VDM_EXIT_CODE_MSG;	// <size 0xc>

typedef struct _BASE_DEFERREDCREATEPROCESS_MSG
{
	struct _CLIENT_ID* ClientId;
	ULONG NtUserFlags;
} BASE_DEFERREDCREATEPROCESS_MSG, *PBASE_DEFERREDCREATEPROCESS_MSG;	// <size 0x8>

typedef struct _BASE_EXITPROCESS_MSG {
	NTSTATUS uExitCode;
} BASE_EXITPROCESS_MSG, *PBASE_EXITPROCESS_MSG;	// <size 0x4>

typedef struct _BASE_GET_SET_VDM_CUR_DIRS_MSG
{
	PVOID ConsoleHandle;
	PCHAR lpszzCurDirs;
	ULONG cchCurDirs;
} BASE_GET_SET_VDM_CUR_DIRS_MSG, *PBASE_GET_SET_VDM_CUR_DIRS_MSG;	// <size 0xc>

typedef struct _BASE_SET_REENTER_COUNT
{
	PVOID ConsoleHandle;
	ULONG fIncDec;
} BASE_SET_REENTER_COUNT, *PBASE_SET_REENTER_COUNT;	// <size 0x8>

#if !defined(_WINNT_) || (defined(_MSC_VER) && (_MSC_VER >= 1300))
typedef enum
{
    ACTCTX_RUN_LEVEL_UNSPECIFIED = 0,
    ACTCTX_RUN_LEVEL_AS_INVOKER,
    ACTCTX_RUN_LEVEL_HIGHEST_AVAILABLE,
    ACTCTX_RUN_LEVEL_REQUIRE_ADMIN,
    ACTCTX_RUN_LEVEL_NUMBERS
} ACTCTX_REQUESTED_RUN_LEVEL;

typedef struct _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION {
    DWORD ulFlags;
    ACTCTX_REQUESTED_RUN_LEVEL  RunLevel;
    DWORD UiAccess;
} ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION, * PACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION;

typedef const struct _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION * PCACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION;


#endif

typedef struct _BASE_SXS_CREATEPROCESS_MSG
{
	ULONG Flags;
	ULONG ProcessParameterFlags;
	union
	{
		UNICODE_STRING CultureFallbacks;
		ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION RunLevel;
		UNICODE_STRING AssemblyName;
	} u;
} BASE_SXS_CREATEPROCESS_MSG, *PBASE_SXS_CREATEPROCESS_MSG;	// <size 0x80>


typedef struct _BASE_CREATEPROCESS_MSG
{
	PVOID ProcessHandle;
	PVOID ThreadHandle;
	CLIENT_ID ClientId;
	ULONG CreationFlags;
	ULONG VdmBinaryType;
	ULONG VdmTask;
	PVOID hVDM;
	struct _BASE_SXS_CREATEPROCESS_MSG Sxs;
	ULONGLONG PebAddressNative;
	ULONG PebAddressWow64;
	USHORT ProcessorArchitecture;
} BASE_CREATEPROCESS_MSG, *PBASE_CREATEPROCESS_MSG;	// <size 0xb0>


typedef struct _BASE_CREATETHREAD_MSG
{
	PVOID ThreadHandle;
	CLIENT_ID ClientId;
} BASE_CREATETHREAD_MSG, *PBASE_CREATETHREAD_MSG;	// <size 0xc>


typedef struct _BASE_MSG_SXS_HANDLES
{
	PVOID File;
	PVOID Process;
	PVOID Section;
	ULONGLONG ViewBase;
} BASE_MSG_SXS_HANDLES, *PBASE_MSG_SXS_HANDLES;	// <size 0x18>


typedef struct _BASE_EXIT_VDM_MSG
{
	PVOID ConsoleHandle;
	ULONG iWowTask;
	PVOID WaitObjectForVDM;
} BASE_EXIT_VDM_MSG, *PBASE_EXIT_VDM_MSG;	// <size 0xc>


typedef struct _BASE_IS_FIRST_VDM_MSG
{
	__int32 FirstVDM;
} BASE_IS_FIRST_VDM_MSG, *PBASE_IS_FIRST_VDM_MSG;	// <size 0x4>


typedef struct _BASE_SET_REENTER_COUNT_MSG
{
	PVOID ConsoleHandle;
	ULONG fIncDec;
} BASE_SET_REENTER_COUNT_MSG, *PBASE_SET_REENTER_COUNT_MSG;	// <size 0x8>


typedef struct _BASE_BAT_NOTIFICATION_MSG
{
	PVOID ConsoleHandle;
	ULONG fBeginEnd;
} BASE_BAT_NOTIFICATION_MSG, *PBASE_BAT_NOTIFICATION_MSG;	// <size 0x8>


typedef struct _BASE_REGISTER_WOWEXEC_MSG
{
	PVOID hEventWowExec;
	PVOID ConsoleHandle;
} BASE_REGISTER_WOWEXEC_MSG, *PBASE_REGISTER_WOWEXEC_MSG;	// <size 0x8>


typedef struct _BASE_REFRESHINIFILEMAPPING_MSG
{
	UNICODE_STRING IniFileName;
} BASE_REFRESHINIFILEMAPPING_MSG, *PBASE_REFRESHINIFILEMAPPING_MSG;	// <size 0x8>


typedef struct _BASE_SET_TERMSRVCLIENTTIMEZONE
{
	struct _RTL_DYNAMIC_TIME_ZONE_INFORMATION* pDTZInfo;
	ULONG ulDTZInfoSize;
	KSYSTEM_TIME RealBias;
	ULONG TimeZoneId;
} BASE_SET_TERMSRVCLIENTTIMEZONE, *PBASE_SET_TERMSRVCLIENTTIMEZONE;	// <size 0x18>

typedef struct _BASE_SET_TERMSRVAPPINSTALLMODE
{
	__int32 bState;
} BASE_SET_TERMSRVAPPINSTALLMODE, *PBASE_SET_TERMSRVAPPINSTALLMODE;


typedef struct _BASE_SOUNDSENTRY_NOTIFICATION_MSG
{
	ULONG VideoMode;
} BASE_SOUNDSENTRY_NOTIFICATION_MSG, *PBASE_SOUNDSENTRY_NOTIFICATION_MSG;	// <size 0x4>


typedef struct _BASE_DEFINEDOSDEVICE_MSG
{
	ULONG Flags;
	UNICODE_STRING DeviceName;
	UNICODE_STRING TargetPath;
} BASE_DEFINEDOSDEVICE_MSG, *PBASE_DEFINEDOSDEVICE_MSG;	// <size 0x14>

typedef struct _BASE_MSG_SXS_STREAM
{
	UCHAR FileType;
	UCHAR PathType;
	UCHAR HandleType;
	UNICODE_STRING Path;
	PVOID FileHandle;
	HANDLE Handle;
	unsigned __int64 Offset;
	ULONG Size;
} BASE_MSG_SXS_STREAM, *PBASE_MSG_SXS_STREAM;	// <size 0x28>


typedef struct _BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG
{
	ULONG Flags;
	USHORT ProcessorArchitecture;
	UNICODE_STRING CultureFallbacks;
	struct _BASE_MSG_SXS_STREAM Manifest;
	struct _BASE_MSG_SXS_STREAM Policy;
	UNICODE_STRING AssemblyDirectory;
	UNICODE_STRING TextualAssemblyIdentity;
	unsigned __int64 FileTime;
	ULONG ResourceName;
	PVOID ActivationContextData;
	struct _ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION RunLevel;
	UNICODE_STRING AssemblyName;
} BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG, *PBASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG;	// <size 0x98>



typedef struct _BASE_API_MSG
{
	PORT_MESSAGE h;
	struct _CSR_CAPTURE_HEADER* CaptureBuffer;
	CSR_API_NUMBER ApiNumber;
	ULONG ReturnValue;
	ULONG Reserved;
	union
	{ /* size 0xb0*/
		BASE_NLS_SET_USER_INFO_MSG NlsSetUserInfo;
		BASE_NLS_GET_USER_INFO_MSG NlsGetUserInfo;
		BASE_NLS_UPDATE_CACHE_COUNT_MSG NlsCacheUpdateCount;
		BASE_SHUTDOWNPARAM_MSG ShutdownParam;
		BASE_CREATEPROCESS_MSG CreateProcess;
		BASE_DEFERREDCREATEPROCESS_MSG DeferredCreateProcess;
		BASE_CREATETHREAD_MSG CreateThread;
		BASE_GETTEMPFILE_MSG GetTempFile;
		BASE_EXITPROCESS_MSG ExitProcess;
		BASE_DEBUGPROCESS_MSG DebugProcess;
		BASE_CHECKVDM_MSG CheckVDM;
		BASE_UPDATE_VDM_ENTRY_MSG UpdateVDMEntry;
		BASE_GET_NEXT_VDM_COMMAND_MSG GetNextVDMCommand;
		BASE_EXIT_VDM_MSG ExitVDM;
		BASE_IS_FIRST_VDM_MSG IsFirstVDM;
		BASE_GET_VDM_EXIT_CODE_MSG GetVDMExitCode;
		BASE_SET_REENTER_COUNT SetReenterCount;
		BASE_GET_SET_VDM_CUR_DIRS_MSG GetSetVDMCurDirs;
		BASE_BAT_NOTIFICATION_MSG BatNotification;
		BASE_REGISTER_WOWEXEC_MSG RegisterWowExec;
		BASE_SOUNDSENTRY_NOTIFICATION_MSG SoundSentryNotification;
		BASE_REFRESHINIFILEMAPPING_MSG RefreshIniFileMapping;
		BASE_DEFINEDOSDEVICE_MSG DefineDosDeviceApi;
		BASE_SET_TERMSRVAPPINSTALLMODE SetTermsrvAppInstallMode;
		BASE_SET_TERMSRVCLIENTTIMEZONE SetTermsrvClientTimeZone;
		BASE_SXS_CREATE_ACTIVATION_CONTEXT_MSG SxsCreateActivationContext;
	} u;
} BASE_API_MSG, *PBASE_API_MSG;	// <size 0xd8>

typedef struct _BASE_STATIC_SERVER_DATA
{
	UNICODE_STRING WindowsDirectory;
	UNICODE_STRING WindowsSystemDirectory;
	UNICODE_STRING NamedObjectDirectory;
	USHORT WindowsMajorVersion;
	USHORT WindowsMinorVersion;
	USHORT BuildNumber;
	USHORT CSDNumber;
	USHORT RCNumber;
	WCHAR CSDVersion[128];
	SYSTEM_BASIC_INFORMATION SysInfo;
	SYSTEM_TIMEOFDAY_INFORMATION TimeOfDay;
	struct _INIFILE_MAPPING* IniFileMapping;
	NLS_USER_INFO NlsUserInfo;
	UCHAR DefaultSeparateVDM;
	UCHAR IsWowTaskReady;
	UNICODE_STRING WindowsSys32x86Directory;
	UCHAR fTermsrvAppInstallMode;
	RTL_DYNAMIC_TIME_ZONE_INFORMATION tziTermsrvClientTimeZone;
	KSYSTEM_TIME ktTermsrvClientBias;
	ULONG TermsrvClientTimeZoneId;
	UCHAR LUIDDeviceMapsEnabled;
	ULONG TermsrvClientTimeZoneChangeNum;
} BASE_STATIC_SERVER_DATA, *PBASE_STATIC_SERVER_DATA;	// <size 0x1860>

#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
	ULONG	Offset;
	UCHAR	Alignment[4];
	ULONG_PTR HDC;
	ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH,*PGDI_TEB_BATCH;

typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;

typedef enum _TIMER_TYPE {
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;

typedef enum _WAIT_TYPE {
	WaitAll,
	WaitAny
} WAIT_TYPE;

#define STATIC_UNICODE_BUFFER_LENGTH 261
#define WIN32_CLIENT_INFO_LENGTH 62

#define WIN32_CLIENT_INFO_SPIN_COUNT 1

typedef PVOID* PPVOID;

#define TLS_MINIMUM_AVAILABLE 64

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {

	ULONG Flags;
	UNICODE_STRING DosPath;
	PVOID Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {

	ULONG Flags;
	ULONG AssemblyCount;
	struct _ASSEMBLY_STORAGE_MAP_ENTRY** AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _ACTIVATION_CONTEXT_DATA {
	ULONG Magic;
	ULONG HeaderSize;
	ULONG FormatVersion;
	ULONG TotalSize;
	ULONG DefaultTocOffset;
	ULONG ExtendedTocOffset;
	ULONG AssemblyRosterOffset;
	ULONG Flags;
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ACTIVATION_CONTEXT {

	LONG RefCount;
	ULONG Flags;
	LIST_ENTRY Links;
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	//void (NotificationRoutine)(unsigned long, struct _ACTIVATION_CONTEXT*, void*, void*, void*, unsigned char*);
	struct _ACTIVATION_CONTEXT* NotificationRoutine;
	PVOID NotificationContext;
	ULONG SentNotifications[8];
	ULONG DisabledNotifications[8];
	struct _ASSEMBLY_STORAGE_MAP StorageMap;
	struct _ASSEMBLY_STORAGE_MAP_ENTRY* InlineStorageMapEntries[32];
	ULONG StackTraceIndex;
	PVOID StackTraces[4][4];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;	// <size 0x12c>

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _INITIAL_TEB
{
	struct
	{
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;

	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;

} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _WOW64_PROCESS
{
	PVOID Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;

//
// Private flags for loader data table entries
//

#define LDRP_STATIC_LINK                0x00000002
#define LDRP_IMAGE_DLL                  0x00000004
#define LDRP_LOAD_IN_PROGRESS           0x00001000
#define LDRP_UNLOAD_IN_PROGRESS         0x00002000
#define LDRP_ENTRY_PROCESSED            0x00004000
#define LDRP_ENTRY_INSERTED             0x00008000
#define LDRP_CURRENT_LOAD               0x00010000
#define LDRP_FAILED_BUILTIN_LOAD        0x00020000
#define LDRP_DONT_CALL_FOR_THREADS      0x00040000
#define LDRP_PROCESS_ATTACH_CALLED      0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED       0x00100000
#define LDRP_IMAGE_NOT_AT_BASE          0x00200000
#define LDRP_COR_IMAGE                  0x00400000
#define LDRP_COR_OWNS_UNMAP             0x00800000
#define LDRP_SYSTEM_MAPPED              0x01000000
#define LDRP_IMAGE_VERIFYING            0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL       0x04000000
#define LDRP_ENTRY_NATIVE               0x08000000
#define LDRP_REDIRECTED                 0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO       0x20000000
#define LDRP_MM_LOADED                  0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED  0x80000000

#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT 0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN 0x00000002

#define LDR_ADDREF_DLL_PIN 0x00000001

#define LDR_GET_PROCEDURE_ADDRESS_DONT_RECORD_FORWARDER 0x00000001

#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY 0x00000002

#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID 0
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED 1
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED 2

#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PCUNICODE_STRING FullDllName;
	PCUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(
	IN ULONG NotificationReason,
	IN PLDR_DLL_NOTIFICATION_DATA NotificationData,
	IN OPTIONAL PVOID Context
	);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
	USHORT NextOffset;
	RTL_PROCESS_MODULE_INFORMATION BaseInfo;
	ULONG ImageChecksum;
	ULONG TimeDateStamp;
	PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

//
// Loader Data Table. Used to track DLLs loaded into an
// image.
//
#ifdef __cplusplus
struct LIST_ENTRY_EX : public LIST_ENTRY
{
	BYTE unk1[8];
	HANDLE base;
	BYTE unk2[20];
	WCHAR* name;
};
#endif

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef const struct _LDR_DATA_TABLE_ENTRY *PCLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS LDR_RELOCATE_IMAGE_RETURN_TYPE;

struct _FLS_CALLBACK_INFO;

typedef BOOLEAN (NTAPI *PDLL_INIT_ROUTINE)(
	IN PVOID DllHandle,
	IN ULONG Reason,
	IN OPTIONAL PCONTEXT Context
	);

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_RELATIVE_NAME
{
	STRING RelativeName;
	HANDLE ContainingDirectory;
} RTL_RELATIVE_NAME, *PRTL_RELATIVE_NAME;

typedef struct _RTLP_CURDIR_REF *PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, *PRTL_RELATIVE_NAME_U;

typedef enum _RTL_PATH_TYPE
{
	RtlPathTypeUnknown,
	RtlPathTypeUncAbsolute,
	RtlPathTypeDriveAbsolute,
	RtlPathTypeDriveRelative,
	RtlPathTypeRooted,
	RtlPathTypeRelative,
	RtlPathTypeLocalDevice,
	RtlPathTypeRootLocalDevice
} RTL_PATH_TYPE, *PRTL_PATH_TYPE;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

// 18/04/2011 updated
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PPVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PPVOID FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pContextData;
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG SpareTracingBits : 30;
        };
    };
} PEB, *PPEB;

//
//  Fusion/sxs thread state information (aka, stuff noone cares about!)
//

#define ACTIVATION_CONTEXT_STACK_FLAG_QUERIES_DISABLED (0x00000001)

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	struct _ACTIVATION_CONTEXT* ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;


typedef struct _ACTIVATION_CONTEXT_STACK
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME * ActiveFrame;
	struct _LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef const ACTIVATION_CONTEXT_STACK * PCACTIVATION_CONTEXT_STACK;

#define TEB_ACTIVE_FRAME_CONTEXT_FLAG_EXTENDED (0x00000001)

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef const TEB_ACTIVE_FRAME_CONTEXT *PCTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX
{
	TEB_ACTIVE_FRAME_CONTEXT BasicContext;
	PCSTR SourceLocation; // e.g. "c:\windows\system32\ntdll.dll"
} TEB_ACTIVE_FRAME_CONTEXT_EX, *PTEB_ACTIVE_FRAME_CONTEXT_EX;

typedef const TEB_ACTIVE_FRAME_CONTEXT_EX *PCTEB_ACTIVE_FRAME_CONTEXT_EX;

#define TEB_ACTIVE_FRAME_FLAG_EXTENDED (0x00000001)

// 17/3/2011 updated
typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef const TEB_ACTIVE_FRAME *PCTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_EX
{
	TEB_ACTIVE_FRAME BasicFrame;
	PVOID ExtensionIdentifier; // use address of your DLL Main or something mapping in the address space
} TEB_ACTIVE_FRAME_EX, *PTEB_ACTIVE_FRAME_EX;

typedef const TEB_ACTIVE_FRAME_EX *PCTEB_ACTIVE_FRAME_EX;

// 18/04/2011
typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#if defined(_M_X64)
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#if defined(_M_X64)
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PPVOID TlsExpansionSlots;
#if defined(_M_X64)
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SpareSameTebBits : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
} TEB, *PTEB;

#define PcTeb 0x18

#define RtlGetCurrentProcessId() (HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess))
#define RtlGetCurrentThreadId()  (HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread))

#define ZwCurrentProcess() NtCurrentProcess()

// 17/3/2011 added
__inline struct _PEB * NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }
#define WOWAddress() ( NtCurrentTeb()->WOW32Reserved )
#define RtlProcessHeap() ( NtCurrentPeb()->ProcessHeap )

// 28/3/2011 added
#define RtlAcquireLockRoutine(L) RtlEnterCriticalSection((PRTL_CRITICAL_SECTION)(L))

// added 18.04.2011
typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// added 20.12.11
// Process Device Map information
//  NtQueryInformationProcess using ProcessDeviceMap
//  NtSetInformationProcess using ProcessDeviceMap
//
//#pragma pack (push, 1)
typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[ 32 ];
        } Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _PROCESS_DEVICEMAP_INFORMATION_EX {
    union {
        struct {
            HANDLE DirectoryHandle;
        } Set;
        struct {
            ULONG DriveMap;
            UCHAR DriveType[ 32 ];
        } Query;
    };
    ULONG Flags;    // specifies that the query type
} PROCESS_DEVICEMAP_INFORMATION_EX, *PPROCESS_DEVICEMAP_INFORMATION_EX;
//#pragma pack(pop)

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION
{
	SIZE_T Size;    // Must be set to structure size on input
	PROCESS_BASIC_INFORMATION BasicInfo;
	union
	{
		ULONG Flags;
		struct
		{
			ULONG IsProtectedProcess : 1;
			ULONG IsWow64Process : 1;
			ULONG IsProcessDeleting : 1;
			ULONG IsCrossSessionCreate : 1;
			ULONG SpareBits : 28;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

typedef struct _RTL_HEAP_ENTRY
{
	SIZE_T Size;
	USHORT Flags;
	USHORT AllocatorBackTraceIndex;
	union
	{
		struct
		{
			SIZE_T Settable;
			ULONG Tag;
		} s1;   // All other heap entries
		struct
		{
			SIZE_T CommittedSize;
			PVOID FirstBlock;
		} s2;   // RTL_SEGMENT
	} u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY               (USHORT)0x0001
#define RTL_HEAP_SEGMENT            (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE     (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1     (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2     (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3     (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS     (USHORT)0x00E0
#define RTL_HEAP_UNCOMMITTED_RANGE  (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY    (USHORT)0x0200

typedef struct _RTL_HEAP_TAG
{
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[ 24 ];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION
{
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[ 5 ];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS
{
	ULONG NumberOfHeaps;
	RTL_HEAP_INFORMATION Heaps[ 1 ];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
	PVOID Address;
	USHORT Type;
	USHORT CreatorBackTraceIndex;

	HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
	LONG LockCount;
	ULONG ContentionCount;
	ULONG EntryCount;

	//
	// The following fields are only valid for Type == RTL_CRITSECT_TYPE
	//

	LONG RecursionCount;

	//
	// The following fields are only valid for Type == RTL_RESOURCE_TYPE
	//

	ULONG NumberOfWaitingShared;
	ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;

// do not name SHA_CTX, if using OpenSSL or such... produces errors.
typedef struct {
	ULONG Unknown[6];
	ULONG State[5];
	ULONG Count[2];
	UCHAR Buffer[64];
} ASHA_CTX, *PSHA_CTX;

struct _CONTEXT;
struct _EXCEPTION_RECORD;

// note, winnt.h ... such the pain-in-ass with this structure.
#if !defined(_WINNT_)
typedef
EXCEPTION_DISPOSITION
(*PEXCEPTION_ROUTINE) (
    IN struct _EXCEPTION_RECORD *ExceptionRecord,
    IN PVOID EstablisherFrame,
    IN OUT struct _CONTEXT *ContextRecord,
    IN OUT PVOID DispatcherContext
    );

typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;

typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;
#endif

#if !defined(POINTER_64)
#define POINTER_64 __ptr64
typedef unsigned __int64 POINTER_64_INT;
#if defined(_M_X64)
#define POINTER_32 __ptr32
#else
#define POINTER_32
#endif
#endif

typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt,
	NtProductServer
} NT_PRODUCT_TYPE, *PNT_PRODUCT_TYPE;


typedef enum _SUITE_TYPE
{
	SmallBusiness,
	Enterprise,
	BackOffice,
	CommunicationServer,
	TerminalServer,
	SmallBusinessRestricted,
	EmbeddedNT,
	DataCenter,
	SingleUserTS,
	Personal,
	Blade,
	EmbeddedRestricted,
	SecurityAppliance,
	StorageServer,
	ComputeServer,
	MaxSuiteType
} SUITE_TYPE;

#define VER_SERVER_NT                       0x80000000
#define VER_WORKSTATION_NT                  0x40000000
#define VER_SUITE_SMALLBUSINESS             0x00000001
#define VER_SUITE_ENTERPRISE                0x00000002
#define VER_SUITE_BACKOFFICE                0x00000004
#define VER_SUITE_COMMUNICATIONS            0x00000008
#define VER_SUITE_TERMINAL                  0x00000010
#define VER_SUITE_SMALLBUSINESS_RESTRICTED  0x00000020
#define VER_SUITE_EMBEDDEDNT                0x00000040
#define VER_SUITE_DATACENTER                0x00000080
#define VER_SUITE_SINGLEUSERTS              0x00000100
#define VER_SUITE_PERSONAL                  0x00000200
#define VER_SUITE_BLADE                     0x00000400
#define VER_SUITE_EMBEDDED_RESTRICTED       0x00000800
#define VER_SUITE_SECURITY_APPLIANCE        0x00001000
#define VER_SUITE_STORAGE_SERVER            0x00002000
#define VER_SUITE_COMPUTE_SERVER            0x00004000

//
// exception structures
//

#ifndef _WINNT_		// take presidence over winnt.h

typedef struct _CONTEXT
{

	//
	// The flags values within this flag control the contents of
	// a CONTEXT record.
	//
	// If the context record is used as an input parameter, then
	// for each portion of the context record controlled by a flag
	// whose value is set, it is assumed that that portion of the
	// context record contains valid context. If the context record
	// is being used to modify a threads context, then only that
	// portion of the threads context will be modified.
	//
	// If the context record is used as an IN OUT parameter to capture
	// the context of a thread, then only those portions of the thread's
	// context corresponding to set flags will be returned.
	//
	// The context record is never used as an OUT only parameter.
	//

	DWORD ContextFlags;

	//
	// This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
	// set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
	// included in CONTEXT_FULL.
	//

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
	//

	FLOATING_SAVE_AREA FloatSave;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_SEGMENTS.
	//

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_INTEGER.
	//

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_CONTROL.
	//

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;

	//
	// This section is specified/returned if the ContextFlags word
	// contains the flag CONTEXT_EXTENDED_REGISTERS.
	// The format and contexts are processor specific
	//

	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} CONTEXT, *PCONTEXT;

typedef struct _EXCEPTION_RECORD
{
	DWORD  ExceptionCode;																						// NTSTATUS code of the exception.
	DWORD ExceptionFlags;																						// need more information
	struct _EXCEPTION_RECORD *ExceptionRecord;											// pointer to an extra record
	PVOID ExceptionAddress;																					// address of the exception happen
	DWORD NumberParameters;																					// more information needed ...
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

//
//  Values put in ExceptionRecord.ExceptionInformation[0]
//  First parameter is always in ExceptionInformation[1],
//  Second parameter is always in ExceptionInformation[2]
//

typedef struct _EXCEPTION_RECORD32 {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	DWORD ExceptionRecord;
	DWORD ExceptionAddress;
	DWORD NumberParameters;
	DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_RECORD64 {
	DWORD    ExceptionCode;
	DWORD ExceptionFlags;
	DWORD64 ExceptionRecord;
	DWORD64 ExceptionAddress;
	DWORD NumberParameters;
	DWORD __unusedAlignment;
	DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

//
// Typedef for pointer returned by exception_info()
//

typedef struct _EXCEPTION_POINTERS
{
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

#endif

typedef NTSTATUS (NTAPI * PRTL_QUERY_REGISTRY_ROUTINE)(
	IN PWSTR ValueName,
	IN ULONG ValueType,
	IN PVOID ValueData,
	IN ULONG ValueLength,
	IN PVOID Context,
	IN PVOID EntryContext
	);

typedef struct _RTL_QUERY_REGISTRY_TABLE {
	PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
	ULONG Flags;
	PWSTR Name;
	PVOID EntryContext;
	ULONG DefaultType;
	PVOID DefaultData;
	ULONG DefaultLength;

} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

#define EXCEPTION_CHAIN_END ((struct _EXCEPTION_REGISTRATION_RECORD * POINTER_32)-1)

#define MAJOR_VERSION 30
#define MINOR_VERSION 00
#define OS2_VERSION (MAJOR_VERSION << 8 | MINOR_VERSION )

#ifdef DBG
#define DBG_TEB_THREADNAME 16
#define DBG_TEB_RESERVED_1 15
#define DBG_TEB_RESERVED_2 14
#define DBG_TEB_RESERVED_3 13
#define DBG_TEB_RESERVED_4 12
#define DBG_TEB_RESERVED_5 11
#define DBG_TEB_RESERVED_6 10
#define DBG_TEB_RESERVED_7  9
#define DBG_TEB_RESERVED_8  8
#endif // DBG

#define PROCESS_PRIORITY_CLASS_UNKNOWN      0
#define PROCESS_PRIORITY_CLASS_IDLE         1
#define PROCESS_PRIORITY_CLASS_NORMAL       2
#define PROCESS_PRIORITY_CLASS_HIGH         3
#define PROCESS_PRIORITY_CLASS_REALTIME     4
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL 5
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL 6

typedef struct _PROCESS_PRIORITY_CLASS {
	BOOLEAN Foreground;
	UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef struct _PROCESS_FOREGROUND_BACKGROUND {
	BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

typedef struct _FILE_PATH {
	ULONG Version;
	ULONG Length;
	ULONG Type;
	UCHAR FilePath[ANYSIZE_ARRAY];
} FILE_PATH, *PFILE_PATH;

#define FILE_PATH_VERSION 1

#define FILE_PATH_TYPE_ARC           1
#define FILE_PATH_TYPE_ARC_SIGNATURE 2
#define FILE_PATH_TYPE_NT            3
#define FILE_PATH_TYPE_EFI           4

#define FILE_PATH_TYPE_MIN FILE_PATH_TYPE_ARC
#define FILE_PATH_TYPE_MAX FILE_PATH_TYPE_EFI

typedef struct _WINDOWS_OS_OPTIONS {
	UCHAR Signature[8];
	ULONG Version;
	ULONG Length;
	ULONG OsLoadPathOffset;
	WCHAR OsLoadOptions[ANYSIZE_ARRAY];
	//FILE_PATH OsLoadPath;
} WINDOWS_OS_OPTIONS, *PWINDOWS_OS_OPTIONS;

#define WINDOWS_OS_OPTIONS_SIGNATURE "WINDOWS"

#define WINDOWS_OS_OPTIONS_VERSION 1

typedef struct _BOOT_ENTRY {
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
	//WCHAR FriendlyName[ANYSIZE_ARRAY];
	//FILE_PATH BootFilePath;
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _BOOT_OPTIONS {
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[ANYSIZE_ARRAY];
} BOOT_OPTIONS, *PBOOT_OPTIONS;


//
// Security APIs.
//

typedef struct _USER_SID
{
	SID_IDENTIFIER_AUTHORITY sidAuthority;
	ULONG UserGroupId;
	ULONG UserId;
} USER_SID, *PUSER_SID;


typedef struct _USER_PERMISSION
{
	USER_SID UserSid;						// identifies the user for whom you want to grant permissions to
	ULONG dwAccessType;         // currently, this is either ACCESS_ALLOWED_ACE_TYPE or  ACCESS_DENIED_ACE_TYPE
	BOOL bInherit;              // the permissions inheritable? (eg a directory or reg key and you want new children to inherit this permission)
	ULONG dwAccessMask;         // access granted (eg FILE_LIST_CONTENTS or KEY_ALL_ACCESS, etc...)
	ULONG dwInheritMask;        // mask used for inheritance, usually (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE)
	ULONG dwInheritAccessMask;  // the inheritable access granted (eg GENERIC_ALL)
} USER_PERMISSION, *PUSER_PERMISSION;

#define LongAlignPtr(Ptr) ((PVOID)(((ULONG_PTR)(Ptr) + 3) & -4))
#define LongAlignSize(Size) (((ULONG)(Size) + 3) & -4)

//
// Macros for calculating the address of the components of a security
// descriptor.  This will calculate the address of the field regardless
// of whether the security descriptor is absolute or self-relative form.
// A null value indicates the specified field is not present in the
// security descriptor.
//

#define RtlpOwnerAddrSecurityDescriptor( SD )                                  \
           (  ((SD)->Control & SE_SELF_RELATIVE) ?                             \
               (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Owner == 0) ? ((PSID) NULL) :               \
                       (PSID)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Owner)    \
               ) :                                                             \
               (PSID)((SD)->Owner)                                             \
           )

#define RtlpGroupAddrSecurityDescriptor( SD )                                  \
           (  ((SD)->Control & SE_SELF_RELATIVE) ?                             \
               (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Group == 0) ? ((PSID) NULL) :               \
                       (PSID)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Group)    \
               ) :                                                             \
               (PSID)((SD)->Group)                                             \
           )

#define RtlpSaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_SACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Sacl) \
                   ) :                                                         \
                   (PACL)((SD)->Sacl)                                          \
               )                                                               \
           )

#define RtlpDaclAddrSecurityDescriptor( SD )                                   \
           ( (!((SD)->Control & SE_DACL_PRESENT) ) ?                           \
             (PACL)NULL :                                                      \
               (  ((SD)->Control & SE_SELF_RELATIVE) ?                         \
                   (   (((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl == 0) ? ((PACL) NULL) :            \
                           (PACL)RtlOffsetToPointer((SD), ((SECURITY_DESCRIPTOR_RELATIVE *) (SD))->Dacl) \
                   ) :                                                         \
                   (PACL)((SD)->Dacl)                                          \
               )                                                               \
           )


//
//  Macro to determine if the given ID has the owner attribute set,
//  which means that it may be assignable as an owner
//  The GroupSid should not be marked for UseForDenyOnly.
//

#define RtlpIdAssignableAsOwner( G )                                               \
            ( (((G).Attributes & SE_GROUP_OWNER) != 0)  &&                         \
              (((G).Attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0) )

//
//  Macro to copy the state of the passed bits from the old security
//  descriptor (OldSD) into the Control field of the new one (NewSD)
//

#define RtlpPropagateControlBits( NewSD, OldSD, Bits )                             \
            ( NewSD )->Control |=                     \
            (                                                                  \
            ( OldSD )->Control & ( Bits )             \
            )


//
//  Macro to query whether or not the passed set of bits are ALL on
//  or not (ie, returns FALSE if some are on and not others)
//

#define RtlpAreControlBitsSet( SD, Bits )                                          \
            (BOOLEAN)                                                          \
            (                                                                  \
            (( SD )->Control & ( Bits )) == ( Bits )  \
            )

//
//  Macro to set the passed control bits in the given Security Descriptor
//

#define RtlpSetControlBits( SD, Bits )                                             \
            (                                                                  \
            ( SD )->Control |= ( Bits )                                        \
            )

//
//  Macro to clear the passed control bits in the given Security Descriptor
//

#define RtlpClearControlBits( SD, Bits )	\
            (															\
            ( SD )->Control &= ~( Bits )	\
            )


//
// Local Security Authority APIs.
//

#ifdef DEFINE_GUID

/* 0cce9210-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_SecurityStateChange_defined)
    DEFINE_GUID(
        Audit_System_SecurityStateChange,
        0x0cce9210,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_SecurityStateChange_defined
    #endif
#endif

/* 0cce9211-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_SecuritySubsystemExtension_defined)
    DEFINE_GUID(
        Audit_System_SecuritySubsystemExtension,
        0x0cce9211,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_SecuritySubsystemExtension_defined
    #endif
#endif

/* 0cce9212-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_Integrity_defined)
    DEFINE_GUID(
        Audit_System_Integrity,
        0x0cce9212,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_Integrity_defined
    #endif
#endif

/* 0cce9213-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_IPSecDriverEvents_defined)
    DEFINE_GUID(
        Audit_System_IPSecDriverEvents,
        0x0cce9213,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_IPSecDriverEvents_defined
    #endif
#endif

/* 0cce9214-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_Others_defined)
    DEFINE_GUID(
        Audit_System_Others,
        0x0cce9214,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_Others_defined
    #endif
#endif

/* 0cce9215-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_Logon_defined)
    DEFINE_GUID(
        Audit_Logon_Logon,
        0x0cce9215,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_Logon_defined
    #endif
#endif

/* 0cce9216-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_Logoff_defined)
    DEFINE_GUID(
        Audit_Logon_Logoff,
        0x0cce9216,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_Logoff_defined
    #endif
#endif

/* 0cce9217-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_AccountLockout_defined)
    DEFINE_GUID(
        Audit_Logon_AccountLockout,
        0x0cce9217,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_AccountLockout_defined
    #endif
#endif

/* 0cce9218-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_IPSecMainMode_defined)
    DEFINE_GUID(
        Audit_Logon_IPSecMainMode,
        0x0cce9218,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_IPSecMainMode_defined
    #endif
#endif

/* 0cce9219-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_IPSecQuickMode_defined)
    DEFINE_GUID(
        Audit_Logon_IPSecQuickMode,
        0x0cce9219,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_IPSecQuickMode_defined
    #endif
#endif

/* 0cce921a-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_IPSecUserMode_defined)
    DEFINE_GUID(
        Audit_Logon_IPSecUserMode,
        0x0cce921a,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_IPSecUserMode_defined
    #endif
#endif

/* 0cce921b-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_SpecialLogon_defined)
    DEFINE_GUID(
        Audit_Logon_SpecialLogon,
        0x0cce921b,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_SpecialLogon_defined
    #endif
#endif

/* 0cce921c-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_Others_defined)
    DEFINE_GUID(
        Audit_Logon_Others,
        0x0cce921c,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_Others_defined
    #endif
#endif

/* 0cce921d-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_FileSystem_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_FileSystem,
        0x0cce921d,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_FileSystem_defined
    #endif
#endif

/* 0cce921e-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Registry_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Registry,
        0x0cce921e,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Registry_defined
    #endif
#endif

/* 0cce921f-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Kernel_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Kernel,
        0x0cce921f,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Kernel_defined
    #endif
#endif

/* 0cce9220-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Sam_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Sam,
        0x0cce9220,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Sam_defined
    #endif
#endif

/* 0cce9221-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_CertificationServices_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_CertificationServices,
        0x0cce9221,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_CertificationServices_defined
    #endif
#endif

/* 0cce9222-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_ApplicationGenerated_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_ApplicationGenerated,
        0x0cce9222,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_ApplicationGenerated_defined
    #endif
#endif

/*
The Audit_ObjectAccess_Handle sub-category behaves different from the other sub-categories.
For handle based audits to be generated (Open handle AuditId: 0x1230, Close handle AuditId:
0x1232), the corresponding object sub-category AND Audit_ObjectAccess_Handle must be
enabled. For eg, to generate handle based audits for Reg keys, both
Audit_ObjectAccess_Registry and Audit_ObjectAccess_Handle must be enabled
*/

/* 0cce9223-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Handle_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Handle,
        0x0cce9223,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Handle_defined
    #endif
#endif

/* 0cce9224-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Share_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Share,
        0x0cce9224,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Share_defined
    #endif
#endif

/* 0cce9225-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_FirewallPacketDrops_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_FirewallPacketDrops,
        0x0cce9225,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_FirewallPacketDrops_defined
    #endif
#endif

/* 0cce9226-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_FirewallConnection_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_FirewallConnection,
        0x0cce9226,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_FirewallConnection_defined
    #endif
#endif

/* 0cce9227-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_Other_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_Other,
        0x0cce9227,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_Other_defined
    #endif
#endif

/* 0cce9228-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PrivilegeUse_Sensitive_defined)
    DEFINE_GUID(
        Audit_PrivilegeUse_Sensitive,
        0x0cce9228,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PrivilegeUse_Sensitive_defined
    #endif
#endif

/* 0cce9229-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PrivilegeUse_NonSensitive_defined)
    DEFINE_GUID(
        Audit_PrivilegeUse_NonSensitive,
        0x0cce9229,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PrivilegeUse_NonSensitive_defined
    #endif
#endif

/* 0cce922a-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PrivilegeUse_Others_defined)
    DEFINE_GUID(
        Audit_PrivilegeUse_Others,
        0x0cce922a,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PrivilegeUse_Others_defined
    #endif
#endif

/* 0cce922b-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DetailedTracking_ProcessCreation_defined)
    DEFINE_GUID(
        Audit_DetailedTracking_ProcessCreation,
        0x0cce922b,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DetailedTracking_ProcessCreation_defined
    #endif
#endif

/* 0cce922c-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DetailedTracking_ProcessTermination_defined)
    DEFINE_GUID(
        Audit_DetailedTracking_ProcessTermination,
        0x0cce922c,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DetailedTracking_ProcessTermination_defined
    #endif
#endif

/* 0cce922d-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DetailedTracking_DpapiActivity_defined)
    DEFINE_GUID(
        Audit_DetailedTracking_DpapiActivity,
        0x0cce922d,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DetailedTracking_DpapiActivity_defined
    #endif
#endif

/* 0cce922e-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DetailedTracking_RpcCall_defined)
    DEFINE_GUID(
        Audit_DetailedTracking_RpcCall,
        0x0cce922e,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DetailedTracking_RpcCall_defined
    #endif
#endif

/* 0cce922f-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_AuditPolicy_defined)
    DEFINE_GUID(
        Audit_PolicyChange_AuditPolicy,
        0x0cce922f,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_AuditPolicy_defined
    #endif
#endif

/* 0cce9230-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_AuthenticationPolicy_defined)
    DEFINE_GUID(
        Audit_PolicyChange_AuthenticationPolicy,
        0x0cce9230,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_AuthenticationPolicy_defined
    #endif
#endif

/* 0cce9231-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_AuthorizationPolicy_defined)
    DEFINE_GUID(
        Audit_PolicyChange_AuthorizationPolicy,
        0x0cce9231,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_AuthorizationPolicy_defined
    #endif
#endif

/* 0cce9232-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_MpsscvRulePolicy_defined)
    DEFINE_GUID(
        Audit_PolicyChange_MpsscvRulePolicy,
        0x0cce9232,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_MpsscvRulePolicy_defined
    #endif
#endif

/* 0cce9233-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_WfpIPSecPolicy_defined)
    DEFINE_GUID(
        Audit_PolicyChange_WfpIPSecPolicy,
        0x0cce9233,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_WfpIPSecPolicy_defined
    #endif
#endif

/* 0cce9234-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_Others_defined)
    DEFINE_GUID(
        Audit_PolicyChange_Others,
        0x0cce9234,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_Others_defined
    #endif
#endif

/* 0cce9235-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_UserAccount_defined)
    DEFINE_GUID(
        Audit_AccountManagement_UserAccount,
        0x0cce9235,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_UserAccount_defined
    #endif
#endif

/* 0cce9236-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_ComputerAccount_defined)
    DEFINE_GUID(
        Audit_AccountManagement_ComputerAccount,
        0x0cce9236,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_ComputerAccount_defined
    #endif
#endif

/* 0cce9237-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_SecurityGroup_defined)
    DEFINE_GUID(
        Audit_AccountManagement_SecurityGroup,
        0x0cce9237,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_SecurityGroup_defined
    #endif
#endif

/* 0cce9238-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_DistributionGroup_defined)
    DEFINE_GUID(
        Audit_AccountManagement_DistributionGroup,
        0x0cce9238,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_DistributionGroup_defined
    #endif
#endif

/* 0cce9239-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_ApplicationGroup_defined)
    DEFINE_GUID(
        Audit_AccountManagement_ApplicationGroup,
        0x0cce9239,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_ApplicationGroup_defined
    #endif
#endif

/* 0cce923a-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_Others_defined)
    DEFINE_GUID(
        Audit_AccountManagement_Others,
        0x0cce923a,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_Others_defined
    #endif
#endif

/* 0cce923b-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DSAccess_DSAccess_defined)
    DEFINE_GUID(
        Audit_DSAccess_DSAccess,
        0x0cce923b,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DSAccess_DSAccess_defined
    #endif
#endif

/* 0cce923c-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DsAccess_AdAuditChanges_defined)
    DEFINE_GUID(
        Audit_DsAccess_AdAuditChanges,
        0x0cce923c,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DsAccess_AdAuditChanges_defined
    #endif
#endif

/* 0cce923d-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Ds_Replication_defined)
    DEFINE_GUID(
        Audit_Ds_Replication,
        0x0cce923d,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Ds_Replication_defined
    #endif
#endif

/* 0cce923e-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Ds_DetailedReplication_defined)
    DEFINE_GUID(
        Audit_Ds_DetailedReplication,
        0x0cce923e,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Ds_DetailedReplication_defined
    #endif
#endif

/* 0cce923f-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountLogon_CredentialValidation_defined)
    DEFINE_GUID(
        Audit_AccountLogon_CredentialValidation,
        0x0cce923f,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountLogon_CredentialValidation_defined
    #endif
#endif

/* 0cce9240-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountLogon_Kerberos_defined)
    DEFINE_GUID(
        Audit_AccountLogon_Kerberos,
        0x0cce9240,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountLogon_Kerberos_defined
    #endif
#endif

/* 0cce9241-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountLogon_Others_defined)
    DEFINE_GUID(
        Audit_AccountLogon_Others,
        0x0cce9241,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountLogon_Others_defined
    #endif
#endif

/* 0cce9242-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountLogon_KerbCredentialValidation_defined)
    DEFINE_GUID(
        Audit_AccountLogon_KerbCredentialValidation,
        0x0cce9242,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountLogon_KerbCredentialValidation_defined
    #endif
#endif

/* 0cce9243-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_NPS_defined)
    DEFINE_GUID(
        Audit_Logon_NPS,
        0x0cce9243,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_NPS_defined
    #endif
#endif

/* 0cce9244-69ae-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_DetailedFileShare_defined)
    DEFINE_GUID(
        Audit_ObjectAccess_DetailedFileShare,
        0x0cce9244,
        0x69ae, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_DetailedFileShare_defined
    #endif
#endif

#endif // DEFINE_GUID


//
// All categories are named as <Audit_CategoryName>
//

#ifdef DEFINE_GUID

/* 69979848-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_System_defined)
    DEFINE_GUID(
        Audit_System,
        0x69979848,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_System_defined
    #endif
#endif

/* 69979849-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_Logon_defined)
    DEFINE_GUID(
        Audit_Logon,
        0x69979849,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_Logon_defined
    #endif
#endif

/* 6997984a-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_ObjectAccess_defined)
    DEFINE_GUID(
        Audit_ObjectAccess,
        0x6997984a,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_ObjectAccess_defined
    #endif
#endif

/* 6997984b-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PrivilegeUse_defined)
    DEFINE_GUID(
        Audit_PrivilegeUse,
        0x6997984b,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PrivilegeUse_defined
    #endif
#endif

/* 6997984c-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DetailedTracking_defined)
    DEFINE_GUID(
        Audit_DetailedTracking,
        0x6997984c,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DetailedTracking_defined
    #endif
#endif

/* 6997984d-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_PolicyChange_defined)
    DEFINE_GUID(
        Audit_PolicyChange,
        0x6997984d,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_PolicyChange_defined
    #endif
#endif

/* 6997984e-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountManagement_defined)
    DEFINE_GUID(
        Audit_AccountManagement,
        0x6997984e,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountManagement_defined
    #endif
#endif

/* 6997984f-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_DirectoryServiceAccess_defined)
    DEFINE_GUID(
        Audit_DirectoryServiceAccess,
        0x6997984f,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_DirectoryServiceAccess_defined
    #endif
#endif

/* 69979850-797a-11d9-bed3-505054503030 */
#if !defined(INITGUID) || !defined(Audit_AccountLogon_defined)
    DEFINE_GUID(
        Audit_AccountLogon,
        0x69979850,
        0x797a, 0x11d9, 0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30
    	);
    #ifdef INITGUID
    #define Audit_AccountLogon_defined
    #endif
#endif

#endif // DEFINE_GUID

// 04.06.2011 - added
#if !defined(_NTLSA_IFS_)
#define _NTLSA_IFS_

#if !defined(_LSALOOKUP_)
#define _LSALOOKUP_

#if defined(_NTDEF_)

typedef UNICODE_STRING LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;
typedef STRING LSA_STRING, *PLSA_STRING;
typedef OBJECT_ATTRIBUTES LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

#else // _NTDEF_

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength/2), length_is(Length/2)]
#endif // MIDL_PASS
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING;

typedef struct _LSA_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} LSA_STRING, *PLSA_STRING;

typedef struct _LSA_OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PLSA_UNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} LSA_OBJECT_ATTRIBUTES, *PLSA_OBJECT_ATTRIBUTES;

#endif // _NTDEF_

typedef struct _LSA_TRUST_INFORMATION {
	LSA_UNICODE_STRING Name;	// The name of the domain
	PSID Sid;									// ptr to domain Sid
} LSA_TRUST_INFORMATION, *PLSA_TRUST_INFORMATION;

typedef struct _LSA_REFERENCED_DOMAIN_LIST {
	ULONG Entries;									// count of domains in domain array
	PLSA_TRUST_INFORMATION Domains;	// pointer to array LSA_TRUST_INFORMATION data
} LSA_REFERENCED_DOMAIN_LIST, *PLSA_REFERENCED_DOMAIN_LIST;

#if (_WIN32_WINNT >= 0x0501)
typedef struct _LSA_TRANSLATED_SID2 {
	SID_NAME_USE Use;
	PSID         Sid;
	LONG         DomainIndex;
	ULONG        Flags;
} LSA_TRANSLATED_SID2, *PLSA_TRANSLATED_SID2;
#endif

typedef struct _LSA_TRANSLATED_NAME {
	SID_NAME_USE Use;
	LSA_UNICODE_STRING Name;
	LONG DomainIndex;
} LSA_TRANSLATED_NAME, *PLSA_TRANSLATED_NAME;

typedef struct _POLICY_ACCOUNT_DOMAIN_INFO {
	LSA_UNICODE_STRING DomainName;
	PSID DomainSid;
} POLICY_ACCOUNT_DOMAIN_INFO, *PPOLICY_ACCOUNT_DOMAIN_INFO;

typedef struct _POLICY_DNS_DOMAIN_INFO
{
	LSA_UNICODE_STRING Name;
	LSA_UNICODE_STRING DnsDomainName;
	LSA_UNICODE_STRING DnsForestName;
	GUID DomainGuid;
	PSID Sid;
} POLICY_DNS_DOMAIN_INFO, *PPOLICY_DNS_DOMAIN_INFO;

#define LOOKUP_VIEW_LOCAL_INFORMATION       0x00000001
#define LOOKUP_TRANSLATE_NAMES              0x00000800

typedef enum _LSA_LOOKUP_DOMAIN_INFO_CLASS {
	AccountDomainInformation = 5,
	DnsDomainInformation     = 12
} LSA_LOOKUP_DOMAIN_INFO_CLASS, *PLSA_LOOKUP_DOMAIN_INFO_CLASS;

typedef PVOID LSA_LOOKUP_HANDLE, *PLSA_LOOKUP_HANDLE;

NTSTATUS
LsaLookupOpenLocalPolicy(
	IN PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	IN ACCESS_MASK AccessMask,
	IN OUT PLSA_LOOKUP_HANDLE PolicyHandle
	);

NTSTATUS
LsaLookupClose(
	IN LSA_LOOKUP_HANDLE ObjectHandle
	);

NTSTATUS
LsaLookupTranslateSids(
	IN LSA_LOOKUP_HANDLE PolicyHandle,
	IN ULONG Count,
	IN PSID *Sids,
	OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	OUT PLSA_TRANSLATED_NAME *Names
	);

#if (_WIN32_WINNT >= 0x0501)
NTSTATUS
LsaLookupTranslateNames(
	IN LSA_LOOKUP_HANDLE PolicyHandle,
	IN ULONG Flags,
	IN ULONG Count,
	IN PLSA_UNICODE_STRING Names,
	OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	OUT PLSA_TRANSLATED_SID2 *Sids
	);
#endif

NTSTATUS
LsaLookupGetDomainInfo(
	IN LSA_LOOKUP_HANDLE PolicyHandle,
	IN LSA_LOOKUP_DOMAIN_INFO_CLASS DomainInfoClass,
	OUT PVOID *DomainInfo
	);

NTSTATUS
LsaLookupFreeMemory(
	IN PVOID Buffer
	);

#endif // _LSALOOKUP_

#define LSA_MODE_PASSWORD_PROTECTED     (0x00000001L)
#define LSA_MODE_INDIVIDUAL_ACCOUNTS    (0x00000002L)
#define LSA_MODE_MANDATORY_ACCESS       (0x00000004L)
#define LSA_MODE_LOG_FULL               (0x00000008L)

typedef enum _SECURITY_LOGON_TYPE {
    UndefinedLogonType = 0, // This is used to specify an undefied logon type
    Interactive = 2,      // Interactively logged on (locally or remotely)
    Network,              // Accessing system via network
    Batch,                // Started via a batch queue
    Service,              // Service started by service controller
    Proxy,                // Proxy logon
    Unlock,               // Unlock workstation
    NetworkCleartext,     // Network logon with cleartext credentials
    NewCredentials,       // Clone caller, new default credentials
    //The types below only exist in Windows XP and greater
#if (_WIN32_WINNT >= 0x0501)
    RemoteInteractive,  // Remote, yet interactive. Terminal server
    CachedInteractive,  // Try cached credentials without hitting the net.
    // The types below only exist in Windows Server 2003 and greater
#endif
#if (_WIN32_WINNT >= 0x0502)
    CachedRemoteInteractive, // Same as RemoteInteractive, this is used internally for auditing purpose
    CachedUnlock        // Cached Unlock workstation
#endif
} SECURITY_LOGON_TYPE, *PSECURITY_LOGON_TYPE;

typedef ULONG LSA_OPERATIONAL_MODE, *PLSA_OPERATIONAL_MODE;

#if !defined(_NTLSA_AUDIT_)
#define _NTLSA_AUDIT_

//
// The following enumerated type is used between the reference monitor and
// LSA in the generation of audit messages.  It is used to indicate the
// type of data being passed as a parameter from the reference monitor
// to LSA.  LSA is responsible for transforming the specified data type
// into a set of unicode strings that are added to the event record in
// the audit log.
//

typedef enum _SE_ADT_PARAMETER_TYPE {

    SeAdtParmTypeNone = 0,          //Produces 1 parameter
    SeAdtParmTypeString,            //Produces 1 parameter.
    SeAdtParmTypeFileSpec,
		SeAdtParmTypeUlong,             //Produces 1 parameter
    SeAdtParmTypeSid,               //Produces 1 parameter.
    SeAdtParmTypeLogonId,           //Produces 4 parameters.
    SeAdtParmTypeNoLogonId,         //Produces 3 parameters.
    SeAdtParmTypeAccessMask,        //Produces 1 parameter with formatting.
    SeAdtParmTypePrivs,             //Produces 1 parameter with formatting.
    SeAdtParmTypeObjectTypes,       //Produces 10 parameters with formatting.
    SeAdtParmTypeHexUlong,          //Produces 1 parameter
    SeAdtParmTypePtr,               //Produces 1 parameter
    SeAdtParmTypeTime,              //Produces 2 parameters
    SeAdtParmTypeGuid,              //Produces 1 parameter
    SeAdtParmTypeLuid,              //
    SeAdtParmTypeHexInt64,          //Produces 1 parameter
    SeAdtParmTypeStringList,        //Produces 1 parameter
    SeAdtParmTypeSidList,           //Produces 1 parameter
    SeAdtParmTypeDuration,          //Produces 1 parameters
    SeAdtParmTypeUserAccountControl,//Produces 3 parameters
    SeAdtParmTypeNoUac,             //Produces 3 parameters
    SeAdtParmTypeMessage,           //Produces 1 Parameter
    SeAdtParmTypeDateTime,          //Produces 1 Parameter
    SeAdtParmTypeSockAddr,          // Produces 2 parameters
    SeAdtParmTypeSD,                // Produces 1 parameters
    SeAdtParmTypeLogonHours,        // Produces 1 parameters
    SeAdtParmTypeLogonIdNoSid,      //Produces 3 parameters.
    SeAdtParmTypeUlongNoConv,       // Produces 1 parameter.
    SeAdtParmTypeSockAddrNoPort,     // Produces 1 parameter
    SeAdtParmTypeAccessReason

} SE_ADT_PARAMETER_TYPE, *PSE_ADT_PARAMETER_TYPE;

#if !defined(GUID_DEFINED)
#include <guiddef.h>
#endif /* GUID_DEFINED */

typedef struct _SE_ADT_OBJECT_TYPE {
    GUID ObjectType;
    USHORT Flags;
#define SE_ADT_OBJECT_ONLY 0x1
    USHORT Level;
    ACCESS_MASK AccessMask;
} SE_ADT_OBJECT_TYPE, *PSE_ADT_OBJECT_TYPE;

typedef struct _SE_ADT_PARAMETER_ARRAY_ENTRY {

    SE_ADT_PARAMETER_TYPE Type;
    ULONG Length;
    ULONG_PTR Data[2];
    PVOID Address;
} SE_ADT_PARAMETER_ARRAY_ENTRY, *PSE_ADT_PARAMETER_ARRAY_ENTRY;


typedef struct _SE_ADT_ACCESS_REASON{
    ACCESS_MASK AccessMask;
    ULONG  AccessReasons[32];
    ULONG  ObjectTypeIndex;
    ULONG AccessGranted;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
} SE_ADT_ACCESS_REASON, *PSE_ADT_ACCESS_REASON;

#define SE_MAX_AUDIT_PARAMETERS 32
#define SE_MAX_GENERIC_AUDIT_PARAMETERS 28

typedef struct _SE_ADT_PARAMETER_ARRAY {

    ULONG CategoryId;
    ULONG AuditId;
    ULONG ParameterCount;
    ULONG Length;
    USHORT FlatSubCategoryId;
    USHORT Type;
    ULONG Flags;
    SE_ADT_PARAMETER_ARRAY_ENTRY Parameters[ SE_MAX_AUDIT_PARAMETERS ];

} SE_ADT_PARAMETER_ARRAY, *PSE_ADT_PARAMETER_ARRAY;

#define SE_ADT_PARAMETERS_SELF_RELATIVE     0x00000001
#define SE_ADT_PARAMETERS_SEND_TO_LSA       0x00000002
#define SE_ADT_PARAMETER_EXTENSIBLE_AUDIT   0x00000004
#define SE_ADT_PARAMETER_GENERIC_AUDIT      0x00000008
#define SE_ADT_PARAMETER_WRITE_SYNCHRONOUS  0x00000010

#define LSAP_SE_ADT_PARAMETER_ARRAY_TRUE_SIZE(AuditParameters)    \
     ( sizeof(SE_ADT_PARAMETER_ARRAY) -                           \
       sizeof(SE_ADT_PARAMETER_ARRAY_ENTRY) *                     \
       (SE_MAX_AUDIT_PARAMETERS - AuditParameters->ParameterCount) )

#endif // !defined(_NTLSA_AUDIT_)

typedef enum _POLICY_AUDIT_EVENT_TYPE {

    AuditCategorySystem = 0,
    AuditCategoryLogon,
    AuditCategoryObjectAccess,
    AuditCategoryPrivilegeUse,
    AuditCategoryDetailedTracking,
    AuditCategoryPolicyChange,
    AuditCategoryAccountManagement,
    AuditCategoryDirectoryServiceAccess,
    AuditCategoryAccountLogon

} POLICY_AUDIT_EVENT_TYPE, *PPOLICY_AUDIT_EVENT_TYPE;

#define POLICY_AUDIT_EVENT_UNCHANGED       (0x00000000L)
#define POLICY_AUDIT_EVENT_SUCCESS         (0x00000001L)
#define POLICY_AUDIT_EVENT_FAILURE         (0x00000002L)
#define POLICY_AUDIT_EVENT_NONE            (0x00000004L)

#define POLICY_AUDIT_EVENT_MASK \
    (POLICY_AUDIT_EVENT_SUCCESS | \
     POLICY_AUDIT_EVENT_FAILURE | \
     POLICY_AUDIT_EVENT_UNCHANGED | \
     POLICY_AUDIT_EVENT_NONE)

#define LSA_SUCCESS(Error) ((LONG)(Error) >= 0)

NTSTATUS
NTAPI
LsaRegisterLogonProcess (
	IN PLSA_STRING LogonProcessName,
	OUT PHANDLE LsaHandle,
	OUT PLSA_OPERATIONAL_MODE SecurityMode
	);

NTSTATUS
NTAPI
LsaLogonUser (
	IN HANDLE LsaHandle,
	IN PLSA_STRING OriginName,
	IN SECURITY_LOGON_TYPE LogonType,
	IN ULONG AuthenticationPackage,
	IN PVOID AuthenticationInformation,
	IN ULONG AuthenticationInformationLength,
	IN OPTIONAL PTOKEN_GROUPS LocalGroups,
	IN PTOKEN_SOURCE SourceContext,
	OUT PVOID *ProfileBuffer,
	OUT PULONG ProfileBufferLength,
	OUT PLUID LogonId,
	OUT PHANDLE Token,
	OUT PQUOTA_LIMITS Quotas,
	OUT PNTSTATUS SubStatus
	);

NTSTATUS
NTAPI
LsaLookupAuthenticationPackage (
	IN HANDLE LsaHandle,
	IN PLSA_STRING PackageName,
	OUT PULONG AuthenticationPackage
	);

NTSTATUS
NTAPI
LsaFreeReturnBuffer (
	IN PVOID Buffer
	);

NTSTATUS
NTAPI
LsaCallAuthenticationPackage (
	IN HANDLE LsaHandle,
	IN ULONG AuthenticationPackage,
	IN PVOID ProtocolSubmitBuffer,
	IN ULONG SubmitBufferLength,
	OUT OPTIONAL PVOID *ProtocolReturnBuffer,
	OUT OPTIONAL PULONG ReturnBufferLength,
	OUT OPTIONAL PNTSTATUS ProtocolStatus
	);

NTSTATUS
NTAPI
LsaDeregisterLogonProcess (
	IN HANDLE LsaHandle
	);

NTSTATUS
NTAPI
LsaConnectUntrusted (
	OUT PHANDLE LsaHandle
	);

////////////////////////////////////////////////////////////////////////////
//                                                                        //
// Local Security Policy Administration API datatypes and defines         //
//                                                                        //
////////////////////////////////////////////////////////////////////////////

#define POLICY_VIEW_LOCAL_INFORMATION              0x00000001L
#define POLICY_VIEW_AUDIT_INFORMATION              0x00000002L
#define POLICY_GET_PRIVATE_INFORMATION             0x00000004L
#define POLICY_TRUST_ADMIN                         0x00000008L
#define POLICY_CREATE_ACCOUNT                      0x00000010L
#define POLICY_CREATE_SECRET                       0x00000020L
#define POLICY_CREATE_PRIVILEGE                    0x00000040L
#define POLICY_SET_DEFAULT_QUOTA_LIMITS            0x00000080L
#define POLICY_SET_AUDIT_REQUIREMENTS              0x00000100L
#define POLICY_AUDIT_LOG_ADMIN                     0x00000200L
#define POLICY_SERVER_ADMIN                        0x00000400L
#define POLICY_LOOKUP_NAMES                        0x00000800L
#define POLICY_NOTIFICATION                        0x00001000L

#define POLICY_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED         |\
                               POLICY_VIEW_LOCAL_INFORMATION    |\
                               POLICY_VIEW_AUDIT_INFORMATION    |\
                               POLICY_GET_PRIVATE_INFORMATION   |\
                               POLICY_TRUST_ADMIN               |\
                               POLICY_CREATE_ACCOUNT            |\
                               POLICY_CREATE_SECRET             |\
                               POLICY_CREATE_PRIVILEGE          |\
                               POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                               POLICY_SET_AUDIT_REQUIREMENTS    |\
                               POLICY_AUDIT_LOG_ADMIN           |\
                               POLICY_SERVER_ADMIN              |\
                               POLICY_LOOKUP_NAMES)


#define POLICY_READ           (STANDARD_RIGHTS_READ             |\
                               POLICY_VIEW_AUDIT_INFORMATION    |\
                               POLICY_GET_PRIVATE_INFORMATION)

#define POLICY_WRITE          (STANDARD_RIGHTS_WRITE            |\
                               POLICY_TRUST_ADMIN               |\
                               POLICY_CREATE_ACCOUNT            |\
                               POLICY_CREATE_SECRET             |\
                               POLICY_CREATE_PRIVILEGE          |\
                               POLICY_SET_DEFAULT_QUOTA_LIMITS  |\
                               POLICY_SET_AUDIT_REQUIREMENTS    |\
                               POLICY_AUDIT_LOG_ADMIN           |\
                               POLICY_SERVER_ADMIN)

#define POLICY_EXECUTE        (STANDARD_RIGHTS_EXECUTE          |\
                               POLICY_VIEW_LOCAL_INFORMATION    |\
                               POLICY_LOOKUP_NAMES)

typedef struct _LSA_TRANSLATED_SID {

    SID_NAME_USE Use;
    ULONG RelativeId;
    LONG DomainIndex;

} LSA_TRANSLATED_SID, *PLSA_TRANSLATED_SID;

typedef enum _POLICY_LSA_SERVER_ROLE {

    PolicyServerRoleBackup = 2,
    PolicyServerRolePrimary

} POLICY_LSA_SERVER_ROLE, *PPOLICY_LSA_SERVER_ROLE;

#if (_WIN32_WINNT < 0x0502)

typedef enum _POLICY_SERVER_ENABLE_STATE {

    PolicyServerEnabled = 2,
    PolicyServerDisabled

} POLICY_SERVER_ENABLE_STATE, *PPOLICY_SERVER_ENABLE_STATE;
#endif

typedef ULONG POLICY_AUDIT_EVENT_OPTIONS, *PPOLICY_AUDIT_EVENT_OPTIONS;

typedef enum _POLICY_INFORMATION_CLASS {

    PolicyAuditLogInformation = 1,
    PolicyAuditEventsInformation,
    PolicyPrimaryDomainInformation,
    PolicyPdAccountInformation,
    PolicyAccountDomainInformation,
    PolicyLsaServerRoleInformation,
    PolicyReplicaSourceInformation,
    PolicyDefaultQuotaInformation,
    PolicyModificationInformation,
    PolicyAuditFullSetInformation,
    PolicyAuditFullQueryInformation,
    PolicyDnsDomainInformation,
    PolicyDnsDomainInformationInt,
    PolicyLocalAccountDomainInformation,
    PolicyLastEntry

} POLICY_INFORMATION_CLASS, *PPOLICY_INFORMATION_CLASS;

typedef struct _POLICY_AUDIT_LOG_INFO {

    ULONG AuditLogPercentFull;
    ULONG MaximumLogSize;
    LARGE_INTEGER AuditRetentionPeriod;
    BOOLEAN AuditLogFullShutdownInProgress;
    LARGE_INTEGER TimeToShutdown;
    ULONG NextAuditRecordId;

} POLICY_AUDIT_LOG_INFO, *PPOLICY_AUDIT_LOG_INFO;

typedef struct _POLICY_AUDIT_EVENTS_INFO {

    BOOLEAN AuditingMode;
    PPOLICY_AUDIT_EVENT_OPTIONS EventAuditingOptions;
    ULONG MaximumAuditEventCount;

} POLICY_AUDIT_EVENTS_INFO, *PPOLICY_AUDIT_EVENTS_INFO;

typedef struct _POLICY_AUDIT_SUBCATEGORIES_INFO {

    ULONG MaximumSubCategoryCount;
    PPOLICY_AUDIT_EVENT_OPTIONS EventAuditingOptions;

} POLICY_AUDIT_SUBCATEGORIES_INFO, *PPOLICY_AUDIT_SUBCATEGORIES_INFO;

typedef struct _POLICY_AUDIT_CATEGORIES_INFO {

    ULONG MaximumCategoryCount;
    PPOLICY_AUDIT_SUBCATEGORIES_INFO SubCategoriesInfo;

} POLICY_AUDIT_CATEGORIES_INFO, *PPOLICY_AUDIT_CATEGORIES_INFO;

//
// Valid bits for Per user policy mask.
//

#define PER_USER_POLICY_UNCHANGED               (0x00)
#define PER_USER_AUDIT_SUCCESS_INCLUDE          (0x01)
#define PER_USER_AUDIT_SUCCESS_EXCLUDE          (0x02)
#define PER_USER_AUDIT_FAILURE_INCLUDE          (0x04)
#define PER_USER_AUDIT_FAILURE_EXCLUDE          (0x08)
#define PER_USER_AUDIT_NONE                     (0x10)


#define VALID_PER_USER_AUDIT_POLICY_FLAG (PER_USER_AUDIT_SUCCESS_INCLUDE | \
                                          PER_USER_AUDIT_SUCCESS_EXCLUDE | \
                                          PER_USER_AUDIT_FAILURE_INCLUDE | \
                                          PER_USER_AUDIT_FAILURE_EXCLUDE | \
                                          PER_USER_AUDIT_NONE)

typedef struct _POLICY_PRIMARY_DOMAIN_INFO {

    LSA_UNICODE_STRING Name;
    PSID Sid;

} POLICY_PRIMARY_DOMAIN_INFO, *PPOLICY_PRIMARY_DOMAIN_INFO;

typedef struct _POLICY_PD_ACCOUNT_INFO {

    LSA_UNICODE_STRING Name;

} POLICY_PD_ACCOUNT_INFO, *PPOLICY_PD_ACCOUNT_INFO;

typedef struct _POLICY_LSA_SERVER_ROLE_INFO {

    POLICY_LSA_SERVER_ROLE LsaServerRole;

} POLICY_LSA_SERVER_ROLE_INFO, *PPOLICY_LSA_SERVER_ROLE_INFO;

typedef struct _POLICY_REPLICA_SOURCE_INFO {

    LSA_UNICODE_STRING ReplicaSource;
    LSA_UNICODE_STRING ReplicaAccountName;

} POLICY_REPLICA_SOURCE_INFO, *PPOLICY_REPLICA_SOURCE_INFO;

typedef struct _POLICY_DEFAULT_QUOTA_INFO {

    QUOTA_LIMITS QuotaLimits;

} POLICY_DEFAULT_QUOTA_INFO, *PPOLICY_DEFAULT_QUOTA_INFO;


typedef struct _POLICY_MODIFICATION_INFO {

    LARGE_INTEGER ModifiedId;
    LARGE_INTEGER DatabaseCreationTime;

} POLICY_MODIFICATION_INFO, *PPOLICY_MODIFICATION_INFO;


typedef struct _POLICY_AUDIT_FULL_SET_INFO {

    BOOLEAN ShutDownOnFull;

} POLICY_AUDIT_FULL_SET_INFO, *PPOLICY_AUDIT_FULL_SET_INFO;


typedef struct _POLICY_AUDIT_FULL_QUERY_INFO {

    BOOLEAN ShutDownOnFull;
    BOOLEAN LogIsFull;

} POLICY_AUDIT_FULL_QUERY_INFO, *PPOLICY_AUDIT_FULL_QUERY_INFO;


typedef enum _POLICY_DOMAIN_INFORMATION_CLASS {

#if (_WIN32_WINNT <= 0x0500)
    PolicyDomainQualityOfServiceInformation = 1,
#endif
    PolicyDomainEfsInformation = 2,
    PolicyDomainKerberosTicketInformation

} POLICY_DOMAIN_INFORMATION_CLASS, *PPOLICY_DOMAIN_INFORMATION_CLASS;

#if (_WIN32_WINNT < 0x0502)

#define POLICY_QOS_SCHANNEL_REQUIRED            0x00000001
#define POLICY_QOS_OUTBOUND_INTEGRITY           0x00000002
#define POLICY_QOS_OUTBOUND_CONFIDENTIALITY     0x00000004
#define POLICY_QOS_INBOUND_INTEGRITY            0x00000008
#define POLICY_QOS_INBOUND_CONFIDENTIALITY      0x00000010
#define POLICY_QOS_ALLOW_LOCAL_ROOT_CERT_STORE  0x00000020
#define POLICY_QOS_RAS_SERVER_ALLOWED           0x00000040
#define POLICY_QOS_DHCP_SERVER_ALLOWED          0x00000080

//
// Bits 0x00000100 through 0xFFFFFFFF are reserved for future use.
//
#endif

#if (_WIN32_WINNT == 0x0500)
typedef struct _POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO {

    ULONG QualityOfService;

} POLICY_DOMAIN_QUALITY_OF_SERVICE_INFO, *PPOLICY_DOMAIN_QUALITY_OF_SERVICE_INFO;

#endif

typedef struct _POLICY_DOMAIN_EFS_INFO {

    ULONG   InfoLength;
    PUCHAR  EfsBlob;

} POLICY_DOMAIN_EFS_INFO, *PPOLICY_DOMAIN_EFS_INFO;

#define POLICY_KERBEROS_VALIDATE_CLIENT 0x00000080

typedef struct _POLICY_DOMAIN_KERBEROS_TICKET_INFO {

    ULONG AuthenticationOptions;
    LARGE_INTEGER MaxServiceTicketAge;
    LARGE_INTEGER MaxTicketAge;
    LARGE_INTEGER MaxRenewAge;
    LARGE_INTEGER MaxClockSkew;
    LARGE_INTEGER Reserved;
} POLICY_DOMAIN_KERBEROS_TICKET_INFO, *PPOLICY_DOMAIN_KERBEROS_TICKET_INFO;

typedef enum _POLICY_NOTIFICATION_INFORMATION_CLASS {

    PolicyNotifyAuditEventsInformation = 1,
    PolicyNotifyAccountDomainInformation,
    PolicyNotifyServerRoleInformation,
    PolicyNotifyDnsDomainInformation,
    PolicyNotifyDomainEfsInformation,
    PolicyNotifyDomainKerberosTicketInformation,
    PolicyNotifyMachineAccountPasswordInformation,
    PolicyNotifyGlobalSaclInformation,
    PolicyNotifyMax // must always be the last entry

} POLICY_NOTIFICATION_INFORMATION_CLASS, *PPOLICY_NOTIFICATION_INFORMATION_CLASS;

typedef PVOID LSA_HANDLE, *PLSA_HANDLE;

typedef enum _TRUSTED_INFORMATION_CLASS {

    TrustedDomainNameInformation = 1,
    TrustedControllersInformation,
    TrustedPosixOffsetInformation,
    TrustedPasswordInformation,
    TrustedDomainInformationBasic,
    TrustedDomainInformationEx,
    TrustedDomainAuthInformation,
    TrustedDomainFullInformation,
    TrustedDomainAuthInformationInternal,
    TrustedDomainFullInformationInternal,
    TrustedDomainInformationEx2Internal,
    TrustedDomainFullInformation2Internal,
    TrustedDomainSupportedEncryptionTypes,
} TRUSTED_INFORMATION_CLASS, *PTRUSTED_INFORMATION_CLASS;

typedef struct _TRUSTED_DOMAIN_NAME_INFO {

    LSA_UNICODE_STRING Name;

} TRUSTED_DOMAIN_NAME_INFO, *PTRUSTED_DOMAIN_NAME_INFO;

typedef struct _TRUSTED_CONTROLLERS_INFO {

    ULONG Entries;
    PLSA_UNICODE_STRING Names;

} TRUSTED_CONTROLLERS_INFO, *PTRUSTED_CONTROLLERS_INFO;

typedef struct _TRUSTED_POSIX_OFFSET_INFO {

    ULONG Offset;

} TRUSTED_POSIX_OFFSET_INFO, *PTRUSTED_POSIX_OFFSET_INFO;

typedef struct _TRUSTED_PASSWORD_INFO {
    LSA_UNICODE_STRING Password;
    LSA_UNICODE_STRING OldPassword;
} TRUSTED_PASSWORD_INFO, *PTRUSTED_PASSWORD_INFO;

typedef  LSA_TRUST_INFORMATION TRUSTED_DOMAIN_INFORMATION_BASIC;
typedef PLSA_TRUST_INFORMATION PTRUSTED_DOMAIN_INFORMATION_BASIC;

#define TRUST_DIRECTION_DISABLED        0x00000000
#define TRUST_DIRECTION_INBOUND         0x00000001
#define TRUST_DIRECTION_OUTBOUND        0x00000002
#define TRUST_DIRECTION_BIDIRECTIONAL   (TRUST_DIRECTION_INBOUND | TRUST_DIRECTION_OUTBOUND)

#define TRUST_TYPE_DOWNLEVEL            0x00000001  // NT4 and before
#define TRUST_TYPE_UPLEVEL              0x00000002  // NT5
#define TRUST_TYPE_MIT                  0x00000003  // Trust with a MIT Kerberos realm

#if (_WIN32_WINNT < 0x0502)
#define TRUST_TYPE_DCE                  0x00000004  // Trust with a DCE realm
#endif

// Levels 0x5 - 0x000FFFFF reserved for future use
// Provider specific trust levels are from 0x00100000 to 0xFFF00000

#define TRUST_ATTRIBUTE_NON_TRANSITIVE                0x00000001  // Disallow transitivity
#define TRUST_ATTRIBUTE_UPLEVEL_ONLY                  0x00000002  // Trust link only valid for uplevel client
#if (_WIN32_WINNT == 0x0500)
#define TRUST_ATTRIBUTE_TREE_PARENT     0x00400000  // Denotes that we are setting the trust
                                                    // to our parent in the org tree...
#define TRUST_ATTRIBUTE_TREE_ROOT       0x00800000  // Denotes that we are setting the trust
                                                    // to another tree root in a forest...
// Trust attributes 0x00000004 through 0x004FFFFF reserved for future use
// Trust attributes 0x00F00000 through 0x00400000 are reserved for internal use
// Trust attributes 0x01000000 through 0xFF000000 are reserved for user
#define TRUST_ATTRIBUTES_VALID  0xFF02FFFF
#endif

#if (_WIN32_WINNT < 0x0502)
#define TRUST_ATTRIBUTE_FILTER_SIDS        0x00000004  // Used to quarantine domains
#else
#define TRUST_ATTRIBUTE_QUARANTINED_DOMAIN            0x00000004  // Used to quarantine domains
#endif

#if (_WIN32_WINNT >= 0x0501)
#define TRUST_ATTRIBUTE_FOREST_TRANSITIVE             0x00000008  // This link may contain forest trust information
#if (_WIN32_WINNT >= 0x0502)
#define TRUST_ATTRIBUTE_CROSS_ORGANIZATION            0x00000010  // This trust is to a domain/forest which is not part of this enterprise
#define TRUST_ATTRIBUTE_WITHIN_FOREST                 0x00000020  // Trust is internal to this forest
#define TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL             0x00000040  // Trust is to be treated as external for trust boundary purposes
#if (_WIN32_WINNT >= 0x0600)
#define TRUST_ATTRIBUTE_TRUST_USES_RC4_ENCRYPTION     0x00000080  // MIT trust with RC4
#define TRUST_ATTRIBUTE_TRUST_USES_AES_KEYS           0x00000100  // Use AES keys to encrypte KRB TGTs
#endif
// Trust attributes 0x00000040 through 0x00200000 are reserved for future use
#else
// Trust attributes 0x00000010 through 0x00200000 are reserved for future use
#endif
// Trust attributes 0x00400000 through 0x00800000 were used previously (up to W2K) and should not be re-used
// Trust attributes 0x01000000 through 0x80000000 are reserved for user
#define TRUST_ATTRIBUTES_VALID          0xFF03FFFF
#endif
#define TRUST_ATTRIBUTES_USER           0xFF000000

typedef struct _TRUSTED_DOMAIN_INFORMATION_EX {

    LSA_UNICODE_STRING Name;
    LSA_UNICODE_STRING FlatName;
    PSID  Sid;
    ULONG TrustDirection;
    ULONG TrustType;
    ULONG TrustAttributes;

} TRUSTED_DOMAIN_INFORMATION_EX, *PTRUSTED_DOMAIN_INFORMATION_EX;

typedef struct _TRUSTED_DOMAIN_INFORMATION_EX2 {

    LSA_UNICODE_STRING Name;
    LSA_UNICODE_STRING FlatName;
    PSID  Sid;
    ULONG TrustDirection;
    ULONG TrustType;
    ULONG TrustAttributes;
    ULONG ForestTrustLength;
#ifdef MIDL_PASS
    [size_is( ForestTrustLength )]
#endif
    PUCHAR ForestTrustInfo;

} TRUSTED_DOMAIN_INFORMATION_EX2, *PTRUSTED_DOMAIN_INFORMATION_EX2;

#define TRUST_AUTH_TYPE_NONE    0   // Ignore this entry
#define TRUST_AUTH_TYPE_NT4OWF  1   // NT4 OWF password
#define TRUST_AUTH_TYPE_CLEAR   2   // Cleartext password
#define TRUST_AUTH_TYPE_VERSION 3   // Cleartext password version number

typedef struct _LSA_AUTH_INFORMATION {

    LARGE_INTEGER LastUpdateTime;
    ULONG AuthType;
    ULONG AuthInfoLength;
    PUCHAR AuthInfo;
} LSA_AUTH_INFORMATION, *PLSA_AUTH_INFORMATION;

typedef struct _TRUSTED_DOMAIN_AUTH_INFORMATION {

    ULONG IncomingAuthInfos;
    PLSA_AUTH_INFORMATION   IncomingAuthenticationInformation;
    PLSA_AUTH_INFORMATION   IncomingPreviousAuthenticationInformation;
    ULONG OutgoingAuthInfos;
    PLSA_AUTH_INFORMATION   OutgoingAuthenticationInformation;
    PLSA_AUTH_INFORMATION   OutgoingPreviousAuthenticationInformation;

} TRUSTED_DOMAIN_AUTH_INFORMATION, *PTRUSTED_DOMAIN_AUTH_INFORMATION;

typedef struct _TRUSTED_DOMAIN_FULL_INFORMATION {

    TRUSTED_DOMAIN_INFORMATION_EX   Information;
    TRUSTED_POSIX_OFFSET_INFO       PosixOffset;
    TRUSTED_DOMAIN_AUTH_INFORMATION AuthInformation;

} TRUSTED_DOMAIN_FULL_INFORMATION, *PTRUSTED_DOMAIN_FULL_INFORMATION;

typedef struct _TRUSTED_DOMAIN_FULL_INFORMATION2 {

    TRUSTED_DOMAIN_INFORMATION_EX2  Information;
    TRUSTED_POSIX_OFFSET_INFO       PosixOffset;
    TRUSTED_DOMAIN_AUTH_INFORMATION AuthInformation;

} TRUSTED_DOMAIN_FULL_INFORMATION2, *PTRUSTED_DOMAIN_FULL_INFORMATION2;

typedef struct _TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES {

	ULONG SupportedEncryptionTypes;

} TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES, *PTRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES;

typedef enum {

    ForestTrustTopLevelName,
    ForestTrustTopLevelNameEx,
    ForestTrustDomainInfo,
    ForestTrustRecordTypeLast = ForestTrustDomainInfo

} LSA_FOREST_TRUST_RECORD_TYPE;

#if (_WIN32_WINNT < 0x0502)
#define LSA_FOREST_TRUST_RECORD_TYPE_UNRECOGNIZED 0x80000000
#endif

//
// Bottom 16 bits of the flags are reserved for disablement reasons
//

#define LSA_FTRECORD_DISABLED_REASONS            ( 0x0000FFFFL )

//
// Reasons for a top-level name forest trust record to be disabled
//

#define LSA_TLN_DISABLED_NEW                     ( 0x00000001L )
#define LSA_TLN_DISABLED_ADMIN                   ( 0x00000002L )
#define LSA_TLN_DISABLED_CONFLICT                ( 0x00000004L )

//
// Reasons for a domain information forest trust record to be disabled
//

#define LSA_SID_DISABLED_ADMIN                   ( 0x00000001L )
#define LSA_SID_DISABLED_CONFLICT                ( 0x00000002L )
#define LSA_NB_DISABLED_ADMIN                    ( 0x00000004L )
#define LSA_NB_DISABLED_CONFLICT                 ( 0x00000008L )

typedef struct _LSA_FOREST_TRUST_DOMAIN_INFO {

#ifdef MIDL_PASS
    PISID Sid;
#else
    PSID Sid;
#endif
    LSA_UNICODE_STRING DnsName;
    LSA_UNICODE_STRING NetbiosName;

} LSA_FOREST_TRUST_DOMAIN_INFO, *PLSA_FOREST_TRUST_DOMAIN_INFO;


#if (_WIN32_WINNT >= 0x0502)
//
//  To prevent huge data to be passed in, we should put a limit on LSA_FOREST_TRUST_BINARY_DATA.
//      128K is large enough that can't be reached in the near future, and small enough not to
//      cause memory problems.

#define MAX_FOREST_TRUST_BINARY_DATA_SIZE ( 128 * 1024 )
#endif

typedef struct _LSA_FOREST_TRUST_BINARY_DATA {

#ifdef MIDL_PASS
    [range(0, MAX_FOREST_TRUST_BINARY_DATA_SIZE)] ULONG Length;
    [size_is( Length )] PUCHAR Buffer;
#else
    ULONG Length;
    PUCHAR Buffer;
#endif

} LSA_FOREST_TRUST_BINARY_DATA, *PLSA_FOREST_TRUST_BINARY_DATA;

typedef struct _LSA_FOREST_TRUST_RECORD {

    ULONG Flags;
    LSA_FOREST_TRUST_RECORD_TYPE ForestTrustType; // type of record
    LARGE_INTEGER Time;

#ifdef MIDL_PASS
    [switch_type( LSA_FOREST_TRUST_RECORD_TYPE ), switch_is( ForestTrustType )]
#endif

    union {                                       // actual data

#ifdef MIDL_PASS
        [case( ForestTrustTopLevelName,
               ForestTrustTopLevelNameEx )] LSA_UNICODE_STRING TopLevelName;
        [case( ForestTrustDomainInfo )] LSA_FOREST_TRUST_DOMAIN_INFO DomainInfo;
        [default] LSA_FOREST_TRUST_BINARY_DATA Data;
#else
        LSA_UNICODE_STRING TopLevelName;
        LSA_FOREST_TRUST_DOMAIN_INFO DomainInfo;
        LSA_FOREST_TRUST_BINARY_DATA Data;        // used for unrecognized types
#endif
    } ForestTrustData;

} LSA_FOREST_TRUST_RECORD, *PLSA_FOREST_TRUST_RECORD;

#if (_WIN32_WINNT >= 0x0502)
//
// To prevent forest trust blobs of large size, number of records must be
// smaller than MAX_RECORDS_IN_FOREST_TRUST_INFO
//

#define MAX_RECORDS_IN_FOREST_TRUST_INFO 4000
#endif

typedef struct _LSA_FOREST_TRUST_INFORMATION {

#ifdef MIDL_PASS
    [range(0, MAX_RECORDS_IN_FOREST_TRUST_INFO)] ULONG RecordCount;
    [size_is( RecordCount )] PLSA_FOREST_TRUST_RECORD * Entries;
#else
    ULONG RecordCount;
    PLSA_FOREST_TRUST_RECORD * Entries;
#endif

} LSA_FOREST_TRUST_INFORMATION, *PLSA_FOREST_TRUST_INFORMATION;

typedef enum {

    CollisionTdo,
    CollisionXref,
    CollisionOther

} LSA_FOREST_TRUST_COLLISION_RECORD_TYPE;

typedef struct _LSA_FOREST_TRUST_COLLISION_RECORD {

    ULONG Index;
    LSA_FOREST_TRUST_COLLISION_RECORD_TYPE Type;
    ULONG Flags;
    LSA_UNICODE_STRING Name;

} LSA_FOREST_TRUST_COLLISION_RECORD, *PLSA_FOREST_TRUST_COLLISION_RECORD;

typedef struct _LSA_FOREST_TRUST_COLLISION_INFORMATION {

    ULONG RecordCount;
#ifdef MIDL_PASS
    [size_is( RecordCount )]
#endif
    PLSA_FOREST_TRUST_COLLISION_RECORD * Entries;

} LSA_FOREST_TRUST_COLLISION_INFORMATION, *PLSA_FOREST_TRUST_COLLISION_INFORMATION;


//
// LSA Enumeration Context
//

typedef ULONG LSA_ENUMERATION_HANDLE, *PLSA_ENUMERATION_HANDLE;

//
// LSA Enumeration Information
//

typedef struct _LSA_ENUMERATION_INFORMATION {

    PSID Sid;

} LSA_ENUMERATION_INFORMATION, *PLSA_ENUMERATION_INFORMATION;


////////////////////////////////////////////////////////////////////////////
//                                                                        //
// Local Security Policy - Miscellaneous API function prototypes          //
//                                                                        //
////////////////////////////////////////////////////////////////////////////


NTSTATUS
NTAPI
LsaFreeMemory(
	IN OPTIONAL PVOID Buffer
	);

NTSTATUS
NTAPI
LsaClose(
	IN LSA_HANDLE ObjectHandle
	);

#if (_WIN32_WINNT >= 0x0600)

typedef struct _LSA_LAST_INTER_LOGON_INFO {
    LARGE_INTEGER LastSuccessfulLogon;
    LARGE_INTEGER LastFailedLogon;
    ULONG FailedAttemptCountSinceLastSuccessfulLogon;
} LSA_LAST_INTER_LOGON_INFO, *PLSA_LAST_INTER_LOGON_INFO;

#endif

#if (_WIN32_WINNT >= 0x0501)
typedef struct _SECURITY_LOGON_SESSION_DATA {
    ULONG               Size;
    LUID                LogonId;
    LSA_UNICODE_STRING  UserName;
    LSA_UNICODE_STRING  LogonDomain;
    LSA_UNICODE_STRING  AuthenticationPackage;
    ULONG               LogonType;
    ULONG               Session;
    PSID                Sid;
    LARGE_INTEGER       LogonTime;

    LSA_UNICODE_STRING  LogonServer;
    LSA_UNICODE_STRING  DnsDomainName;
    LSA_UNICODE_STRING  Upn;

#if (_WIN32_WINNT >= 0x0600)

    ULONG UserFlags;

    LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
    LSA_UNICODE_STRING LogonScript;
    LSA_UNICODE_STRING ProfilePath;
    LSA_UNICODE_STRING HomeDirectory;
    LSA_UNICODE_STRING HomeDirectoryDrive;

    LARGE_INTEGER LogoffTime;
    LARGE_INTEGER KickOffTime;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;

#endif
} SECURITY_LOGON_SESSION_DATA, * PSECURITY_LOGON_SESSION_DATA;

NTSTATUS
NTAPI
LsaEnumerateLogonSessions(
	OUT PULONG  LogonSessionCount,
	OUT PLUID * LogonSessionList
	);

NTSTATUS
NTAPI
LsaGetLogonSessionData(
	IN PLUID LogonId,
	OUT PSECURITY_LOGON_SESSION_DATA * ppLogonSessionData
	);

#endif
NTSTATUS
NTAPI
LsaOpenPolicy(
	IN OPTIONAL PLSA_UNICODE_STRING SystemName,
	IN PLSA_OBJECT_ATTRIBUTES ObjectAttributes,
	IN ACCESS_MASK DesiredAccess,
	OUT PLSA_HANDLE PolicyHandle
	);


NTSTATUS
NTAPI
LsaQueryInformationPolicy(
	IN LSA_HANDLE PolicyHandle,
	IN POLICY_INFORMATION_CLASS InformationClass,
	OUT PVOID *Buffer
	);

NTSTATUS
NTAPI
LsaSetInformationPolicy(
	IN LSA_HANDLE PolicyHandle,
	IN POLICY_INFORMATION_CLASS InformationClass,
	IN PVOID Buffer
	);

NTSTATUS
NTAPI
LsaQueryDomainInformationPolicy(
	IN LSA_HANDLE PolicyHandle,
	IN POLICY_DOMAIN_INFORMATION_CLASS InformationClass,
	OUT PVOID *Buffer
	);

NTSTATUS
NTAPI
LsaSetDomainInformationPolicy(
	IN LSA_HANDLE PolicyHandle,
	IN POLICY_DOMAIN_INFORMATION_CLASS InformationClass,
	IN OPTIONAL PVOID Buffer
	);

NTSTATUS
NTAPI
LsaRegisterPolicyChangeNotification(
	IN POLICY_NOTIFICATION_INFORMATION_CLASS InformationClass,
	IN HANDLE NotificationEventHandle
	);

NTSTATUS
NTAPI
LsaUnregisterPolicyChangeNotification(
	IN POLICY_NOTIFICATION_INFORMATION_CLASS InformationClass,
	IN HANDLE NotificationEventHandle
	);

NTSTATUS
NTAPI
LsaEnumerateTrustedDomains(
	IN LSA_HANDLE PolicyHandle,
	IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
	OUT PVOID *Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
	);

NTSTATUS
NTAPI
LsaLookupNames(
	IN LSA_HANDLE PolicyHandle,
	IN ULONG Count,
	IN PLSA_UNICODE_STRING Names,
	OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	OUT PLSA_TRANSLATED_SID *Sids
	);

#if (_WIN32_WINNT >= 0x0501)
NTSTATUS
NTAPI
LsaLookupNames2(
	IN LSA_HANDLE PolicyHandle,
	IN ULONG Flags, // Reserved
	IN ULONG Count,
	IN PLSA_UNICODE_STRING Names,
	OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	OUT PLSA_TRANSLATED_SID2 *Sids
	);
#endif

NTSTATUS
NTAPI
LsaLookupSids(
	IN LSA_HANDLE PolicyHandle,
	IN ULONG Count,
	IN PSID *Sids,
	OUT PLSA_REFERENCED_DOMAIN_LIST *ReferencedDomains,
	OUT PLSA_TRANSLATED_NAME *Names
	);

#define SE_INTERACTIVE_LOGON_NAME           TEXT("SeInteractiveLogonRight")
#define SE_NETWORK_LOGON_NAME               TEXT("SeNetworkLogonRight")
#define SE_BATCH_LOGON_NAME                 TEXT("SeBatchLogonRight")
#define SE_SERVICE_LOGON_NAME               TEXT("SeServiceLogonRight")
#define SE_DENY_INTERACTIVE_LOGON_NAME      TEXT("SeDenyInteractiveLogonRight")
#define SE_DENY_NETWORK_LOGON_NAME          TEXT("SeDenyNetworkLogonRight")
#define SE_DENY_BATCH_LOGON_NAME            TEXT("SeDenyBatchLogonRight")
#define SE_DENY_SERVICE_LOGON_NAME          TEXT("SeDenyServiceLogonRight")
#if (_WIN32_WINNT >= 0x0501)
#define SE_REMOTE_INTERACTIVE_LOGON_NAME    TEXT("SeRemoteInteractiveLogonRight")
#define SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME TEXT("SeDenyRemoteInteractiveLogonRight")
#endif

NTSTATUS
NTAPI
LsaEnumerateAccountsWithUserRight(
	IN LSA_HANDLE PolicyHandle,
	IN OPTIONAL PLSA_UNICODE_STRING UserRight,
	OUT PVOID *Buffer,
	OUT PULONG CountReturned
	);

NTSTATUS
NTAPI
LsaEnumerateAccountRights(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	OUT PLSA_UNICODE_STRING *UserRights,
	OUT PULONG CountOfRights
	);

NTSTATUS
NTAPI
LsaAddAccountRights(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN PLSA_UNICODE_STRING UserRights,
	IN ULONG CountOfRights
	);

NTSTATUS
NTAPI
LsaRemoveAccountRights(
	IN LSA_HANDLE PolicyHandle,
	IN PSID AccountSid,
	IN BOOLEAN AllRights,
	IN LSA_UNICODE_STRING UserRights,
	IN ULONG CountOfRights
	);

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Local Security Policy - Trusted Domain Object API function prototypes     //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
LsaOpenTrustedDomainByName(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING TrustedDomainName,
	IN ACCESS_MASK DesiredAccess,
	OUT PLSA_HANDLE TrustedDomainHandle
	);

NTSTATUS
NTAPI
LsaQueryTrustedDomainInfo(
	IN LSA_HANDLE PolicyHandle,
	IN PSID TrustedDomainSid,
	IN TRUSTED_INFORMATION_CLASS InformationClass,
	OUT PVOID *Buffer
	);

NTSTATUS
NTAPI
LsaSetTrustedDomainInformation(
	IN LSA_HANDLE PolicyHandle,
	IN PSID TrustedDomainSid,
	IN TRUSTED_INFORMATION_CLASS InformationClass,
	IN PVOID Buffer
	);

NTSTATUS
NTAPI
LsaDeleteTrustedDomain(
	IN LSA_HANDLE PolicyHandle,
	IN PSID TrustedDomainSid
	);

NTSTATUS
NTAPI
LsaQueryTrustedDomainInfoByName(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING TrustedDomainName,
	IN TRUSTED_INFORMATION_CLASS InformationClass,
	OUT PVOID *Buffer
	);

NTSTATUS
NTAPI
LsaSetTrustedDomainInfoByName(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING TrustedDomainName,
	IN TRUSTED_INFORMATION_CLASS InformationClass,
	IN PVOID Buffer
	);

NTSTATUS
NTAPI
LsaEnumerateTrustedDomainsEx(
	IN LSA_HANDLE PolicyHandle,
	IN OUT PLSA_ENUMERATION_HANDLE EnumerationContext,
	OUT PVOID *Buffer,
	IN ULONG PreferedMaximumLength,
	OUT PULONG CountReturned
	);

NTSTATUS
NTAPI
LsaCreateTrustedDomainEx(
	IN LSA_HANDLE PolicyHandle,
	IN PTRUSTED_DOMAIN_INFORMATION_EX TrustedDomainInformation,
	IN PTRUSTED_DOMAIN_AUTH_INFORMATION AuthenticationInformation,
	IN ACCESS_MASK DesiredAccess,
	OUT PLSA_HANDLE TrustedDomainHandle
	);

#if (_WIN32_WINNT >= 0x0501)
NTSTATUS
NTAPI
LsaQueryForestTrustInformation(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING TrustedDomainName,
	OUT PLSA_FOREST_TRUST_INFORMATION * ForestTrustInfo
	);

NTSTATUS
NTAPI
LsaSetForestTrustInformation(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING TrustedDomainName,
	IN PLSA_FOREST_TRUST_INFORMATION ForestTrustInfo,
	IN BOOLEAN CheckOnly,
	OUT PLSA_FOREST_TRUST_COLLISION_INFORMATION * CollisionInfo
	);

// #define TESTING_MATCHING_ROUTINE
#ifdef TESTING_MATCHING_ROUTINE

NTSTATUS
NTAPI
LsaForestTrustFindMatch(
	IN LSA_HANDLE PolicyHandle,
	IN ULONG Type,
	IN PLSA_UNICODE_STRING Name,
	OUT PLSA_UNICODE_STRING * Match
	);

#endif
#endif

//
// This API sets the workstation password (equivalent of setting/getting
// the SSI_SECRET_NAME secret)
//

NTSTATUS
NTAPI
LsaStorePrivateData(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING KeyName,
	IN OPTIONAL PLSA_UNICODE_STRING PrivateData
	);

NTSTATUS
NTAPI
LsaRetrievePrivateData(
	IN LSA_HANDLE PolicyHandle,
	IN PLSA_UNICODE_STRING KeyName,
	OUT PLSA_UNICODE_STRING * PrivateData
	);


ULONG
NTAPI
LsaNtStatusToWinError(
	IN NTSTATUS Status
	);

BOOL
NTAPI
ConvertSidToStringSidW(
	IN PSID Sid,
	OUT LPWSTR *StringSid
	);

#endif // _NTLSA_IFS_
// 04.06.2011 - end

//
// Driver entry management APIs.
//

typedef struct _EFI_DRIVER_ENTRY {
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
	//WCHAR FriendlyName[ANYSIZE_ARRAY];
	//FILE_PATH DriverFilePath;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef struct _EFI_DRIVER_ENTRY_LIST {
	ULONG NextEntryOffset;
	EFI_DRIVER_ENTRY DriverEntry;
} EFI_DRIVER_ENTRY_LIST, *PEFI_DRIVER_ENTRY_LIST;

#define EFI_DRIVER_ENTRY_VERSION 1
#define MAX_STACK_DEPTH 32

typedef struct _RTL_STACK_CONTEXT_ENTRY {
	ULONG_PTR Address; // stack address
	ULONG_PTR Data;    // stack contents
} RTL_STACK_CONTEXT_ENTRY, * PRTL_STACK_CONTEXT_ENTRY;

typedef struct _RTL_STACK_CONTEXT {
	ULONG NumberOfEntries;
	RTL_STACK_CONTEXT_ENTRY Entry[1];
} RTL_STACK_CONTEXT, * PRTL_STACK_CONTEXT;

typedef NTSTATUS
	(NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(
	IN PVOID Base,
	IN OUT PVOID *CommitAddress,
	IN OUT PSIZE_T CommitSize
	);

typedef struct _RTL_HEAP_PARAMETERS
{
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

#define HEAP_SETTABLE_USER_VALUE 0x00000100
#define HEAP_SETTABLE_USER_FLAG1 0x00000200
#define HEAP_SETTABLE_USER_FLAG2 0x00000400
#define HEAP_SETTABLE_USER_FLAG3 0x00000800
#define HEAP_SETTABLE_USER_FLAGS 0x00000e00

#define HEAP_CLASS_0 0x00000000 // Process heap
#define HEAP_CLASS_1 0x00001000 // Private heap
#define HEAP_CLASS_2 0x00002000 // Kernel heap
#define HEAP_CLASS_3 0x00003000 // GDI heap
#define HEAP_CLASS_4 0x00004000 // User heap
#define HEAP_CLASS_5 0x00005000 // Console heap
#define HEAP_CLASS_6 0x00006000 // User desktop heap
#define HEAP_CLASS_7 0x00007000 // CSR shared heap
#define HEAP_CLASS_8 0x00008000 // CSR port heap
#define HEAP_CLASS_MASK 0x0000f000

struct _RTL_AVL_TABLE;

typedef struct _RTL_SPLAY_LINKS {
	struct _RTL_SPLAY_LINKS *Parent;
	struct _RTL_SPLAY_LINKS *LeftChild;
	struct _RTL_SPLAY_LINKS *RightChild;
} RTL_SPLAY_LINKS;
typedef RTL_SPLAY_LINKS *PRTL_SPLAY_LINKS;

typedef enum _TABLE_SEARCH_RESULT
{
	TableEmptyTree,
	TableFoundNode,
	TableInsertAsLeft,
	TableInsertAsRight
} TABLE_SEARCH_RESULT;

typedef enum _RTL_GENERIC_COMPARE_RESULTS
{
	GenericLessThan,
	GenericGreaterThan,
	GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;

struct _RTL_AVL_TABLE;

typedef RTL_GENERIC_COMPARE_RESULTS (NTAPI *PRTL_AVL_COMPARE_ROUTINE)(
	IN struct _RTL_AVL_TABLE *Table,
	IN PVOID FirstStruct,
	IN PVOID SecondStruct
	);

typedef PVOID (NTAPI *PRTL_AVL_ALLOCATE_ROUTINE)(
	IN struct _RTL_AVL_TABLE *Table,
	IN CLONG ByteSize
	);

typedef VOID (NTAPI *PRTL_AVL_FREE_ROUTINE)(
	IN struct _RTL_AVL_TABLE *Table,
	IN	PVOID Buffer
	);

typedef NTSTATUS (NTAPI *PRTL_AVL_MATCH_FUNCTION)(
	IN struct _RTL_AVL_TABLE *Table,
	IN PVOID UserData,
	IN PVOID MatchData
	);

typedef
	RTL_GENERIC_COMPARE_RESULTS
	(NTAPI *PRTL_AVL_COMPARE_ROUTINE) (
	struct _RTL_AVL_TABLE *Table,
	PVOID FirstStruct,
	PVOID SecondStruct
	);

typedef
	PVOID
	(NTAPI *PRTL_AVL_ALLOCATE_ROUTINE) (
	struct _RTL_AVL_TABLE *Table,
	ULONG ByteSize
	);


typedef
	NTSTATUS
	(NTAPI *PRTL_AVL_MATCH_FUNCTION) (
	struct _RTL_AVL_TABLE *Table,
	PVOID UserData,
	PVOID MatchData
	);

typedef
	RTL_GENERIC_COMPARE_RESULTS
	(NTAPI *PRTL_GENERIC_COMPARE_ROUTINE) (
	struct _RTL_GENERIC_TABLE *Table,
	PVOID FirstStruct,
	PVOID SecondStruct
	);

typedef
	PVOID
	(NTAPI *PRTL_GENERIC_ALLOCATE_ROUTINE) (
	struct _RTL_GENERIC_TABLE *Table,
	ULONG ByteSize
	);

typedef
	VOID
	(NTAPI *PRTL_GENERIC_FREE_ROUTINE) (
	struct _RTL_GENERIC_TABLE *Table,
	PVOID Buffer
	);

typedef struct _RTL_BALANCED_LINKS
{
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE
{
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PRTL_AVL_COMPARE_ROUTINE CompareRoutine;
	PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine;
	PRTL_AVL_FREE_ROUTINE FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

typedef struct _RTL_GENERIC_TABLE {
	PRTL_SPLAY_LINKS TableRoot;
	LIST_ENTRY InsertOrderList;
	PLIST_ENTRY OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
	PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
	PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
	PVOID TableContext;
} RTL_GENERIC_TABLE;
typedef RTL_GENERIC_TABLE *PRTL_GENERIC_TABLE;

typedef struct _GENERATE_NAME_CONTEXT {

	USHORT Checksum;
	BOOLEAN ChecksumInserted;

	UCHAR NameLength;         // not including extension
	WCHAR NameBuffer[8];      // e.g., "ntoskrnl"

	ULONG ExtensionLength;    // including dot
	WCHAR ExtensionBuffer[4]; // e.g., ".exe"

	ULONG LastIndexValue;

} GENERATE_NAME_CONTEXT;
typedef GENERATE_NAME_CONTEXT *PGENERATE_NAME_CONTEXT;

typedef struct _PREFIX_TABLE_ENTRY {
	CSHORT NodeTypeCode;
	CSHORT NameLength;
	struct _PREFIX_TABLE_ENTRY *NextPrefixTree;
	RTL_SPLAY_LINKS Links;
	PSTRING Prefix;
} PREFIX_TABLE_ENTRY;
typedef PREFIX_TABLE_ENTRY *PPREFIX_TABLE_ENTRY;

typedef struct _PREFIX_TABLE {
	CSHORT NodeTypeCode;
	CSHORT NameLength;
	PPREFIX_TABLE_ENTRY NextPrefixTree;
} PREFIX_TABLE;
typedef PREFIX_TABLE *PPREFIX_TABLE;

typedef struct _UNICODE_PREFIX_TABLE_ENTRY {
	CSHORT NodeTypeCode;
	CSHORT NameLength;
	struct _UNICODE_PREFIX_TABLE_ENTRY *NextPrefixTree;
	struct _UNICODE_PREFIX_TABLE_ENTRY *CaseMatch;
	RTL_SPLAY_LINKS Links;
	PUNICODE_STRING Prefix;
} UNICODE_PREFIX_TABLE_ENTRY;
typedef UNICODE_PREFIX_TABLE_ENTRY *PUNICODE_PREFIX_TABLE_ENTRY;

typedef struct _UNICODE_PREFIX_TABLE {
	CSHORT NodeTypeCode;
	CSHORT NameLength;
	PUNICODE_PREFIX_TABLE_ENTRY NextPrefixTree;
	PUNICODE_PREFIX_TABLE_ENTRY LastNextEntry;
} UNICODE_PREFIX_TABLE;
typedef UNICODE_PREFIX_TABLE *PUNICODE_PREFIX_TABLE;

#define COMPRESSION_FORMAT_NONE          (0x0000)   // winnt
#define COMPRESSION_FORMAT_DEFAULT       (0x0001)   // winnt
#define COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt

#define COMPRESSION_ENGINE_STANDARD      (0x0000)   // winnt
#define COMPRESSION_ENGINE_MAXIMUM       (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER         (0x0200)   // winnt

typedef struct _COMPRESSED_DATA_INFO {

	USHORT CompressionFormatAndEngine;

	UCHAR CompressionUnitShift;
	UCHAR ChunkShift;
	UCHAR ClusterShift;
	UCHAR Reserved;
	USHORT NumberOfChunks;
	ULONG CompressedChunkSizes[ANYSIZE_ARRAY];

} COMPRESSED_DATA_INFO;
typedef COMPRESSED_DATA_INFO *PCOMPRESSED_DATA_INFO;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	UCHAR Alignment[4];
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union {
		struct {
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR	ImageFlags;
		struct 
		{
			BOOLEAN ComPlusNativeReady : 1;
			BOOLEAN ComPlusILOnly : 1;
			BOOLEAN ImageDynamicallyRelocated : 1;
			BOOLEAN ImageMappedFlat : 1;
			BOOLEAN Reserved : 4;
		};
	};

	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION64 {
	ULONGLONG TransferAddress;
	ULONG ZeroBits;
	ULONGLONG MaximumStackSize;
	ULONGLONG CommittedStackSize;
	ULONG SubSystemType;
	union {
		struct {
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	BOOLEAN Spare1;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG Reserved[ 1 ];
} SECTION_IMAGE_INFORMATION64, *PSECTION_IMAGE_INFORMATION64;

typedef struct _RTL_BITMAP {
	ULONG SizeOfBitMap;
	UCHAR Padding[4];
	PULONG Buffer;
} RTL_BITMAP;
typedef RTL_BITMAP *PRTL_BITMAP;

#define RTL_USER_PROC_CURDIR_CLOSE      0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT    0x00000003

#define RTL_RANGE_SHARED    0x01
#define RTL_RANGE_CONFLICT  0x02

typedef struct _RTL_RANGE_LIST {
	LIST_ENTRY ListHead;
	ULONG Flags;        // use RANGE_LIST_FLAG_*
	ULONG Count;
	ULONG Stamp;
} RTL_RANGE_LIST, *PRTL_RANGE_LIST;

typedef enum {
	RtlBsdItemVersionNumber = 0x00,
	RtlBsdItemProductType,
	RtlBsdItemAabEnabled,
	RtlBsdItemAabTimeout,
	RtlBsdItemBootGood,
	RtlBsdItemBootShutdown,
	RtlBsdItemMax
} RTL_BSD_ITEM_TYPE, *PRTL_BSD_ITEM_TYPE;

typedef struct _RANGE_LIST_ITERATOR {
	PLIST_ENTRY RangeListHead;
	PLIST_ENTRY MergedHead;
	PVOID Current;
	ULONG Stamp;
} RTL_RANGE_LIST_ITERATOR, *PRTL_RANGE_LIST_ITERATOR;

typedef struct _STARTUP_ARGUMENT
{
	//ULONG Unknown[ 3 ];
	UNICODE_STRING Unknown[ 3 ];
	PRTL_USER_PROCESS_PARAMETERS Environment;
} STARTUP_ARGUMENT, *PSTARTUP_ARGUMENT;

#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_USER_PROC_PROFILE_USER          0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL        0x00000004
#define RTL_USER_PROC_PROFILE_SERVER        0x00000008
#define RTL_USER_PROC_RESERVE_1MB           0x00000020
#define RTL_USER_PROC_RESERVE_16MB          0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE        0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT  0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING     0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS         0x00020000

typedef NTSTATUS (*PUSER_PROCESS_START_ROUTINE)(
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters
	);

typedef NTSTATUS (*PUSER_THREAD_START_ROUTINE)(
	PVOID ThreadParameter
	);

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION64 {
	ULONG Length;
	LONGLONG Process;
	LONGLONG Thread;
	CLIENT_ID64 ClientId;
	SECTION_IMAGE_INFORMATION64 ImageInformation;
} RTL_USER_PROCESS_INFORMATION64, *PRTL_USER_PROCESS_INFORMATION64;

#define RTL_TRACE_IN_USER_MODE       0x00000001
#define RTL_TRACE_IN_KERNEL_MODE     0x00000002
#define RTL_TRACE_USE_NONPAGED_POOL  0x00000004
#define RTL_TRACE_USE_PAGED_POOL     0x00000008

typedef struct _RTL_RESOURCE {

	RTL_CRITICAL_SECTION CriticalSection;

	HANDLE SharedSemaphore;
	ULONG NumberOfWaitingShared;
	HANDLE ExclusiveSemaphore;
	ULONG NumberOfWaitingExclusive;

	LONG NumberOfActive;
	HANDLE ExclusiveOwnerThread;

	ULONG Flags;        // See RTL_RESOURCE_FLAG_ equates below.

	PRTL_RESOURCE_DEBUG DebugInfo;
} RTL_RESOURCE, *PRTL_RESOURCE;

#define RTL_RESOURCE_FLAG_LONG_TERM     ((ULONG) 0x00000001)

typedef struct _RTL_TRACE_BLOCK {
	ULONG Magic;
	ULONG Count;
	ULONG Size;

	SIZE_T UserCount;
	SIZE_T UserSize;
	PVOID UserContext;

	struct _RTL_TRACE_BLOCK * Next;
	PVOID * Trace;
} RTL_TRACE_BLOCK, * PRTL_TRACE_BLOCK;

typedef ULONG (* RTL_TRACE_HASH_FUNCTION) (ULONG Count, PVOID * Trace);
typedef struct _RTL_TRACE_DATABASE * PRTL_TRACE_DATABASE;

typedef struct _RTL_TRACE_ENUMERATE {
	PRTL_TRACE_DATABASE Database;
	ULONG Index;
	PRTL_TRACE_BLOCK Block;
} RTL_TRACE_ENUMERATE, * PRTL_TRACE_ENUMERATE;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;	// <size 0x54>

#define RTL_HEAP_BUSY               (USHORT)0x0001
#define RTL_HEAP_SEGMENT            (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE     (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1     (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2     (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3     (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS     (USHORT)0x00E0
#define RTL_HEAP_UNCOMMITTED_RANGE  (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY    (USHORT)0x0200

#pragma warning(disable: 4273) // nconsistent dll linkage (winnt.h)

typedef struct _DISPATCHER_HEADER
{
	union
	{
		struct
		{
			UCHAR Type;
			union
			{
				UCHAR Absolute;
				UCHAR NpxIrql;
			};

			union
			{
				UCHAR Size;
				UCHAR Hand;
			};

			union
			{
				UCHAR Inserted;
				BOOLEAN DebugActive;
			};

		};	// struct ..
		volatile LONG Lock;
	};	// first union ..

	LONG SignalState;
	LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _KEVENT
{
	DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *PRKEVENT;

typedef struct _KGATE
{
	DISPATCHER_HEADER Header;
} KGATE, *PKGATE;

typedef struct _KSEMAPHORE
{
	DISPATCHER_HEADER Header;
	LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE;		// <size 0x14>

typedef struct _OWNER_ENTRY
{
	ULONG OwnerThread;
	LONG OwnerCount;
	ULONG TableSize;
} OWNER_ENTRY, *POWNER_ENTRY;		// <size 0x8>

typedef struct _ERESOURCE
{
	LIST_ENTRY SystemResourcesList;
	OWNER_ENTRY* OwnerTable;
	SHORT ActiveCount;
	USHORT Flag;
	KSEMAPHORE* SharedWaiters;
	KEVENT* ExclusiveWaiters;
	OWNER_ENTRY OwnerEntry;
	ULONG ActiveEntries;
	ULONG ContentionCount;
	ULONG NumberOfSharedWaiters;
	ULONG NumberOfExclusiveWaiters;
	PVOID Address;
	ULONG CreatorBackTraceIndex;
	ULONG SpinLock;
} ERESOURCE, *PERESOURCE;		// <size 0x38>

#define SET_LAST_STATUS(S)NtCurrentTeb()->LastErrorValue = RtlNtStatusToDosError(NtCurrentTeb()->LastStatusValue = (ULONG)(S))

#define HEAP_GRANULARITY            (sizeof( HEAP_ENTRY ))
#define HEAP_GRANULARITY_SHIFT      3

#define HEAP_MAXIMUM_BLOCK_SIZE     (USHORT)(((0x10000 << HEAP_GRANULARITY_SHIFT) - PAGE_SIZE) >> HEAP_GRANULARITY_SHIFT)

#define HEAP_MAXIMUM_FREELISTS 128
#define HEAP_MAXIMUM_SEGMENTS 16

#define HEAP_ENTRY_BUSY             0x01
#define HEAP_ENTRY_EXTRA_PRESENT    0x02
#define HEAP_ENTRY_FILL_PATTERN     0x04
#define HEAP_ENTRY_VIRTUAL_ALLOC    0x08
#define HEAP_ENTRY_LAST_ENTRY       0x10
#define HEAP_ENTRY_SETTABLE_FLAG1   0x20
#define HEAP_ENTRY_SETTABLE_FLAG2   0x40
#define HEAP_ENTRY_SETTABLE_FLAG3   0x80
#define HEAP_ENTRY_SETTABLE_FLAGS   0xE0

typedef struct _HEAP_LOCK
{
	union
	{
		RTL_CRITICAL_SECTION CriticalSection;
		ERESOURCE Resource;
	} Lock;
} HEAP_LOCK, *PHEAP_LOCK;

typedef struct _HEAP_TUNING_PARAMETERS
{
	ULONG CommittThresholdShift;
	ULONG MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;		// <size 0x8>

typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
	ULONG Allocs;
	ULONG Frees;
	ULONG Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;	// <size 0xc>

typedef struct _HEAP_TAG_ENTRY
{
	ULONG Allocs;
	ULONG Frees;
	ULONG Size;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[ 24 ];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;		// <size 0x40>

typedef struct _HEAP_ENTRY
{
	USHORT Size;
	UCHAR Flags;
	UCHAR SmallTagIndex;
	PVOID SubSegmentCode;
	USHORT PreviousSize;
	UCHAR SegmentOffset;
	UCHAR LFHFlags;
	UCHAR UnusedBytes;
	USHORT FunctionIndex;
	USHORT ContextValue;
	ULONG InterceptorValue;
	USHORT UnusedBytesLength;
	UCHAR EntryOffset;
	UCHAR ExtendedBlockSignature;
	ULONG Code1;
	USHORT Code2;
	UCHAR Code3;
	UCHAR Code4;
	ULONG64 AgregateCode;
} HEAP_ENTRY, *PHEAP_ENTRY;

typedef struct _HEAP_COUNTERS
{
	ULONG TotalMemoryReserved;
	ULONG TotalMemoryCommitted;
	ULONG TotalMemoryLargeUCR;
	ULONG TotalSizeInVirtualBlocks;
	ULONG TotalSegments;
	ULONG TotalUCRs;
	ULONG CommittOps;
	ULONG DeCommitOps;
	ULONG LockAcquires;
	ULONG LockCollisions;
	ULONG CommitRate;
	ULONG DecommittRate;
	ULONG CommitFailures;
	ULONG InBlockCommitFailures;
	ULONG CompactHeapCalls;
	ULONG CompactedUCRs;
	ULONG InBlockDeccommits;
	ULONG InBlockDeccomitSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;		// <size 0x48>

typedef struct _HEAP
{
	HEAP_ENTRY Entry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	LIST_ENTRY SegmentListEntry;
	struct _HEAP* Heap;
	PVOID BaseAddress;
	ULONG NumberOfPages;
	PHEAP_ENTRY FirstEntry;
	PHEAP_ENTRY LastValidEntry;
	ULONG NumberOfUnCommittedPages;
	ULONG NumberOfUnCommittedRanges;
	USHORT SegmentAllocatorBackTraceIndex;
	USHORT Reserved;
	LIST_ENTRY UCRSegmentList;
	ULONG Flags;
	ULONG ForceFlags;
	ULONG CompatibilityFlags;
	ULONG EncodeFlagMask;
	HEAP_ENTRY Encoding;
	ULONG PointerKey;
	ULONG Interceptor;
	ULONG VirtualMemoryThreshold;
	ULONG Signature;
	ULONG SegmentReserve;
	ULONG SegmentCommit;
	ULONG DeCommitFreeBlockThreshold;
	ULONG DeCommitTotalFreeThreshold;
	ULONG TotalFreeSize;
	ULONG MaximumAllocationSize;
	USHORT ProcessHeapsListIndex;
	USHORT HeaderValidateLength;
	PVOID HeaderValidateCopy;
	USHORT NextAvailableTagIndex;
	USHORT MaximumTagIndex;
	PHEAP_TAG_ENTRY TagEntries;
	LIST_ENTRY UCRList;
	ULONG AlignRound;
	ULONG AlignMask;
	LIST_ENTRY VirtualAllocdBlocks;
	LIST_ENTRY SegmentList;
	USHORT AllocatorBackTraceIndex;
	ULONG NonDedicatedListLength;
	PVOID BlocksIndex;
	PVOID UCRIndex;
	PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
	LIST_ENTRY FreeLists;
	PHEAP_LOCK LockVariable;
	LONG * CommitRoutine;		// <<-- http://www.nirsoft.net/kernel_struct/vista/HEAP.html
	PVOID FrontEndHeap;
	USHORT FrontHeapLockCount;
	UCHAR FrontEndHeapType;
	HEAP_COUNTERS Counters;
	HEAP_TUNING_PARAMETERS TuningParameters;
} HEAP, *PHEAP;		// <size 0x130>

typedef struct _HEAP_FREE_ENTRY_EXTRA
{
	USHORT TagIndex;
	USHORT FreeBackTraceIndex;
} HEAP_FREE_ENTRY_EXTRA, *PHEAP_FREE_ENTRY_EXTRA;		// <size 0x4>

typedef struct _HEAP_ENTRY_EXTRA
{
	USHORT AllocatorBackTraceIndex;
	USHORT TagIndex;
	ULONG Settable;
	ULONG64 ZeroInit;
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;		// <size 0x8>

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY
{
	LIST_ENTRY Entry;
	HEAP_ENTRY_EXTRA ExtraStuff;
	ULONG CommitSize;
	ULONG ReserveSize;
	HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;		// <size 0x20>

//
// Known extended CPU state feature IDs
//

// #define XSTATE_LEGACY_FLOATING_POINT        0
// #define XSTATE_LEGACY_SSE                   1
// #define XSTATE_GSSE                         2
// 
// #define XSTATE_MASK_LEGACY_FLOATING_POINT   (1i64 << (XSTATE_LEGACY_FLOATING_POINT))
// #define XSTATE_MASK_LEGACY_SSE              (1i64 << (XSTATE_LEGACY_SSE))
// #define XSTATE_MASK_LEGACY                  (XSTATE_MASK_LEGACY_FLOATING_POINT | XSTATE_MASK_LEGACY_SSE)
// #define XSTATE_MASK_GSSE                    (1i64 << (XSTATE_GSSE))
// 
// #define MAXIMUM_XSTATE_FEATURES             64


typedef enum _HARDERROR_RESPONSE_OPTION
{
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem,
	OptionOkNoWait,
	OptionCancelTryContinue
} HARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes,
	ResponseTryAgain,
	ResponseContinue
} HARDERROR_RESPONSE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign,                 // None == 0 == standard design
	NEC98x86,                       // NEC PC98xx series on X86
	EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;

#define NX_SUPPORT_POLICY_ALWAYSOFF 0
#define NX_SUPPORT_POLICY_ALWAYSON 1
#define NX_SUPPORT_POLICY_OPTIN 2
#define NX_SUPPORT_POLICY_OPTOUT 3

#define PROCESSOR_FEATURE_MAX 64
#define MAX_WOW64_SHARED_ENTRIES 16

#if defined(_MSC_VER) && (_MSC_VER < 1300)

#define XSTATE_LEGACY_FLOATING_POINT        0
#define XSTATE_LEGACY_SSE                   1
#define XSTATE_GSSE                         2

#define XSTATE_MASK_LEGACY_FLOATING_POINT   (1i64 << (XSTATE_LEGACY_FLOATING_POINT))
#define XSTATE_MASK_LEGACY_SSE              (1i64 << (XSTATE_LEGACY_SSE))
#define XSTATE_MASK_LEGACY                  (XSTATE_MASK_LEGACY_FLOATING_POINT | XSTATE_MASK_LEGACY_SSE)
#define XSTATE_MASK_GSSE                    (1i64 << (XSTATE_GSSE))

#define MAXIMUM_XSTATE_FEATURES             64

//
// Extended processor state configuration
//
#if defined(_WINNT_) && defined(_MSC_VER) && _MSC_VER < 1300
typedef struct _XSTATE_FEATURE {
    DWORD Offset;
    DWORD Size;
} XSTATE_FEATURE, *PXSTATE_FEATURE;

typedef struct _XSTATE_CONFIGURATION {
    // Mask of enabled features
    DWORD64 EnabledFeatures;

    // Total size of the save area
    DWORD Size;

    DWORD OptimizedSave : 1;

    // List of features (
    XSTATE_FEATURE Features[MAXIMUM_XSTATE_FEATURES];

} XSTATE_CONFIGURATION, *PXSTATE_CONFIGURATION;
#endif

#ifndef _WINDOWS_
typedef enum _HEAP_INFORMATION_CLASS {
	HeapCompatibilityInformation
} HEAP_INFORMATION_CLASS;
#endif //_WINDOWS_

#endif

typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    WCHAR NtSystemRoot[260];

    ULONG MaxStackTraceDepth;

    ULONG CryptoExponent;

    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];

    ULONG NtProductType;
    BOOLEAN ProductTypeIsValid;

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

    ULONG Reserved1;
    ULONG Reserved3;

    volatile ULONG TimeSlip;

    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    LARGE_INTEGER SystemExpirationDate;

    ULONG SuiteMask;

    BOOLEAN KdDebuggerEnabled;

    UCHAR NXSupportPolicy;

    volatile ULONG ActiveConsoleId;

    volatile ULONG DismountCount;

    ULONG ComPlusPackage;

    ULONG LastSystemRITEventTickCount;

    ULONG NumberOfPhysicalPages;

    BOOLEAN SafeBootMode;
    union
    {
        UCHAR TscQpcData;
        struct
        {
            UCHAR TscQpcEnabled : 1;
            UCHAR TscQpcSpareFlag : 1;
            UCHAR TscQpcShift : 6;
        };
    };
    UCHAR TscQpcPad[2];

    union
    {
        ULONG TraceLogging;
        ULONG SharedDataFlags;
        struct
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgSystemDllRelocated : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgSEHValidationEnabled : 1;
            ULONG SpareBits : 25;
        };
    };
    ULONG DataFlagsPad[1];

    ULONGLONG TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    ULONGLONG SystemCallPad[3];

    union
    {
        volatile KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
        struct
        {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        };
    };

    ULONG Cookie;

    // Entries below all invalid below Windows Vista

    ULONG CookiePad[1];

    LONGLONG ConsoleSessionForegroundProcessId;

    ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];

    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;

    ULONG LangGenerationCount;

    union
    {
        ULONGLONG AffinityPad; // only valid on Windows Vista
        ULONG_PTR ActiveProcessorAffinity; // only valid on Windows Vista
        ULONGLONG Reserved5;
    };
    volatile ULONG64 InterruptTimeBias;
    volatile ULONG64 TscQpcBias;

    volatile ULONG ActiveProcessorCount;
    volatile USHORT ActiveGroupCount;
    USHORT Reserved4;

    volatile ULONG AitSamplingValue;
    volatile ULONG AppCompatFlag;

    ULONGLONG SystemDllNativeRelocation;
    ULONG SystemDllWowRelocation;

    ULONG XStatePad[1];
    XSTATE_CONFIGURATION XState;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountMultiplier) == 0x4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTime) == 0x8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemTime) == 0x14);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneBias) == 0x20);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberLow) == 0x2c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageNumberHigh) == 0x2e);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtSystemRoot) == 0x30);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, MaxStackTraceDepth) == 0x238);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, CryptoExponent) == 0x23c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeZoneId) == 0x240);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LargePageMinimum) == 0x244);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved2) == 0x248);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtProductType) == 0x264);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProductTypeIsValid) == 0x268);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMajorVersion) == 0x26c);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NtMinorVersion) == 0x270);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ProcessorFeatures) == 0x274);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved1) == 0x2b4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved3) == 0x2b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TimeSlip) == 0x2bc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AlternativeArchitecture) == 0x2c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemExpirationDate) == 0x2c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SuiteMask) == 0x2d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, KdDebuggerEnabled) == 0x2d4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NXSupportPolicy) == 0x2d5);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveConsoleId) == 0x2d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, DismountCount) == 0x2dC);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ComPlusPackage) == 0x2e0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LastSystemRITEventTickCount) == 0x2e4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, NumberOfPhysicalPages) == 0x2e8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SafeBootMode) == 0x2ec);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TraceLogging) == 0x2f0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TestRetInstruction) == 0x2f8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCall) == 0x300);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallReturn) == 0x304);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemCallPad) == 0x308);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCount) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TickCountQuad) == 0x320);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Cookie) == 0x330);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ConsoleSessionForegroundProcessId) == 0x338);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Wow64SharedInformation) == 0x340);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, UserModeGlobalLogger) == 0x380);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ImageFileExecutionOptions) == 0x3a0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, LangGenerationCount) == 0x3a4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved5) == 0x3a8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, InterruptTimeBias) == 0x3b0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, TscQpcBias) == 0x3b8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveProcessorCount) == 0x3c0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, ActiveGroupCount) == 0x3c4);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, Reserved4) == 0x3c6);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AitSamplingValue) == 0x3c8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, AppCompatFlag) == 0x3cc);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemDllNativeRelocation) == 0x3d0);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, SystemDllWowRelocation) == 0x3d8);
C_ASSERT(FIELD_OFFSET(KUSER_SHARED_DATA, XState) == 0x3e0);

#define SHARED_USER_DATA_VA 0x7FFE0000
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)SHARED_USER_DATA_VA)

__inline struct _KUSER_SHARED_DATA * GetKUserSharedData() { return (USER_SHARED_DATA); }

__forceinline ULONG NtGetTickCount() { return (ULONG) ((USER_SHARED_DATA->TickCountQuad * USER_SHARED_DATA->TickCountMultiplier) >> 24); }

//added 20/03/2011
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004

//added 20/03/2011
typedef struct _RTL_PROCESS_REFLECTION_INFORMATION
{
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
} RTL_PROCESS_REFLECTION_INFORMATION, *PRTL_PROCESS_REFLECTION_INFORMATION;

//FIXED 21.02.2011 size for x64
typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

#if (_MSC_VER < 1300) && !defined(_WINDOWS_)
typedef struct _IO_COUNTERS {
	ULONGLONG  ReadOperationCount;
	ULONGLONG  WriteOperationCount;
	ULONGLONG  OtherOperationCount;
	ULONGLONG ReadTransferCount;
	ULONGLONG WriteTransferCount;
	ULONGLONG OtherTransferCount;
} IO_COUNTERS;
typedef IO_COUNTERS *PIO_COUNTERS;
#endif

// SystemProcessesAndThreadsInformation
//FIXED 21.02.2011 size for x64 (and as well for x86 too)
typedef struct _SYSTEM_PROCESSES_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESSES_INFORMATION, *PSYSTEM_PROCESSES_INFORMATION;

#define SIZEOF_BP_BUFFER 32
#define LPC_BUFFER_SIZE 0x130

typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD
{
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS
{
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGUI_CREATE_THREAD CreateThread;
		DBGUI_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
	DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
	DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE 0x1

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;


//added 21/03/2011
//begin
typedef struct _RTL_HEAP_TAG_INFO
{
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
} RTL_HEAP_TAG_INFO, *PRTL_HEAP_TAG_INFO;

#define RTL_HEAP_MAKE_TAG HEAP_MAKE_TAG_FLAGS
#define MAKE_TAG( t ) (RTL_HEAP_MAKE_TAG( NtdllBaseTag, t ))

typedef NTSTATUS (NTAPI *PRTL_ENUM_HEAPS_ROUTINE)(
	IN PVOID HeapHandle,
	IN PVOID Parameter
	);

typedef struct _RTL_HEAP_USAGE_ENTRY
{
	struct _RTL_HEAP_USAGE_ENTRY *Next;
	PVOID Address;
	SIZE_T Size;
	USHORT AllocatorBackTraceIndex;
	USHORT TagIndex;
} RTL_HEAP_USAGE_ENTRY, *PRTL_HEAP_USAGE_ENTRY;

typedef struct _RTL_HEAP_USAGE
{
	ULONG Length;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	SIZE_T BytesReserved;
	SIZE_T BytesReservedMaximum;
	PRTL_HEAP_USAGE_ENTRY Entries;
	PRTL_HEAP_USAGE_ENTRY AddedEntries;
	PRTL_HEAP_USAGE_ENTRY RemovedEntries;
	ULONG_PTR Reserved[8];
} RTL_HEAP_USAGE, *PRTL_HEAP_USAGE;

#define HEAP_USAGE_ALLOCATED_BLOCKS HEAP_REALLOC_IN_PLACE_ONLY
#define HEAP_USAGE_FREE_BUFFER HEAP_ZERO_MEMORY

typedef struct _RTL_HEAP_WALK_ENTRY
{
	PVOID DataAddress;
	SIZE_T DataSize;
	UCHAR OverheadBytes;
	UCHAR SegmentIndex;
	USHORT Flags;
	union
	{
		struct
		{
			SIZE_T Settable;
			USHORT TagIndex;
			USHORT AllocatorBackTraceIndex;
			ULONG Reserved[2];
		} Block;
		struct
		{
			ULONG CommittedSize;
			ULONG UnCommittedSize;
			PVOID FirstEntry;
			PVOID LastEntry;
		} Segment;
	};
} RTL_HEAP_WALK_ENTRY, *PRTL_HEAP_WALK_ENTRY;

#define HeapDebuggingInformation 0x80000002

typedef NTSTATUS (NTAPI *PRTL_HEAP_LEAK_ENUMERATION_ROUTINE)(
	IN LONG Reserved,
	IN PVOID HeapHandle,
	IN PVOID BaseAddress,
	IN SIZE_T BlockSize,
	IN ULONG StackTraceDepth,
	IN PVOID *StackTrace
	);

typedef struct _HEAP_DEBUGGING_INFORMATION
{
	PVOID InterceptorFunction;
	USHORT InterceptorValue;
	ULONG ExtendedOptions;
	ULONG StackTraceDepth;
	SIZE_T MinTotalBlockSize;
	SIZE_T MaxTotalBlockSize;
	PRTL_HEAP_LEAK_ENUMERATION_ROUTINE HeapLeakEnumerationRoutine;
} HEAP_DEBUGGING_INFORMATION, *PHEAP_DEBUGGING_INFORMATION;

// added 11/04/2011
#define PREALLOCATE_EVENT_MASK  0x80000000

#define RtlInitializeLockRoutine(L) RtlInitializeCriticalSectionAndSpinCount((PRTL_CRITICAL_SECTION)(L),(PREALLOCATE_EVENT_MASK | 4000))
#define RtlAcquireLockRoutine(L)    RtlEnterCriticalSection((PRTL_CRITICAL_SECTION)(L))
#define RtlReleaseLockRoutine(L)    RtlLeaveCriticalSection((PRTL_CRITICAL_SECTION)(L))
#define RtlDeleteLockRoutine(L)     RtlDeleteCriticalSection((PRTL_CRITICAL_SECTION)(L))

typedef struct _RTL_MEMORY_ZONE_SEGMENT
{
	struct _RTL_MEMORY_ZONE_SEGMENT *NextSegment;
	SIZE_T Size;
	PVOID Next;
	PVOID Limit;
} RTL_MEMORY_ZONE_SEGMENT, *PRTL_MEMORY_ZONE_SEGMENT;

#if defined(_WINNT_) && defined(_MSC_VER) && (_MSC_VER < 1300)
typedef struct _RTL_SRWLOCK {                            
	PVOID Ptr;                                       
} RTL_SRWLOCK, *PRTL_SRWLOCK; 
#endif

typedef struct _RTL_MEMORY_ZONE
{
	RTL_MEMORY_ZONE_SEGMENT Segment;
	RTL_SRWLOCK Lock;
	ULONG LockCount;
	PRTL_MEMORY_ZONE_SEGMENT FirstSegment;
} RTL_MEMORY_ZONE, *PRTL_MEMORY_ZONE;

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
	ULONG SizeStruct;
	ULONG Option;
	UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _VM_INFORMATION
{
    DWORD					dwNumberOfOffsets;
    PULONG					plOutput;
    PCFG_CALL_TARGET_INFO	ptOffsets;
    PVOID					pMustBeZero;
    PVOID					pMoarZero;
} VM_INFORMATION, * PVM_INFORMATION;

typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _RTL_PROCESS_LOCKS {
	ULONG NumberOfLocks;
	RTL_PROCESS_LOCK_INFORMATION Locks[ 1 ];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;

#define MAX_STACK_DEPTH 32

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION {
	PCHAR SymbolicBackTrace;
	ULONG TraceCount;
	USHORT Index;
	USHORT Depth;
	PVOID BackTrace[ MAX_STACK_DEPTH ];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES {
	ULONG CommittedMemory;
	ULONG ReservedMemory;
	ULONG NumberOfBackTraceLookups;
	ULONG NumberOfBackTraces;
	RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[ 1 ];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;

typedef struct _RTL_DEBUG_INFORMATION
{
	HANDLE SectionHandleClient;
	PVOID ViewBaseClient;
	PVOID ViewBaseTarget;
	ULONG_PTR ViewBaseDelta;
	HANDLE EventPairClient;
	HANDLE EventPairTarget;
	HANDLE TargetProcessId;
	HANDLE TargetThreadHandle;
	ULONG Flags;
	SIZE_T OffsetFree;
	SIZE_T CommitSize;
	SIZE_T ViewSize;
	union
	{
		PRTL_PROCESS_MODULES Modules;
		PRTL_PROCESS_MODULE_INFORMATION_EX *ModulesEx;
	};
	PRTL_PROCESS_BACKTRACES BackTraces;
	PRTL_PROCESS_HEAPS Heaps;
	PRTL_PROCESS_LOCKS Locks;
	PVOID SpecificHeap;
	HANDLE TargetProcessHandle;
	PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
	PVOID ProcessHeap;
	HANDLE CriticalSectionHandle;
	HANDLE CriticalSectionOwnerThread;
	PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

//added 21/03/2011
//end


// added: 22/04/2011 - RtlStream
typedef struct _RTL_MEMORY_STREAM_DATA *PRTL_MEMORY_STREAM_DATA;
typedef struct _RTL_MEMORY_STREAM_WITH_VTABLE *PRTL_MEMORY_STREAM_WITH_VTABLE;
typedef struct _RTL_OUT_OF_PROCESS_MEMORY_STREAM_DATA *PRTL_OUT_OF_PROCESS_MEMORY_STREAM_DATA;

HRESULT
NTAPI
RtlReleaseMemoryStream(
	PRTL_MEMORY_STREAM_WITH_VTABLE MemoryStream
	);

HRESULT
NTAPI
RtlSetMemoryStreamSize(
	PRTL_MEMORY_STREAM_WITH_VTABLE MemoryStream,
	ULARGE_INTEGER ULargeInteger
	);

HRESULT
NTAPI
RtlCommitMemoryStream(
	PRTL_MEMORY_STREAM_WITH_VTABLE MemoryStream,
	ULONG NewStream
	);

HRESULT
NTAPI
RtlRevertMemoryStream(
	PRTL_MEMORY_STREAM_WITH_VTABLE MemoryStream
	);

NTSTATUS
NTAPI
RtlCopySecurityDescriptor(
	PSECURITY_DESCRIPTOR SourceDescriptor,
	PSECURITY_DESCRIPTOR DestinationDescriptor
	);


typedef struct _RTL_HANDLE_TABLE_ENTRY
{
	union
	{
		ULONG Flags;
		struct _RTL_HANDLE_TABLE_ENTRY *NextFree;
	};
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;

#define RTL_HANDLE_ALLOCATED (USHORT)0x0001

typedef struct _RTL_HANDLE_TABLE
{
	ULONG MaximumNumberOfHandles;
	ULONG SizeOfHandleTableEntry;
	ULONG Reserved[2];
	PRTL_HANDLE_TABLE_ENTRY FreeHandles;
	PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
	PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
	PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
} RTL_HANDLE_TABLE, *PRTL_HANDLE_TABLE;

#if defined(_WINNT_) && (_MSC_VER < 1300) && !defined(_WINDOWS_)
typedef struct _JOB_SET_ARRAY {
    HANDLE JobHandle;   // Handle to job object to insert
    DWORD MemberLevel;  // Level of this job in the set. Must be > 0. Can be sparse.
    DWORD Flags;        // Unused. Must be zero
} JOB_SET_ARRAY, *PJOB_SET_ARRAY;
#endif

VOID
NTAPI
RtlInitializeHandleTable(
	IN ULONG MaximumNumberOfHandles,
	IN ULONG SizeOfHandleTableEntry,
	OUT PRTL_HANDLE_TABLE HandleTable
	);

NTSTATUS
NTAPI
RtlDestroyHandleTable(
	IN OUT PRTL_HANDLE_TABLE HandleTable
	);

PRTL_HANDLE_TABLE_ENTRY
NTAPI
RtlAllocateHandle(
	IN PRTL_HANDLE_TABLE HandleTable,
	OUT OPTIONAL PULONG HandleIndex
	);

BOOLEAN
NTAPI
RtlFreeHandle(
	IN PRTL_HANDLE_TABLE HandleTable,
	IN PRTL_HANDLE_TABLE_ENTRY Handle
	);

BOOLEAN
NTAPI
RtlIsValidHandle(
	IN PRTL_HANDLE_TABLE HandleTable,
	IN PRTL_HANDLE_TABLE_ENTRY Handle
	);

BOOLEAN
NTAPI
RtlIsValidIndexHandle(
	IN PRTL_HANDLE_TABLE HandleTable,
	IN ULONG HandleIndex,
	OUT PRTL_HANDLE_TABLE_ENTRY *Handle
	);

#define RTL_ATOM_MAXIMUM_INTEGER_ATOM (RTL_ATOM)0xc000
#define RTL_ATOM_INVALID_ATOM (RTL_ATOM)0x0000
#define RTL_ATOM_TABLE_DEFAULT_NUMBER_OF_BUCKETS 37
#define RTL_ATOM_MAXIMUM_NAME_LENGTH 255
#define RTL_ATOM_PINNED 0x01

NTSTATUS
NTAPI
RtlCreateAtomTable(
	IN ULONG NumberOfBuckets,
	OUT PVOID *AtomTableHandle
	);

NTSTATUS
NTAPI
RtlDestroyAtomTable(
	IN PVOID AtomTableHandle
	);

NTSTATUS
NTAPI
RtlEmptyAtomTable(
	IN PVOID AtomTableHandle,
	IN BOOLEAN IncludePinnedAtoms
	);

NTSTATUS
NTAPI
RtlAddAtomToAtomTable(
	IN PVOID AtomTableHandle,
	IN PWSTR AtomName,
	IN OUT OPTIONAL PRTL_ATOM Atom
	);

NTSTATUS
NTAPI
RtlLookupAtomInAtomTable(
	IN PVOID AtomTableHandle,
	IN PWSTR AtomName,
	OUT OPTIONAL PRTL_ATOM Atom
	);

NTSTATUS
NTAPI
RtlDeleteAtomFromAtomTable(
	IN PVOID AtomTableHandle,
	IN RTL_ATOM Atom
	);

NTSTATUS
NTAPI
RtlPinAtomInAtomTable(
	IN PVOID AtomTableHandle,
	IN RTL_ATOM Atom
	);

NTSTATUS
NTAPI
RtlQueryAtomInAtomTable(
	IN PVOID AtomTableHandle,
	IN RTL_ATOM Atom,
	OUT OPTIONAL PULONG AtomUsage,
	OUT OPTIONAL PULONG AtomFlags,
	IN OUT PWSTR AtomName,
	IN OUT OPTIONAL PULONG AtomNameLength
	);

NTSTATUS
NTAPI
RtlQueryAtomsInAtomTable(
	IN PVOID AtomTableHandle,
	IN ULONG MaximumNumberOfAtoms,
	OUT PULONG NumberOfAtoms,
	OUT PRTL_ATOM Atoms
	);

BOOLEAN
NTAPI
RtlGetIntegerAtom(
	IN PWSTR AtomName,
	OUT OPTIONAL PUSHORT IntegerAtom
	);

#define EVENT_MIN_LEVEL                      (0)
#define EVENT_MAX_LEVEL                      (0xff)

#define EVENT_ACTIVITY_CTRL_GET_ID           (1)
#define EVENT_ACTIVITY_CTRL_SET_ID           (2)
#define EVENT_ACTIVITY_CTRL_CREATE_ID        (3)
#define EVENT_ACTIVITY_CTRL_GET_SET_ID       (4)
#define EVENT_ACTIVITY_CTRL_CREATE_SET_ID    (5)

	typedef ULONGLONG REGHANDLE, *PREGHANDLE;

#define MAX_EVENT_DATA_DESCRIPTORS           (128)
#define MAX_EVENT_FILTER_DATA_SIZE           (1024)

	//
	// EVENT_DATA_DESCRIPTOR is used to pass in user data items
	// in events.
	// 

	typedef struct _EVENT_DATA_DESCRIPTOR
	{
		ULONG_PTR   Ptr;        // Pointer to data
		ULONG       Size;       // Size of data in bytes
		ULONG       Reserved;
	} EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;

	typedef struct _EVENT_DESCRIPTOR
	{
		USHORT      Id;
		UCHAR       Version;
		UCHAR       Channel;
		UCHAR       Level;
		UCHAR       Opcode;
		USHORT      Task;
		ULONGLONG   Keyword;
	} EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;
	typedef const EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

	//
	// EVENT_FILTER_DESCRIPTOR is used to pass in enable filter
	// data item to a user callback function.
	// 
	typedef struct _EVENT_FILTER_DESCRIPTOR
	{
		ULONG_PTR   Ptr;
		ULONG       Size;
		ULONG       Type;
	} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

//
// old nt4 channel stuff
//
//#pragma pack(1)
#pragma pack()
typedef struct _CHANNEL_MESSAGE
{
	PVOID Text;
	ULONG Length;
	PVOID Context;
	PVOID Base;
	union
	{
		BOOLEAN Close;
		LONGLONG Align;
	};
} CHANNEL_MESSAGE, *PCHANNEL_MESSAGE;

typedef struct _HOTPATCH_HEADER
{
	ULONG Signature;
	ULONG Version;
	ULONG FixupRgnCount;
	ULONG FixupRgnRva;
	ULONG ValidationCount;
	ULONG ValidationArrayRva;
	ULONG HookCount;
	ULONG HookArrayRva;
	ULONG_PTR OrigHotpBaseAddress;
	ULONG_PTR OrigTargetBaseAddress;
	ULONG TargetNameRva;
	ULONG ModuleIdMethod;
	union { 
		ULONG Filler;
	} TargetModuleIdValue;
} HOTPATCH_HEADER, *PHOTPATCH_HEADER;

typedef struct _HOTPATCH_MODULE_DATA
{
	USHORT HotpatchImageNameLength;
	USHORT ColdpatchImagePathLength;
	WCHAR NameBuffer[ 1 ];
} HOTPATCH_MODULE_DATA, *PHOTPATCH_MODULE_DATA;

typedef struct _HOTPATCH_MODULE_ENTRY
{
	struct _TRIPLE_LIST_ENTRY ListEntry;
	struct _HOTPATCH_MODULE_DATA Data;
} HOTPATCH_MODULE_ENTRY, *PHOTPATCH_MODULE_ENTRY;

typedef struct _HOTPATCH_HOOK
{
	USHORT HookType;
	USHORT HookOptions;
	ULONG HookRva;
	ULONG HotpRva;
	ULONG ValidationRva;
} HOTPATCH_HOOK, *PHOTPATCH_HOOK;

typedef struct _RTL_PATCH_HEADER
{
	LIST_ENTRY PatchList;
	PVOID PatchImageBase;
	struct _RTL_PATCH_HEADER* NextPatch;
	ULONG PatchFlags;
	LONG PatchRefCount;
	struct _HOTPATCH_HEADER* HotpatchHeader;
	UNICODE_STRING TargetDllName;
	HANDLE TargetDllBase;
	PLDR_DATA_TABLE_ENTRY TargetLdrDataTableEntry;
	PLDR_DATA_TABLE_ENTRY PatchLdrDataTableEntry;
	PSYSTEM_HOTPATCH_CODE_INFORMATION CodeInfo;
	PVOID ColdpatchFileHandle;
	HOTPATCH_MODULE_ENTRY HotpatchModuleEntry;
} RTL_PATCH_HEADER, *PRTL_PATCH_HEADER;



#pragma warning(default: 4273) // nconsistent dll linkage (winnt.h)

#ifndef _SLIST_HEADER_
#define _SLIST_HEADER_

#if defined(_M_X64)

//
// The type SINGLE_LIST_ENTRY is not suitable for use with SLISTs.  For
// WIN64, an entry on an SLIST is required to be 16-byte aligned, while a
// SINGLE_LIST_ENTRY structure has only 8 byte alignment.
//
// Therefore, all SLIST code should use the SLIST_ENTRY type instead of the
// SINGLE_LIST_ENTRY type.
//

#pragma warning(push)
#pragma warning(disable:4324)   // structure padded due to align()
typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY *PSLIST_ENTRY;
typedef struct DECLSPEC_ALIGN(16) _SLIST_ENTRY {
    PSLIST_ENTRY Next;
} SLIST_ENTRY;
#pragma warning(pop)

#else

#define SLIST_ENTRY SINGLE_LIST_ENTRY
#define _SLIST_ENTRY _SINGLE_LIST_ENTRY
#define PSLIST_ENTRY PSINGLE_LIST_ENTRY

#endif

#if defined(_M_X64)

typedef struct DECLSPEC_ALIGN(16) _SLIST_HEADER {
    ULONGLONG Alignment;
    ULONGLONG Region;
} SLIST_HEADER;

typedef struct _SLIST_HEADER *PSLIST_HEADER;

#else

typedef union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct {
        SLIST_ENTRY Next;
        WORD   Depth;
        WORD   Sequence;
    };
} SLIST_HEADER, *PSLIST_HEADER;

#endif

#endif

//
// prototypes *must* be encapsulated with extern "C" macros at start and end of prototype block
//

PSLIST_ENTRY
__fastcall
RtlInterlockedPushListSList (
     IN PSLIST_HEADER ListHead,
     IN PSLIST_ENTRY List,
     IN PSLIST_ENTRY ListEnd,
     IN ULONG Count
     );

VOID
NTAPI
RtlAssert(
	IN PVOID VoidFailedAssertion,
	IN PVOID VoidFileName,
	IN ULONG LineNumber,
	IN OPTIONAL PSTR MutableMessage
    );

VOID
NTAPI
RtlInitializeGenericTableAvl (
    PRTL_AVL_TABLE Table,
    PRTL_AVL_COMPARE_ROUTINE CompareRoutine,
    PRTL_AVL_ALLOCATE_ROUTINE AllocateRoutine,
    PRTL_AVL_FREE_ROUTINE FreeRoutine,
    PVOID TableContext
    );

PVOID
NTAPI
RtlInsertElementGenericTableAvl (
    PRTL_AVL_TABLE Table,
    PVOID Buffer,
    ULONG BufferSize,
    PBOOLEAN NewElement OPTIONAL
    );

PVOID
NTAPI
RtlInsertElementGenericTableFullAvl (
    PRTL_AVL_TABLE Table,
    PVOID Buffer,
    ULONG BufferSize,
    PBOOLEAN NewElement OPTIONAL,
    PVOID NodeOrParent,
    TABLE_SEARCH_RESULT SearchResult
    );

BOOLEAN
NTAPI
RtlDeleteElementGenericTableAvl (
    PRTL_AVL_TABLE Table,
    PVOID Buffer
    );

PVOID
NTAPI
RtlLookupElementGenericTableAvl (
    PRTL_AVL_TABLE Table,
    PVOID Buffer
    );

PVOID
NTAPI
RtlLookupElementGenericTableFullAvl (
    PRTL_AVL_TABLE Table,
    PVOID Buffer,
    OUT PVOID *NodeOrParent,
    OUT TABLE_SEARCH_RESULT *SearchResult
    );

PVOID
NTAPI
RtlEnumerateGenericTableAvl (
    PRTL_AVL_TABLE Table,
    BOOLEAN Restart
    );

PVOID
NTAPI
RtlEnumerateGenericTableWithoutSplayingAvl (
    PRTL_AVL_TABLE Table,
    PVOID *RestartKey
    );

PVOID
NTAPI
RtlEnumerateGenericTableLikeADirectory (
    IN PRTL_AVL_TABLE Table,
    IN PRTL_AVL_MATCH_FUNCTION MatchFunction,
    IN PVOID MatchData,
    IN ULONG NextFlag,
    IN OUT PVOID *RestartKey,
    IN OUT PULONG DeleteCount,
    IN OUT PVOID Buffer
    );

PVOID
NTAPI
RtlGetElementGenericTableAvl (
    PRTL_AVL_TABLE Table,
    ULONG I
    );

ULONG
NTAPI
RtlNumberGenericTableElementsAvl (
    PRTL_AVL_TABLE Table
    );

BOOLEAN
NTAPI
RtlIsGenericTableEmptyAvl (
    PRTL_AVL_TABLE Table
    );

PRTL_SPLAY_LINKS
NTAPI
RtlSplay (
    PRTL_SPLAY_LINKS Links
    );

PRTL_SPLAY_LINKS
NTAPI
RtlDelete (
    PRTL_SPLAY_LINKS Links
    );

VOID
NTAPI
RtlDeleteNoSplay (
    PRTL_SPLAY_LINKS Links,
    PRTL_SPLAY_LINKS *Root
    );

PRTL_SPLAY_LINKS
NTAPI
RtlSubtreeSuccessor (
    PRTL_SPLAY_LINKS Links
    );

PRTL_SPLAY_LINKS
NTAPI
RtlSubtreePredecessor (
    PRTL_SPLAY_LINKS Links
    );

PRTL_SPLAY_LINKS
NTAPI
RtlRealSuccessor (
    PRTL_SPLAY_LINKS Links
    );

PRTL_SPLAY_LINKS
NTAPI
RtlRealPredecessor (
    PRTL_SPLAY_LINKS Links
    );

VOID
NTAPI
RtlInitializeGenericTable (
    PRTL_GENERIC_TABLE Table,
    PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine,
    PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine,
    PRTL_GENERIC_FREE_ROUTINE FreeRoutine,
    PVOID TableContext
    );

PVOID
NTAPI
RtlInsertElementGenericTable (
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer,
    ULONG BufferSize,
    PBOOLEAN NewElement OPTIONAL
    );

PVOID
NTAPI
RtlInsertElementGenericTableFull (
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer,
    ULONG BufferSize,
    PBOOLEAN NewElement OPTIONAL,
    PVOID NodeOrParent,
    TABLE_SEARCH_RESULT SearchResult
    );

BOOLEAN
NTAPI
RtlDeleteElementGenericTable (
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer
    );

PVOID
NTAPI
RtlLookupElementGenericTable (
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer
    );

PVOID
NTAPI
RtlLookupElementGenericTableFull (
    PRTL_GENERIC_TABLE Table,
    PVOID Buffer,
    OUT PVOID *NodeOrParent,
    OUT TABLE_SEARCH_RESULT *SearchResult
    );

PVOID
NTAPI
RtlEnumerateGenericTable (
    PRTL_GENERIC_TABLE Table,
    BOOLEAN Restart
    );

PVOID
NTAPI
RtlEnumerateGenericTableWithoutSplaying (
    PRTL_GENERIC_TABLE Table,
    PVOID *RestartKey
    );

PVOID
NTAPI
RtlGetElementGenericTable(
    PRTL_GENERIC_TABLE Table,
    ULONG I
    );

ULONG
NTAPI
RtlNumberGenericTableElements(
    PRTL_GENERIC_TABLE Table
    );

BOOLEAN
NTAPI
RtlIsGenericTableEmpty (
    PRTL_GENERIC_TABLE Table
    );

NTSTATUS
NTAPI
RtlInitializeHeapManager(
    );

PVOID
NTAPI
RtlCreateHeap(
	IN ULONG Flags,
	IN PVOID HeapBase OPTIONAL,
	IN SIZE_T ReserveSize OPTIONAL,
	IN SIZE_T CommitSize OPTIONAL,
	IN PVOID Lock OPTIONAL,
	IN PRTL_HEAP_PARAMETERS Parameters OPTIONAL
	);

PVOID
NTAPI
RtlDestroyHeap(
    IN PVOID HeapHandle
    );

PVOID
NTAPI
RtlAllocateHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN SIZE_T Size
    );

BOOLEAN
NTAPI
RtlFreeHeap(
	IN PVOID HeapHandle,
	IN OPTIONAL ULONG Flags,
	IN PVOID BaseAddress
	);

SIZE_T
NTAPI
RtlSizeHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress
    );

NTSTATUS
NTAPI
RtlZeroHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags
    );

VOID
NTAPI
RtlProtectHeap(
    IN PVOID HeapHandle,
    IN BOOLEAN MakeReadOnly
    );

ULONG
NTAPI
RtlGetNtGlobalFlags(
    VOID
    );

VOID
NTAPI
RtlGetCallersAddress(
    OUT PVOID *CallersAddress,
    OUT PVOID *CallersCaller
    );

ULONG
NTAPI
RtlWalkFrameChain (
    OUT PVOID *Callers,
    IN ULONG Count,
    IN ULONG Flags
    );

USHORT
NTAPI
RtlLogStackBackTrace(
    VOID
    );


ULONG
NTAPI
RtlCaptureStackContext (
    OUT PULONG_PTR Callers,
    OUT PRTL_STACK_CONTEXT Context,
    IN ULONG Limit
    );

BOOLEAN
NTAPI
RtlGetNtProductType(
	PNT_PRODUCT_TYPE NtProductType
	);

NTSTATUS
NTAPI
RtlFormatCurrentUserKeyPath (
    OUT PUNICODE_STRING CurrentUserKeyPath
    );

NTSTATUS
NTAPI
RtlOpenCurrentUser(
    IN ULONG DesiredAccess,
    OUT PHANDLE CurrentUserKey
    );

NTSTATUS
NTAPI
RtlQueryRegistryValues(
    IN ULONG RelativeTo,
    IN PCWSTR Path,
    IN PRTL_QUERY_REGISTRY_TABLE QueryTable,
    IN PVOID Context,
    IN PVOID Environment OPTIONAL
    );

NTSTATUS
NTAPI
RtlWriteRegistryValue(
    IN ULONG RelativeTo,
    IN PCWSTR Path,
    IN PCWSTR ValueName,
    IN ULONG ValueType,
    IN PVOID ValueData,
    IN ULONG ValueLength
    );

NTSTATUS
NTAPI
RtlDeleteRegistryValue(
    IN ULONG RelativeTo,
    IN PCWSTR Path,
    IN PCWSTR ValueName
    );

NTSTATUS
NTAPI
RtlCreateRegistryKey(
	IN ULONG RelativeTo,
	IN PWSTR Path
    );

NTSTATUS
NTAPI
RtlCheckRegistryKey(
	IN ULONG RelativeTo,
	IN PWSTR Path
    );

//added 21/03/2011
//begin
BOOLEAN
NTAPI
RtlLockHeap(
	IN PVOID HeapHandle
	);


BOOLEAN
NTAPI
RtlUnlockHeap(
	IN PVOID HeapHandle
	);


PVOID
NTAPI
RtlReAllocateHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN SIZE_T Size
    );


BOOLEAN
NTAPI
RtlGetUserInfoHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	OUT OPTIONAL PVOID *UserValue,
	OUT OPTIONAL PULONG UserFlags
    );


BOOLEAN
NTAPI
RtlSetUserValueHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN PVOID UserValue
    );


BOOLEAN
NTAPI
RtlSetUserFlagsHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG UserFlagsReset,
	IN ULONG UserFlagsSet
	);


ULONG
NTAPI
RtlCreateTagHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN OPTIONAL PWSTR TagPrefix,
    IN PWSTR TagNames
    );


PWSTR
NTAPI
RtlQueryTagHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN USHORT TagIndex,
    IN BOOLEAN ResetCounters,
    OUT OPTIONAL PRTL_HEAP_TAG_INFO TagInfo
    );


NTSTATUS
NTAPI
RtlExtendHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PVOID Base,
    IN SIZE_T Size
    );


SIZE_T
NTAPI
RtlCompactHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags
    );


BOOLEAN
NTAPI
RtlValidateProcessHeaps(
    );

ULONG
NTAPI
RtlGetProcessHeaps(
    IN ULONG NumberOfHeaps,
    OUT PVOID *ProcessHeaps
    );


NTSTATUS
NTAPI
RtlUsageHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN OUT PRTL_HEAP_USAGE Usage
	);


NTSTATUS
NTAPI
RtlWalkHeap(
	IN PVOID HeapHandle,
	IN OUT PRTL_HEAP_WALK_ENTRY Entry
	);

#if !defined(_WINDOWS_)
NTSTATUS
NTAPI
RtlQueryHeapInformation(
	IN PVOID HeapHandle,
	IN HEAP_INFORMATION_CLASS HeapInformationClass,
	OUT OPTIONAL PVOID HeapInformation,
	IN OPTIONAL SIZE_T HeapInformationLength,
	OUT OPTIONAL PSIZE_T ReturnLength
	);

NTSTATUS
NTAPI
RtlSetHeapInformation(
	IN PVOID HeapHandle,
	IN HEAP_INFORMATION_CLASS HeapInformationClass,
	IN OPTIONAL PVOID HeapInformation,
	IN OPTIONAL SIZE_T HeapInformationLength
	);
#endif

ULONG
NTAPI
RtlMultipleAllocateHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN SIZE_T Size,
	IN ULONG Count,
	OUT PVOID *Array
	);

ULONG
NTAPI
RtlMultipleFreeHeap(
	IN PVOID HeapHandle,
	IN ULONG Flags,
	IN ULONG Count,
	IN PVOID *Array
	);

VOID
NTAPI
RtlDetectHeapLeaks(
	VOID
	);


#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
NTAPI
RtlCreateMemoryZone(
	OUT PVOID *MemoryZone,
	IN SIZE_T InitialSize,
	ULONG Flags
	);

NTSTATUS
NTAPI
RtlDestroyMemoryZone(
	IN PVOID MemoryZone
	);

NTSTATUS
NTAPI
RtlAllocateMemoryZone(
	IN PVOID MemoryZone,
	IN SIZE_T BlockSize,
	OUT PVOID *Block
	);

NTSTATUS
NTAPI
RtlResetMemoryZone(
	IN PVOID MemoryZone
	);

NTSTATUS
NTAPI
RtlLockMemoryZone(
	IN PVOID MemoryZone
	);

NTSTATUS
NTAPI
RtlUnlockMemoryZone(
	IN PVOID MemoryZone
	);
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS
NTAPI
RtlCreateMemoryBlockLookaside(
	OUT PVOID *MemoryBlockLookaside,
	IN ULONG Flags,
	IN ULONG InitialSize,
	IN ULONG MinimumBlockSize,
	IN ULONG MaximumBlockSize
	);

NTSTATUS
NTAPI
RtlDestroyMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside
	);

NTSTATUS
NTAPI
RtlAllocateMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside,
	IN ULONG BlockSize,
	OUT PVOID *Block
	);

NTSYSAPI
NTSTATUS
NTAPI
RtlFreeMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside,
	IN PVOID Block
	);

NTSTATUS
NTAPI
RtlExtendMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside,
	IN ULONG Increment
	);

NTSTATUS
NTAPI
RtlResetMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside
	);

NTSTATUS
NTAPI
RtlLockMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside
	);

NTSTATUS
NTAPI
RtlUnlockMemoryBlockLookaside(
	IN PVOID MemoryBlockLookaside
	);
#endif

HANDLE
NTAPI
RtlGetCurrentTransaction(
	);

LOGICAL
NTAPI
RtlSetCurrentTransaction(
	IN HANDLE TransactionHandle
	);

PRTL_DEBUG_INFORMATION
NTAPI
RtlCreateQueryDebugBuffer(
	IN OPTIONAL ULONG MaximumCommit,
	IN BOOLEAN UseEventPair
	);

NTSTATUS
NTAPI
RtlDestroyQueryDebugBuffer(
	IN PRTL_DEBUG_INFORMATION Buffer
	);

NTSTATUS
NTAPI
RtlQueryProcessDebugInformation(
	IN HANDLE UniqueProcessId,
	IN ULONG Flags,
	IN OUT PRTL_DEBUG_INFORMATION Buffer
	);


//added 21/03/2011
//end

ULONG
NTAPI
RtlUniform (
	PULONG Seed
    );

NTSTATUS
RtlComputeImportTableHash(
	IN HANDLE hFile,
	OUT PCHAR Hash,
	IN ULONG ImportTableHashRevision
    );

NTSTATUS
NTAPI
RtlIntegerToChar (
    ULONG Value,
    ULONG Base,
    LONG OutputLength,
    PSZ String
    );

NTSTATUS
NTAPI
RtlIntegerToUnicode (
    IN ULONG Value,
    IN ULONG Base OPTIONAL,
    IN LONG OutputLength,
    OUT PWSTR String
    );

NTSTATUS
NTAPI
RtlLargeIntegerToChar (
    PLARGE_INTEGER Value,
    ULONG Base OPTIONAL,
    LONG OutputLength,
    PSZ String
    );

NTSTATUS
NTAPI
RtlLargeIntegerToUnicode (
    IN PLARGE_INTEGER Value,
    IN ULONG Base OPTIONAL,
    IN LONG OutputLength,
    OUT PWSTR String
    );

PSTR
NTAPI
RtlIpv4AddressToStringA (
	IN const struct in_addr *Addr,
	OUT PSTR S
	);

PSTR
NTAPI
RtlIpv6AddressToStringA (
	IN const struct in6_addr *Addr,
	OUT PSTR S
	);

NTSTATUS
NTAPI
RtlIpv4AddressToStringExA(
    IN const struct in_addr *Address,
    IN USHORT Port,
    OUT PSTR AddressString,
    IN OUT PULONG AddressStringLength
    );

NTSTATUS
NTAPI
RtlIpv6AddressToStringExA(
    IN const struct in6_addr *Address,
    IN ULONG ScopeId,
    IN USHORT Port,
    OUT PSTR AddressString,
    IN OUT PULONG AddressStringLength
    );

PWSTR
NTAPI
RtlIpv4AddressToStringW (
    IN const struct in_addr *Addr,
    OUT PWSTR S
    );

PWSTR
NTAPI
RtlIpv6AddressToStringW (
    IN const struct in6_addr *Addr,
    OUT PWSTR S
    );

NTSTATUS
NTAPI
RtlIpv4AddressToStringExW(
    IN const struct in_addr *Address,
    IN USHORT Port,
    OUT PWSTR AddressString,
    IN OUT PULONG AddressStringLength
    );

NTSTATUS
NTAPI
RtlIpv6AddressToStringExW(
    IN const struct in6_addr *Address,
    IN ULONG ScopeId,
    IN USHORT Port,
    OUT PWSTR AddressString,
    IN OUT PULONG AddressStringLength
    );

NTSTATUS
NTAPI
RtlIpv4StringToAddressA (
    IN PCSTR S,
    IN BOOLEAN Strict,
    OUT PCSTR *Terminator,
    OUT struct in_addr *Addr
    );

NTSTATUS
NTAPI
RtlIpv6StringToAddressA (
    IN PCSTR S,
    OUT PCSTR *Terminator,
    OUT struct in6_addr *Addr
    );

NTSTATUS
NTAPI
RtlIpv4StringToAddressExA (
    IN PCSTR AddressString,
    IN BOOLEAN Strict,
    OUT struct in_addr *Address,
    OUT PUSHORT Port
    );

NTSTATUS
NTAPI
RtlIpv6StringToAddressExA (
    IN PCSTR AddressString,
    OUT struct in6_addr *Address,
    OUT PULONG ScopeId,
    OUT PUSHORT Port
    );

NTSTATUS
NTAPI
RtlIpv4StringToAddressW (
    IN PCWSTR S,
    IN BOOLEAN Strict,
    OUT LPCWSTR *Terminator,
    OUT struct in_addr *Addr
    );

NTSTATUS
NTAPI
RtlIpv6StringToAddressW (
    IN PCWSTR S,
    OUT PCWSTR *Terminator,
    OUT struct in6_addr *Addr
    );

NTSTATUS
NTAPI
RtlIpv4StringToAddressExW (
    IN PCWSTR AddressString,
    IN BOOLEAN Strict,
    OUT struct in_addr *Address,
    OUT PUSHORT Port
    );

NTSTATUS
NTAPI
RtlIpv6StringToAddressExW (
    IN PCWSTR AddressString,
    OUT struct in6_addr *Address,
    OUT PULONG ScopeId,
    OUT PUSHORT Port
    );

NTSTATUS
NTAPI
RtlIntegerToUnicodeString (
    ULONG Value,
    ULONG Base,
    PUNICODE_STRING String
    );

NTSTATUS
NTAPI
RtlInt64ToUnicodeString (
    IN ULONGLONG Value,
    IN ULONG Base OPTIONAL,
    IN OUT PUNICODE_STRING String
    );

NTSTATUS
NTAPI
RtlUnicodeStringToInteger (
    PCUNICODE_STRING String,
    ULONG Base,
    PULONG Value
    );

VOID
NTAPI
RtlInitString(
    PSTRING DestinationString,
    PCSZ SourceString
    );

VOID
NTAPI
RtlInitAnsiString(
    PANSI_STRING DestinationString,
    PCSZ SourceString
    );

NTSTATUS
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSTATUS
NTAPI
RtlInitAnsiStringEx(
    OUT PANSI_STRING DestinationString,
    IN PCSZ SourceString OPTIONAL
    );

BOOLEAN
NTAPI
RtlCreateUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
    );

BOOLEAN
NTAPI
RtlEqualDomainName(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2
    );

BOOLEAN
NTAPI
RtlEqualComputerName(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2
    );

NTSTATUS
RtlDnsHostNameToComputerName(
    OUT PUNICODE_STRING ComputerNameString,
    IN PCUNICODE_STRING DnsHostNameString,
    IN BOOLEAN AllocateComputerNameString
    );

BOOLEAN
NTAPI
RtlCreateUnicodeStringFromAsciiz(
    OUT PUNICODE_STRING DestinationString,
    IN PCSZ SourceString
    );

VOID
NTAPI
RtlCopyString(
    PSTRING DestinationString,
    const STRING * SourceString
    );

CHAR
NTAPI
RtlUpperChar (
    CHAR Character
    );

LONG
NTAPI
RtlCompareString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );

BOOLEAN
NTAPI
RtlEqualString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );

BOOLEAN
NTAPI
RtlPrefixString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );

VOID
NTAPI
RtlUpperString(
    PSTRING DestinationString,
    const STRING * SourceString
    );

NTSTATUS
NTAPI
RtlAppendAsciizToString (
    PSTRING Destination,
    PCSZ Source
    );

NTSTATUS
NTAPI
RtlAppendStringToString (
    PSTRING Destination,
    const STRING * Source
    );

NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    PUNICODE_STRING DestinationString,
    PCANSI_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

WCHAR
NTAPI
RtlAnsiCharToUnicodeChar(
    PUCHAR *SourceCharacter
    );

NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    PANSI_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToAnsiString(
    PANSI_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlOemStringToUnicodeString(
    PUNICODE_STRING DestinationString,
    PCOEM_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlUnicodeStringToOemString(
    POEM_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToOemString(
    POEM_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlOemStringToCountedUnicodeString(
    PUNICODE_STRING DestinationString,
    PCOEM_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlUnicodeStringToCountedOemString(
    POEM_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeStringToCountedOemString(
    POEM_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

LONG
NTAPI
RtlCompareUnicodeString(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
    );

BOOLEAN
NTAPI
RtlEqualUnicodeString(
    PCUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
    );

NTSTATUS
NTAPI
RtlHashUnicodeString(
    IN const UNICODE_STRING *String,
    IN BOOLEAN CaseInSensitive,
    IN ULONG HashAlgorithm,
    OUT PULONG HashValue
    );

NTSTATUS
NTAPI
RtlValidateUnicodeString(
    IN ULONG Flags,
    IN const UNICODE_STRING *String
    );

NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
    IN ULONG Flags,
    IN const UNICODE_STRING *StringIn,
    OUT UNICODE_STRING *StringOut
    );

BOOLEAN
NTAPI
RtlPrefixUnicodeString(
    IN PCUNICODE_STRING String1,
    IN PCUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeString(
    PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString
    );

NTSTATUS
NTAPI
RtlFindCharInUnicodeString(
    IN ULONG Flags,
    IN PCUNICODE_STRING StringToSearch,
    IN PCUNICODE_STRING CharSet,
    OUT USHORT *NonInclusivePrefixLength
    );

VOID
NTAPI
RtlCopyUnicodeString(
    PUNICODE_STRING DestinationString,
    PCUNICODE_STRING SourceString
    );

NTSTATUS
NTAPI
RtlAppendUnicodeStringToString (
    PUNICODE_STRING Destination,
    PCUNICODE_STRING Source
    );

NTSTATUS
NTAPI
RtlAppendUnicodeToString (
    PUNICODE_STRING Destination,
    PCWSTR Source
    );

WCHAR
NTAPI
RtlUpcaseUnicodeChar(
    WCHAR SourceCharacter
    );

WCHAR
NTAPI
RtlDowncaseUnicodeChar(
    WCHAR SourceCharacter
    );

VOID
NTAPI
RtlFreeUnicodeString(
    PUNICODE_STRING UnicodeString
    );

VOID
NTAPI
RtlFreeAnsiString(
    PANSI_STRING AnsiString
    );

VOID
NTAPI
RtlFreeOemString(
    POEM_STRING OemString
    );

ULONG
NTAPI
RtlxUnicodeStringToAnsiSize(
    PCUNICODE_STRING UnicodeString
    );

ULONG
NTAPI
RtlxUnicodeStringToOemSize(
    PCUNICODE_STRING UnicodeString
    );

ULONG
NTAPI
RtlxAnsiStringToUnicodeSize(
    PCANSI_STRING AnsiString
    );

ULONG
NTAPI
RtlxOemStringToUnicodeSize(
    PCOEM_STRING OemString
    );

NTSTATUS
NTAPI
RtlMultiByteToUnicodeN(
	OUT PWCH UnicodeString,
	IN ULONG MaxBytesInUnicodeString,
	OUT OPTIONAL PULONG BytesInUnicodeString,
	IN PCSTR MultiByteString,
	IN ULONG BytesInMultiByteString
    );

NTSTATUS
NTAPI
RtlMultiByteToUnicodeSize(
    PULONG BytesInUnicodeString,
    PCSTR MultiByteString,
    ULONG BytesInMultiByteString
    );

NTSTATUS
NTAPI
RtlUnicodeToMultiByteSize(
	OUT PULONG BytesInMultiByteString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
    );

NTSTATUS
NTAPI
RtlUnicodeToMultiByteN(
	OUT PCHAR MultiByteString,
	IN ULONG MaxBytesInMultiByteString,
	OUT OPTIONAL PULONG BytesInMultiByteString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
	);

NTSTATUS
NTAPI
RtlUpcaseUnicodeToMultiByteN(
	OUT PCHAR MultiByteString,
	IN ULONG MaxBytesInMultiByteString,
	OUT OPTIONAL PULONG BytesInMultiByteString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
    );

NTSTATUS
NTAPI
RtlOemToUnicodeN(
	OUT PWSTR UnicodeString,
	IN ULONG MaxBytesInUnicodeString,
	OUT OPTIONAL PULONG BytesInUnicodeString,
	IN PCH OemString,
	IN ULONG BytesInOemString
    );

NTSTATUS
NTAPI
RtlUnicodeToOemN(
	OUT PCHAR OemString,
	IN ULONG MaxBytesInOemString,
	OUT OPTIONAL PULONG BytesInOemString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeToOemN(
	OUT PCHAR OemString,
	IN ULONG MaxBytesInOemString,
	OUT OPTIONAL PULONG BytesInOemString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
    );

NTSTATUS
NTAPI
RtlConsoleMultiByteToUnicodeN(
	OUT PWCH UnicodeString,
	IN ULONG MaxBytesInUnicodeString,
	OUT OPTIONAL PULONG BytesInUnicodeString OPTIONAL,
	IN PCH MultiByteString,
	IN ULONG BytesInMultiByteString,
	OUT PULONG pdwSpecialChar );

BOOLEAN
NTAPI
RtlIsTextUnicode(
    IN CONST VOID* Buffer,
    IN ULONG Size,
    IN OUT PULONG Result OPTIONAL
    );

NTSTATUS
NTAPI
RtlStringFromGUID(
    IN REFGUID Guid,
    OUT PUNICODE_STRING GuidString
    );

NTSTATUS
NTAPI
RtlGUIDFromString(
    IN PUNICODE_STRING GuidString,
    OUT GUID* Guid
    );

VOID
NTAPI
RtlGenerate8dot3Name (
    IN PUNICODE_STRING Name,
    IN BOOLEAN AllowExtendedCharacters,
    IN OUT PGENERATE_NAME_CONTEXT Context,
    OUT PUNICODE_STRING Name8dot3
    );

BOOLEAN
NTAPI
RtlIsNameLegalDOS8Dot3 (
    IN PUNICODE_STRING Name,
    IN OUT POEM_STRING OemName OPTIONAL,
    IN OUT PBOOLEAN NameContainsSpaces OPTIONAL
    );

VOID
NTAPI
RtlInitializeContext(
    HANDLE Process,
    PCONTEXT Context,
    PVOID Parameter,
    PVOID InitialPc,
    PVOID InitialSp
    );

NTSTATUS
NTAPI
RtlRemoteCall(
    HANDLE Process,
    HANDLE Thread,
    PVOID CallSite,
    ULONG ArgumentCount,
    PULONG_PTR Arguments,
    BOOLEAN PassContext,
    BOOLEAN AlreadySuspended
    );

VOID
NTAPI
RtlAcquirePebLock(
	);

VOID
NTAPI
RtlReleasePebLock(
	);

NTSTATUS
NTAPI
RtlAllocateFromPeb(
	ULONG Size,
	PVOID *Block
	);

NTSTATUS
NTAPI
RtlFreeToPeb(
	PVOID Block,
	ULONG Size
	);

NTSTATUS
STDAPIVCALLTYPE
RtlSetProcessIsCritical(
    IN  BOOLEAN  NewValue,
    OUT PBOOLEAN OldValue OPTIONAL,
    IN  BOOLEAN  CheckFlag
    );

NTSTATUS
STDAPIVCALLTYPE
RtlSetThreadIsCritical(
    IN  BOOLEAN  NewValue,
    OUT PBOOLEAN OldValue OPTIONAL,
    IN  BOOLEAN  CheckFlag
    );

NTSTATUS
NTAPI
RtlCreateEnvironment(
    BOOLEAN CloneCurrentEnvironment,
    PVOID *Environment
    );

NTSTATUS
NTAPI
RtlDestroyEnvironment(
    PVOID Environment
    );

NTSTATUS
NTAPI
RtlSetCurrentEnvironment(
    PVOID Environment,
    PVOID *PreviousEnvironment
    );

NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    PVOID *Environment,
    PCUNICODE_STRING Name,
    PCUNICODE_STRING Value
    );

ULONG
RtlIsDosDeviceName_U(
	IN PWSTR DosFileName
	);

NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U (
    PVOID Environment,
    PCUNICODE_STRING Name,
    PUNICODE_STRING Value
    );

NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(
    IN PVOID Environment OPTIONAL,
    IN PCUNICODE_STRING Source,
    OUT PUNICODE_STRING Destination,
    OUT PULONG ReturnedLength OPTIONAL
    );

VOID
NTAPI
PfxInitialize (
    PPREFIX_TABLE PrefixTable
    );

BOOLEAN
NTAPI
PfxInsertPrefix (
    PPREFIX_TABLE PrefixTable,
    PSTRING Prefix,
    PPREFIX_TABLE_ENTRY PrefixTableEntry
    );

VOID
NTAPI
PfxRemovePrefix (
    PPREFIX_TABLE PrefixTable,
    PPREFIX_TABLE_ENTRY PrefixTableEntry
    );

PPREFIX_TABLE_ENTRY
NTAPI
PfxFindPrefix (
    PPREFIX_TABLE PrefixTable,
    PSTRING FullName
    );

VOID
NTAPI
RtlInitializeUnicodePrefix (
    PUNICODE_PREFIX_TABLE PrefixTable
    );

BOOLEAN
NTAPI
RtlInsertUnicodePrefix (
    PUNICODE_PREFIX_TABLE PrefixTable,
    PUNICODE_STRING Prefix,
    PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );

VOID
NTAPI
RtlRemoveUnicodePrefix (
    PUNICODE_PREFIX_TABLE PrefixTable,
    PUNICODE_PREFIX_TABLE_ENTRY PrefixTableEntry
    );

PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlFindUnicodePrefix (
    PUNICODE_PREFIX_TABLE PrefixTable,
    PUNICODE_STRING FullName,
    ULONG CaseInsensitiveIndex
    );

PUNICODE_PREFIX_TABLE_ENTRY
NTAPI
RtlNextUnicodePrefix (
    PUNICODE_PREFIX_TABLE PrefixTable,
    BOOLEAN Restart
    );

NTSTATUS
NTAPI
RtlGetCompressionWorkSpaceSize (
    IN USHORT CompressionFormatAndEngine,
    OUT PULONG CompressBufferWorkSpaceSize,
    OUT PULONG CompressFragmentWorkSpaceSize
    );

NTSTATUS
NTAPI
RtlCompressBuffer (
    IN USHORT CompressionFormatAndEngine,
    IN PUCHAR UncompressedBuffer,
    IN ULONG UncompressedBufferSize,
    OUT PUCHAR CompressedBuffer,
    IN ULONG CompressedBufferSize,
    IN ULONG UncompressedChunkSize,
    OUT PULONG FinalCompressedSize,
    IN PVOID WorkSpace
    );

NTSTATUS
NTAPI
RtlDecompressBuffer (
    IN USHORT CompressionFormat,
    OUT PUCHAR UncompressedBuffer,
    IN ULONG UncompressedBufferSize,
    IN PUCHAR CompressedBuffer,
    IN ULONG CompressedBufferSize,
    OUT PULONG FinalUncompressedSize
    );

NTSTATUS
NTAPI
RtlDecompressFragment (
    IN USHORT CompressionFormat,
    OUT PUCHAR UncompressedFragment,
    IN ULONG UncompressedFragmentSize,
    IN PUCHAR CompressedBuffer,
    IN ULONG CompressedBufferSize,
    IN ULONG FragmentOffset,
    OUT PULONG FinalUncompressedSize,
    IN PVOID WorkSpace
    );

NTSTATUS
NTAPI
RtlDescribeChunk (
    IN USHORT CompressionFormat,
    IN OUT PUCHAR *CompressedBuffer,
    IN PUCHAR EndOfCompressedBufferPlus1,
    OUT PUCHAR *ChunkBuffer,
    OUT PULONG ChunkSize
    );

NTSTATUS
NTAPI
RtlReserveChunk (
    IN USHORT CompressionFormat,
    IN OUT PUCHAR *CompressedBuffer,
    IN PUCHAR EndOfCompressedBufferPlus1,
    OUT PUCHAR *ChunkBuffer,
    IN ULONG ChunkSize
    );

NTSTATUS
NTAPI
RtlDecompressChunks (
    OUT PUCHAR UncompressedBuffer,
    IN ULONG UncompressedBufferSize,
    IN PUCHAR CompressedBuffer,
    IN ULONG CompressedBufferSize,
    IN PUCHAR CompressedTail,
    IN ULONG CompressedTailSize,
    IN PCOMPRESSED_DATA_INFO CompressedDataInfo
    );

NTSTATUS
NTAPI
RtlCompressChunks (
    IN PUCHAR UncompressedBuffer,
    IN ULONG UncompressedBufferSize,
    OUT PUCHAR CompressedBuffer,
    IN ULONG CompressedBufferSize,
    IN OUT PCOMPRESSED_DATA_INFO CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PVOID WorkSpace
    );

NTSTATUS
NTAPI
RtlCreateProcessParameters(
    PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData
    );

NTSTATUS
NTAPI
RtlDestroyProcessParameters(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlDeNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

NTSTATUS
NTAPI
RtlCreateUserProcess(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

NTSTATUS
NTAPI
RtlCreateUserThread(
    HANDLE Process,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    SIZE_T MaximumStackSize OPTIONAL,
    SIZE_T InitialStackSize OPTIONAL,
    PUSER_THREAD_START_ROUTINE StartAddress,
    PVOID Parameter,
    PHANDLE Thread,
    PCLIENT_ID ClientId
    );

VOID
NTAPI
RtlExitUserThread (
    IN NTSTATUS ExitStatus
    );

VOID
NTAPI
RtlFreeUserThreadStack(
    HANDLE hProcess,
    HANDLE hThread
    );
/*
PVOID
NTAPI
RtlPcToFileHeader(
    PVOID PcValue,
    PVOID *BaseOfImage
    );*/

NTSTATUS
NTAPI
RtlImageNtHeaderEx(
    ULONG Flags,
    PVOID Base,
    ULONG64 Size,
    OUT PIMAGE_NT_HEADERS * OutHeaders
    );

PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    PVOID Base
    );

PVOID
NTAPI
RtlAddressInSectionTable (
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID BaseOfImage,
    IN ULONG VirtualAddress
    );

PIMAGE_SECTION_HEADER
NTAPI
RtlSectionTableFromVirtualAddress (
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID BaseOfImage,
    IN ULONG VirtualAddress
    );

NTSTATUS
NTAPI
RtlImageDirectoryEntryToData(
    PVOID BaseOfImage,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
    );

PVOID
RtlImageDirectoryEntryToData32 (
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
    );

PIMAGE_SECTION_HEADER
NTAPI
RtlImageRvaToSection(
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Rva
    );

PVOID
NTAPI
RtlImageRvaToVa(
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Rva,
    IN OUT PIMAGE_SECTION_HEADER *LastRvaSection OPTIONAL
    );


VOID
NTAPI
RtlCopyMemoryNonTemporal (
   VOID UNALIGNED *Destination,
   CONST VOID UNALIGNED *Source,
   SIZE_T Length
   );

VOID __fastcall
RtlPrefetchMemoryNonTemporal(
    IN PVOID Source,
    IN SIZE_T Length
    );

SIZE_T
NTAPI
RtlCompareMemoryUlong (
    PVOID Source,
    SIZE_T Length,
    ULONG Pattern
    );

VOID
NTAPI
RtlFillMemoryUlong (
   PVOID Destination,
   SIZE_T Length,
   ULONG Pattern
   );

VOID
NTAPI
RtlFillMemoryUlonglong (
   PVOID Destination,
   SIZE_T Length,
   ULONGLONG Pattern
   );

VOID
NTAPI
RtlInitializeExceptionLog(
    IN ULONG Entries
    );

LONG
NTAPI
RtlUnhandledExceptionFilter(
    IN struct _EXCEPTION_POINTERS *ExceptionInfo
    );

LONG
NTAPI
RtlUnhandledExceptionFilter2(
    IN struct _EXCEPTION_POINTERS *ExceptionInfo,
    IN PCSTR Function
    );

VOID
NTAPI
DbgUserBreakPoint(
    VOID
    );

VOID
NTAPI
DbgBreakPointWithStatus(
    IN ULONG Status
    );

ULONG
DbgPrintEx (
	IN ULONG ComponentId,
	IN ULONG Level,
	IN PCH Format,
	...
    );

ULONG
NTAPI
vDbgPrintEx(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCH Format,
    IN va_list arglist
    );

ULONG
NTAPI
vDbgPrintExWithPrefix (
    IN PCH Prefix,
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCH Format,
    IN va_list arglist
    );

ULONG
DbgPrintReturnControlC (
	IN PCHAR Format,
	...
    );

NTSTATUS
NTAPI
DbgQueryDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level
    );

NTSTATUS
NTAPI
DbgSetDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level,
    IN BOOLEAN State
    );

ULONG
NTAPI
DbgPrompt (
	IN PCH Prompt,
	OUT PCH Response,
	IN ULONG Length
    );

VOID
NTAPI
DbgLoadImageSymbols (
	IN PSTRING FileName,
	IN PVOID ImageBase,
	IN ULONG_PTR ProcessId
    );

VOID
NTAPI
DbgUnLoadImageSymbols (
	IN PSTRING FileName,
	IN PVOID ImageBase,
	IN ULONG_PTR ProcessId
    );

VOID
NTAPI
DbgCommandString (
	IN PCH Name,
	IN PCH Command
    );

BOOLEAN
NTAPI
RtlCutoverTimeToSystemTime(
    PTIME_FIELDS CutoverTime,
    PLARGE_INTEGER SystemTime,
    PLARGE_INTEGER CurrentSystemTime,
    BOOLEAN ThisYear
    );

NTSTATUS
NTAPI
RtlSystemTimeToLocalTime (
    IN PLARGE_INTEGER SystemTime,
    OUT PLARGE_INTEGER LocalTime
    );

NTSTATUS
NTAPI
RtlLocalTimeToSystemTime (
    IN PLARGE_INTEGER LocalTime,
    OUT PLARGE_INTEGER SystemTime
    );

VOID
NTAPI
RtlTimeToElapsedTimeFields (
    IN PLARGE_INTEGER Time,
    OUT PTIME_FIELDS TimeFields
    );

VOID
NTAPI
RtlTimeToTimeFields (
    PLARGE_INTEGER Time,
    PTIME_FIELDS TimeFields
    );

BOOLEAN
NTAPI
RtlTimeFieldsToTime (
    PTIME_FIELDS TimeFields,
    PLARGE_INTEGER Time
    );

BOOLEAN
NTAPI
RtlTimeToSecondsSince1980 (
    PLARGE_INTEGER Time,
    PULONG ElapsedSeconds
    );

VOID
NTAPI
RtlSecondsSince1980ToTime (
    ULONG ElapsedSeconds,
    PLARGE_INTEGER Time
    );

BOOLEAN
NTAPI
RtlTimeToSecondsSince1970 (
    PLARGE_INTEGER Time,
    PULONG ElapsedSeconds
    );

VOID
NTAPI
RtlSecondsSince1970ToTime (
    ULONG ElapsedSeconds,
    PLARGE_INTEGER Time
    );

NTSTATUS
NTAPI
RtlQueryTimeZoneInformation(
    OUT PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
    );

NTSTATUS
NTAPI
RtlSetTimeZoneInformation(
    IN PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
    );

NTSTATUS
NTAPI
RtlSetActiveTimeBias(
    IN LONG ActiveBias
    );

VOID
NTAPI
RtlInitializeBitMap (
    PRTL_BITMAP BitMapHeader,
    PULONG BitMapBuffer,
    ULONG SizeOfBitMap
    );

VOID
NTAPI
RtlClearBit (
    PRTL_BITMAP BitMapHeader,
    ULONG BitNumber
    );

VOID
NTAPI
RtlSetBit (
    PRTL_BITMAP BitMapHeader,
    ULONG BitNumber
    );

BOOLEAN
NTAPI
RtlTestBit (
    PRTL_BITMAP BitMapHeader,
    ULONG BitNumber
    );

VOID
NTAPI
RtlClearAllBits (
    PRTL_BITMAP BitMapHeader
    );

VOID
NTAPI
RtlSetAllBits (
    PRTL_BITMAP BitMapHeader
    );

ULONG
NTAPI
RtlFindClearBits (
    PRTL_BITMAP BitMapHeader,
    ULONG NumberToFind,
    ULONG HintIndex
    );

ULONG
NTAPI
RtlFindSetBits (
    PRTL_BITMAP BitMapHeader,
    ULONG NumberToFind,
    ULONG HintIndex
    );

ULONG
NTAPI
RtlFindClearBitsAndSet (
    PRTL_BITMAP BitMapHeader,
    ULONG NumberToFind,
    ULONG HintIndex
    );

ULONG
NTAPI
RtlFindSetBitsAndClear (
    PRTL_BITMAP BitMapHeader,
    ULONG NumberToFind,
    ULONG HintIndex
    );

VOID
NTAPI
RtlClearBits (
    PRTL_BITMAP BitMapHeader,
    ULONG StartingIndex,
    ULONG NumberToClear
    );

VOID
NTAPI
RtlSetBits (
    PRTL_BITMAP BitMapHeader,
    ULONG StartingIndex,
    ULONG NumberToSet
    );

ULONG
NTAPI
RtlFindClearRuns (
    PRTL_BITMAP BitMapHeader,
    PRTL_BITMAP_RUN RunArray,
    ULONG SizeOfRunArray,
    BOOLEAN LocateLongestRuns
    );

ULONG
NTAPI
RtlFindLongestRunClear (
    PRTL_BITMAP BitMapHeader,
    PULONG StartingIndex
    );

ULONG
NTAPI
RtlFindFirstRunClear (
    PRTL_BITMAP BitMapHeader,
    PULONG StartingIndex
    );

ULONG
NTAPI
RtlNumberOfClearBits (
    PRTL_BITMAP BitMapHeader
    );

ULONG
NTAPI
RtlNumberOfSetBits (
    PRTL_BITMAP BitMapHeader
    );

BOOLEAN
NTAPI
RtlAreBitsClear (
    PRTL_BITMAP BitMapHeader,
    ULONG StartingIndex,
    ULONG Length
    );

BOOLEAN
NTAPI
RtlAreBitsSet (
    PRTL_BITMAP BitMapHeader,
    ULONG StartingIndex,
    ULONG Length
    );

ULONG
NTAPI
RtlFindNextForwardRunClear (
    IN PRTL_BITMAP BitMapHeader,
    IN ULONG FromIndex,
    IN PULONG StartingRunIndex
    );

ULONG
NTAPI
RtlFindLastBackwardRunClear (
    IN PRTL_BITMAP BitMapHeader,
    IN ULONG FromIndex,
    IN PULONG StartingRunIndex
    );

CCHAR
NTAPI
RtlFindLeastSignificantBit (
    IN ULONGLONG Set
    );

CCHAR
NTAPI
RtlFindMostSignificantBit (
    IN ULONGLONG Set
    );

BOOLEAN
NTAPI
RtlValidSid (
    PSID Sid
    );

BOOLEAN
NTAPI
RtlEqualSid (
    PSID Sid1,
    PSID Sid2
    );

BOOLEAN
NTAPI
RtlEqualPrefixSid (
    PSID Sid1,
    PSID Sid2
    );

ULONG
NTAPI
RtlLengthRequiredSid (
    ULONG SubAuthorityCount
    );

PVOID
NTAPI
RtlFreeSid(
    IN PSID Sid
    );

NTSTATUS
NTAPI
RtlInitializeSid(
	OUT PSID Sid,
	IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	IN UCHAR SubAuthorityCount
	);

NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(
    IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    IN UCHAR SubAuthorityCount,
    IN ULONG SubAuthority0,
    IN ULONG SubAuthority1,
    IN ULONG SubAuthority2,
    IN ULONG SubAuthority3,
    IN ULONG SubAuthority4,
    IN ULONG SubAuthority5,
    IN ULONG SubAuthority6,
    IN ULONG SubAuthority7,
    OUT PSID *Sid
    );

PSID_IDENTIFIER_AUTHORITY
NTAPI
RtlIdentifierAuthoritySid (
    PSID Sid
    );

PULONG
NTAPI
RtlSubAuthoritySid(
	IN PSID Sid,
	IN ULONG SubAuthority
	);

PUCHAR
NTAPI
RtlSubAuthorityCountSid (
    PSID Sid
    );

ULONG
NTAPI
RtlLengthSid (
    PSID Sid
    );

NTSTATUS
NTAPI
RtlCopySid (
    ULONG DestinationSidLength,
    PSID DestinationSid,
    PSID SourceSid
    );

NTSTATUS
NTAPI
RtlCopySidAndAttributesArray (
    ULONG ArrayLength,
    PSID_AND_ATTRIBUTES Source,
    ULONG TargetSidBufferSize,
    PSID_AND_ATTRIBUTES TargetArrayElement,
    PSID TargetSid,
    PSID *NextTargetSid,
    PULONG RemainingTargetSidSize
    );

NTSTATUS
NTAPI
RtlLengthSidAsUnicodeString(
    PSID Sid,
    PULONG StringLength
    );

NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
    PUNICODE_STRING UnicodeString,
    PSID Sid,
    BOOLEAN AllocateDestinationString
    );

VOID
NTAPI
RtlCopyLuid (
    PLUID DestinationLuid,
    PLUID SourceLuid
    );

VOID
NTAPI
RtlCopyLuidAndAttributesArray (
    ULONG ArrayLength,
    PLUID_AND_ATTRIBUTES Source,
    PLUID_AND_ATTRIBUTES Target
    );

BOOLEAN
NTAPI
RtlAreAllAccessesGranted(
    ACCESS_MASK GrantedAccess,
    ACCESS_MASK DesiredAccess
    );

BOOLEAN
NTAPI
RtlAreAnyAccessesGranted(
    ACCESS_MASK GrantedAccess,
    ACCESS_MASK DesiredAccess
    );

VOID
NTAPI
RtlMapGenericMask(
    PACCESS_MASK AccessMask,
    PGENERIC_MAPPING GenericMapping
    );

NTSTATUS
NTAPI
RtlCreateAcl(
	OUT PACL Acl,
	IN ULONG AclLength,
	IN ULONG AclRevision
	);

BOOLEAN
NTAPI
RtlValidAcl(
	PACL Acl
	);

NTSTATUS
NTAPI
RtlQueryInformationAcl(
	PACL Acl,
	PVOID AclInformation,
	ULONG AclInformationLength,
	ACL_INFORMATION_CLASS AclInformationClass
	);

NTSTATUS
NTAPI
RtlSetInformationAcl(
	PACL Acl,
	PVOID AclInformation,
	ULONG AclInformationLength,
	ACL_INFORMATION_CLASS AclInformationClass
	);

NTSTATUS
NTAPI
RtlAddAce(
	PACL Acl,
	ULONG AceRevision,
	ULONG StartingAceIndex,
	PVOID AceList,
	ULONG AceListLength
	);

NTSTATUS
NTAPI
RtlDeleteAce(
	PACL Acl,
	ULONG AceIndex
	);

NTSTATUS
NTAPI
RtlGetAce(
	PACL Acl,
	ULONG AceIndex,
	PVOID *Ace
	);

NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(
	IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN OPTIONAL PSID Owner,
	IN OPTIONAL BOOLEAN OwnerDefaulted
	);

NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	OUT PSID *Owner,
	OUT PBOOLEAN OwnerDefaulted
	);

NTSTATUS
NTAPI
RtlAddAccessAllowedAce(
	PACL Acl,
	ULONG AceRevision,
	ACCESS_MASK AccessMask,
	PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx(
	PACL Acl,
	ULONG AceRevision,
	ULONG AceFlags,
	ACCESS_MASK AccessMask,
	PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAccessDeniedAce(
	PACL Acl,
	ULONG AceRevision,
	ACCESS_MASK AccessMask,
	PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAccessDeniedAceEx(
	PACL Acl,
	ULONG AceRevision,
	ULONG AceFlags,
	ACCESS_MASK AccessMask,
	PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAuditAccessAce(
	PACL Acl,
	ULONG AceRevision,
	ACCESS_MASK AccessMask,
	PSID Sid,
	BOOLEAN AuditSuccess,
	BOOLEAN AuditFailure
	);

NTSTATUS
NTAPI
RtlAddAuditAccessAceEx(
	PACL Acl,
	ULONG AceRevision,
	ULONG AceFlags,
	ACCESS_MASK AccessMask,
	PSID Sid,
	BOOLEAN AuditSuccess,
	BOOLEAN AuditFailure
	);

NTSTATUS
NTAPI
RtlAddAccessAllowedObjectAce(
	IN OUT PACL Acl,
	IN ULONG AceRevision,
	IN ULONG AceFlags,
	IN ACCESS_MASK AccessMask,
	IN GUID *ObjectTypeGuid OPTIONAL,
	IN GUID *InheritedObjectTypeGuid OPTIONAL,
	IN PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAccessDeniedObjectAce(
	IN OUT PACL Acl,
	IN ULONG AceRevision,
	IN ULONG AceFlags,
	IN ACCESS_MASK AccessMask,
	IN GUID *ObjectTypeGuid OPTIONAL,
	IN GUID *InheritedObjectTypeGuid OPTIONAL,
	IN PSID Sid
	);

NTSTATUS
NTAPI
RtlAddAuditAccessObjectAce(
	IN OUT PACL Acl,
	IN ULONG AceRevision,
	IN ULONG AceFlags,
	IN ACCESS_MASK AccessMask,
	IN GUID *ObjectTypeGuid OPTIONAL,
	IN GUID *InheritedObjectTypeGuid OPTIONAL,
	IN PSID Sid,
	BOOLEAN AuditSuccess,
	BOOLEAN AuditFailure
	);

BOOLEAN
NTAPI
RtlFirstFreeAce(
	PACL Acl,
	PVOID *FirstFree
	);

NTSTATUS
NTAPI
RtlAddCompoundAce(
	IN PACL Acl,
	IN ULONG AceRevision,
	IN UCHAR AceType,
	IN ACCESS_MASK AccessMask,
	IN PSID ServerSid,
	IN PSID ClientSid
	);

NTSTATUS
NTAPI
RtlCreateSecurityDescriptor(
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG Revision
    );

NTSTATUS
NTAPI
RtlCreateSecurityDescriptorRelative(
    PISECURITY_DESCRIPTOR_RELATIVE SecurityDescriptor,
    ULONG Revision
    );

BOOLEAN
NTAPI
RtlValidSecurityDescriptor(
    PSECURITY_DESCRIPTOR SecurityDescriptor
    );

ULONG
NTAPI
RtlLengthSecurityDescriptor(
    PSECURITY_DESCRIPTOR SecurityDescriptor
    );

BOOLEAN
NTAPI
RtlValidRelativeSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptorInput,
    IN ULONG SecurityDescriptorLength,
    IN SECURITY_INFORMATION RequiredInformation
    );

NTSTATUS
NTAPI
RtlGetControlSecurityDescriptor (
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PSECURITY_DESCRIPTOR_CONTROL Control,
    PULONG Revision
    );

NTSTATUS
NTAPI
RtlSetControlSecurityDescriptor (
     IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
     IN SECURITY_DESCRIPTOR_CONTROL ControlBitsOfInterest,
     IN SECURITY_DESCRIPTOR_CONTROL ControlBitsToSet
     );

NTSTATUS
NTAPI
RtlSetAttributesSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN SECURITY_DESCRIPTOR_CONTROL Control,
    IN OUT PULONG Revision
    );

NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor (
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN DaclPresent,
    PACL Dacl,
    BOOLEAN DaclDefaulted
    );

NTSTATUS
NTAPI
RtlGetDaclSecurityDescriptor (
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PBOOLEAN DaclPresent,
    OUT PACL *Dacl,
    OUT PBOOLEAN DaclDefaulted
    );

BOOLEAN
NTAPI
RtlGetSecurityDescriptorRMControl(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PUCHAR RMControl
    );

VOID
NTAPI
RtlSetSecurityDescriptorRMControl(
    IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PUCHAR RMControl OPTIONAL
    );

NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor (
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN SaclPresent,
    PACL Sacl,
    BOOLEAN SaclDefaulted
    );

NTSTATUS
NTAPI
RtlGetSaclSecurityDescriptor (
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PBOOLEAN SaclPresent,
    OUT PACL *Sacl,
    OUT PBOOLEAN SaclDefaulted
    );

NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor (
    IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID Group OPTIONAL,
    IN BOOLEAN GroupDefaulted OPTIONAL
    );

NTSTATUS
NTAPI
RtlGetGroupSecurityDescriptor (
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PSID *Group,
    OUT PBOOLEAN GroupDefaulted
    );

NTSTATUS
NTAPI
RtlMakeSelfRelativeSD (
    IN PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    IN OUT PULONG BufferLength
    );

NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD (
    IN PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    IN OUT PULONG BufferLength
    );

NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD (
    IN PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    OUT OPTIONAL PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    IN OUT PULONG AbsoluteSecurityDescriptorSize,
    OUT OPTIONAL PACL Dacl,
    IN OUT PULONG DaclSize,
    OUT OPTIONAL PACL Sacl,
    IN OUT PULONG SaclSize,
    OUT OPTIONAL PSID Owner,
    IN OUT PULONG OwnerSize,
    OUT OPTIONAL PSID PrimaryGroup,
    IN OUT PULONG PrimaryGroupSize
    );

NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD2 (
    IN OUT PSECURITY_DESCRIPTOR pSelfRelativeSecurityDescriptor,
    IN OUT PULONG pBufferSize
    );

NTSTATUS
NTAPI
RtlNewSecurityGrantedAccess (
    ACCESS_MASK DesiredAccess,
    PPRIVILEGE_SET Privileges,
    PULONG Length,
    HANDLE Token,
    PGENERIC_MAPPING GenericMapping,
    PACCESS_MASK RemainingDesiredAccess
    );

NTSTATUS
NTAPI
RtlMapSecurityErrorToNtStatus (
    SECURITY_STATUS Error
    );

NTSTATUS
NTAPI
RtlImpersonateSelf (
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
    );

NTSTATUS
NTAPI
RtlAdjustPrivilege (
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
    );

NTSTATUS
NTAPI
RtlAcquirePrivilege (
    PULONG Privilege,
    ULONG NumPriv,
    ULONG Flags,
    PVOID *ReturnedState
    );

VOID
NTAPI
RtlReleasePrivilege (
    PVOID StatePointer
    );

VOID
NTAPI
RtlRunEncodeUnicodeString(
    PUCHAR          Seed        OPTIONAL,
    PUNICODE_STRING String
    );

VOID
NTAPI
RtlRunDecodeUnicodeString(
    UCHAR           Seed,
    PUNICODE_STRING String
    );

VOID
NTAPI
RtlEraseUnicodeString(
    PUNICODE_STRING String
    );

NTSTATUS
NTAPI
RtlFindMessage(
    PVOID DllHandle,
    ULONG MessageTableId,
    ULONG MessageLanguageId,
    ULONG MessageId,
    PMESSAGE_RESOURCE_ENTRY *MessageEntry
    );

NTSTATUS
NTAPI
RtlFormatMessage(
	IN PWSTR MessageFormat,
	IN ULONG MaximumWidth,
	IN BOOLEAN IgnoreInserts,
	IN BOOLEAN ArgumentsAreAnsi,
	IN BOOLEAN ArgumentsAreAnArray,
	IN va_list *Arguments,
	OUT PWSTR Buffer,
	IN ULONG Length,
	OUT OPTIONAL PULONG ReturnLength
    );

NTSTATUS
NTAPI
RtlFormatMessageEx(
	IN PWSTR MessageFormat,
	IN ULONG MaximumWidth,
	IN BOOLEAN IgnoreInserts,
	IN BOOLEAN ArgumentsAreAnsi,
	IN BOOLEAN ArgumentsAreAnArray,
	IN va_list *Arguments,
	OUT PWSTR Buffer,
	IN ULONG Length,
	OUT OPTIONAL PULONG ReturnLength,
	OUT OPTIONAL PPARSE_MESSAGE_CONTEXT ParseContext
    );

NTSTATUS
NTAPI
RtlInitializeRXact(
    IN HANDLE RootRegistryKey,
    IN BOOLEAN CommitIfNecessary,
    OUT PRTL_RXACT_CONTEXT *RXactContext
    );

NTSTATUS
NTAPI
RtlStartRXact(
    IN PRTL_RXACT_CONTEXT RXactContext
    );

NTSTATUS
NTAPI
RtlAbortRXact(
    IN PRTL_RXACT_CONTEXT RXactContext
    );

NTSTATUS
NTAPI
RtlAddAttributeActionToRXact(
    IN PRTL_RXACT_CONTEXT RXactContext,
    IN RTL_RXACT_OPERATION Operation,
    IN PUNICODE_STRING SubKeyName,
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING AttributeName,
    IN ULONG NewValueType,
    IN PVOID NewValue,
    IN ULONG NewValueLength
    );

NTSTATUS
NTAPI
RtlAddActionToRXact(
    IN PRTL_RXACT_CONTEXT RXactContext,
    IN RTL_RXACT_OPERATION Operation,
    IN PUNICODE_STRING SubKeyName,
    IN ULONG NewKeyValueType,
    IN PVOID NewKeyValue OPTIONAL,
    IN ULONG NewKeyValueLength
    );

NTSTATUS
NTAPI
RtlApplyRXact(
    IN PRTL_RXACT_CONTEXT RXactContext
    );

NTSTATUS
NTAPI
RtlApplyRXactNoFlush(
    IN PRTL_RXACT_CONTEXT RXactContext
    );

ULONG
NTAPI
RtlNtStatusToDosError (
   NTSTATUS Status
   );

ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb (
   NTSTATUS Status
   );

PPEB
RtlGetCurrentPeb (
    VOID
    );

NTSTATUS
NTAPI
RtlCustomCPToUnicodeN(
	IN PCPTABLEINFO CustomCP,
	OUT PWCH UnicodeString,
	IN ULONG MaxBytesInUnicodeString,
	OUT OPTIONAL PULONG BytesInUnicodeString,
	IN PCH CustomCPString,
	IN ULONG BytesInCustomCPString
    );

NTSTATUS
NTAPI
RtlUnicodeToCustomCPN(
	IN PCPTABLEINFO CustomCP,
	OUT PCH CustomCPString,
	IN ULONG MaxBytesInCustomCPString,
	OUT OPTIONAL PULONG BytesInCustomCPString,
	IN PWCH UnicodeString,
	IN ULONG BytesInUnicodeString
    );

NTSTATUS
NTAPI
RtlUpcaseUnicodeToCustomCPN(
    IN PCPTABLEINFO CustomCP,
    OUT PCH CustomCPString,
    IN ULONG MaxBytesInCustomCPString,
    OUT OPTIONAL PULONG BytesInCustomCPString,
    IN PWCH UnicodeString,
    IN ULONG BytesInUnicodeString
    );

VOID
NTAPI
RtlInitCodePageTable(
    IN PUSHORT TableBase,
    OUT PCPTABLEINFO CodePageTable
    );

VOID
NTAPI
RtlInitNlsTables(
    IN PUSHORT AnsiNlsBase,
    IN PUSHORT OemNlsBase,
    IN PUSHORT LanguageNlsBase,
    OUT PNLSTABLEINFO TableInfo
    );

VOID
NTAPI
RtlResetRtlTranslations(
    PNLSTABLEINFO TableInfo
    );

VOID
NTAPI
RtlGetDefaultCodePage(
    OUT PUSHORT AnsiCodePage,
    OUT PUSHORT OemCodePage
    );

VOID
NTAPI
RtlInitializeRangeList(
    IN OUT PRTL_RANGE_LIST RangeList
    );

VOID
NTAPI
RtlFreeRangeList(
    IN PRTL_RANGE_LIST RangeList
    );

NTSTATUS
NTAPI
RtlCopyRangeList(
    OUT PRTL_RANGE_LIST CopyRangeList,
    IN PRTL_RANGE_LIST RangeList
    );

NTSTATUS
NTAPI
RtlAddRange(
    IN OUT PRTL_RANGE_LIST RangeList,
    IN ULONGLONG Start,
    IN ULONGLONG End,
    IN UCHAR Attributes,
    IN ULONG Flags,
    IN PVOID UserData,  OPTIONAL
    IN PVOID Owner      OPTIONAL
    );

NTSTATUS
NTAPI
RtlDeleteRange(
    IN OUT PRTL_RANGE_LIST RangeList,
    IN ULONGLONG Start,
    IN ULONGLONG End,
    IN PVOID Owner
    );

NTSTATUS
NTAPI
RtlDeleteOwnersRanges(
    IN OUT PRTL_RANGE_LIST RangeList,
    IN PVOID Owner
    );

NTSTATUS
NTAPI
RtlFindRange(
    IN PRTL_RANGE_LIST RangeList,
    IN ULONGLONG Minimum,
    IN ULONGLONG Maximum,
    IN ULONG Length,
    IN ULONG Alignment,
    IN ULONG Flags,
    IN UCHAR AttributeAvailableMask,
    IN PVOID Context OPTIONAL,
    IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
    OUT PULONGLONG Start
    );

NTSTATUS
NTAPI
RtlIsRangeAvailable(
    IN PRTL_RANGE_LIST RangeList,
    IN ULONGLONG Start,
    IN ULONGLONG End,
    IN ULONG Flags,
    IN UCHAR AttributeAvailableMask,
    IN PVOID Context OPTIONAL,
    IN PRTL_CONFLICT_RANGE_CALLBACK Callback OPTIONAL,
    OUT PBOOLEAN Available
    );

NTSTATUS
NTAPI
RtlGetFirstRange(
    IN PRTL_RANGE_LIST RangeList,
    OUT PRTL_RANGE_LIST_ITERATOR Iterator,
    OUT PRTL_RANGE *Range
    );

NTSTATUS
NTAPI
RtlGetLastRange(
    IN PRTL_RANGE_LIST RangeList,
    OUT PRTL_RANGE_LIST_ITERATOR Iterator,
    OUT PRTL_RANGE *Range
    );

NTSTATUS
NTAPI
RtlGetNextRange(
    IN OUT PRTL_RANGE_LIST_ITERATOR Iterator,
    OUT PRTL_RANGE *Range,
    IN BOOLEAN MoveForwards
    );

NTSTATUS
NTAPI
RtlMergeRangeLists(
    OUT PRTL_RANGE_LIST MergedRangeList,
    IN PRTL_RANGE_LIST RangeList1,
    IN PRTL_RANGE_LIST RangeList2,
    IN ULONG Flags
    );

NTSTATUS
NTAPI
RtlInvertRangeList(
    OUT PRTL_RANGE_LIST InvertedRangeList,
    IN PRTL_RANGE_LIST RangeList
    );

NTSTATUS
NTAPI
RtlVolumeDeviceToDosName(
    IN  PVOID           VolumeDeviceObject,
    OUT PUNICODE_STRING DosName
    );

NTSTATUS
NTAPI
RtlCreateSystemVolumeInformationFolder(
    IN  PUNICODE_STRING VolumeRootPath
    );

#if defined(_WINNT_) && (_MSC_VER < 1300)
typedef POSVERSIONINFOW PRTL_OSVERSIONINFOW;
typedef POSVERSIONINFOEXW PRTL_OSVERSIONINFOEXW;

typedef LONG (NTAPI *PVECTORED_EXCEPTION_HANDLER)( struct _EXCEPTION_POINTERS *ExceptionInfo );
typedef VOID (NTAPI * APC_CALLBACK_FUNCTION) (DWORD , PVOID, PVOID);

typedef const GUID *LPCGUID;

#endif

NTSTATUS
NTAPI
RtlGetVersion(
    OUT PRTL_OSVERSIONINFOW lpVersionInformation
    );

NTSTATUS
RtlVerifyVersionInfo(
    IN PRTL_OSVERSIONINFOEXW VersionInfo,
    IN ULONG TypeMask,
    IN ULONGLONG  ConditionMask
    );

BOOLEAN
RtlFlushSecureMemoryCache(
    PVOID   lpAddr,
    SIZE_T  size
    );

LONG
NTAPI
RtlGetLastWin32Error(
    VOID
    );

VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    NTSTATUS Status
    );

VOID
NTAPI
RtlSetLastWin32Error(
    LONG Win32Error
    );

VOID
NTAPI
RtlRestoreLastWin32Error(
    LONG Win32Error
    );

NTSTATUS
NTAPI
RtlGetSetBootStatusData(
    IN HANDLE Handle,
    IN BOOLEAN Get,
    IN RTL_BSD_ITEM_TYPE DataItem,
    IN PVOID DataBuffer,
    IN ULONG DataBufferLength,
    OUT PULONG ByteRead OPTIONAL
    );

NTSTATUS
NTAPI
RtlLockBootStatusData(
    OUT PHANDLE BootStatusDataHandle
    );

VOID
NTAPI
RtlUnlockBootStatusData(
    IN HANDLE BootStatusDataHandle
    );

NTSTATUS
NTAPI
RtlCreateBootStatusDataFile(
    VOID
    );

//

//
// begin_ntapi
NTSTATUS
NTAPI
NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval
    );


NTSTATUS
NTAPI
NtQuerySystemEnvironmentValue (
    IN PUNICODE_STRING VariableName,
    OUT PWSTR VariableValue,
    IN USHORT ValueLength,
    OUT OPTIONAL PUSHORT ReturnLength
    );


NTSTATUS
NTAPI
NtSetSystemEnvironmentValue (
    IN PUNICODE_STRING VariableName,
    IN PUNICODE_STRING VariableValue
    );


NTSTATUS
NTAPI
NtQuerySystemEnvironmentValueEx (
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    OUT OPTIONAL PVOID Value,
    IN OUT PULONG ValueLength,
    OUT OPTIONAL PULONG Attributes
    );


NTSTATUS
NTAPI
NtSetSystemEnvironmentValueEx (
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    IN OPTIONAL PVOID Value,
    IN ULONG ValueLength,
    IN ULONG Attributes
    );


NTSTATUS
NTAPI
NtEnumerateSystemEnvironmentValuesEx (
    IN ULONG InformationClass,
    OUT PVOID Buffer,
    IN OUT PULONG BufferLength
    );


NTSTATUS
NTAPI
NtAddBootEntry (
    IN PBOOT_ENTRY BootEntry,
    OUT OPTIONAL PULONG Id
    );


NTSTATUS
NTAPI
NtDeleteBootEntry (
    IN ULONG Id
    );


NTSTATUS
NTAPI
NtModifyBootEntry (
    IN PBOOT_ENTRY BootEntry
    );


NTSTATUS
NTAPI
NtEnumerateBootEntries (
    OUT OPTIONAL PVOID Buffer,
    IN OUT PULONG BufferLength
    );


NTSTATUS
NTAPI
NtQueryBootEntryOrder (
    OUT OPTIONAL PULONG Ids,
    IN OUT PULONG Count
	);


NTSTATUS
NTAPI
NtSetBootEntryOrder (
    IN PULONG Ids,
    IN ULONG Count
    );


NTSTATUS
NTAPI
NtQueryBootOptions (
    OUT OPTIONAL PBOOT_OPTIONS BootOptions,
    IN OUT PULONG BootOptionsLength
    );


NTSTATUS
NTAPI
NtSetBootOptions (
    IN PBOOT_OPTIONS BootOptions,
    IN ULONG FieldsToChange
    );


NTSTATUS
NTAPI
NtTranslateFilePath (
    IN PFILE_PATH InputFilePath,
    IN ULONG OutputType,
    OUT OPTIONAL PFILE_PATH OutputFilePath,
    IN OUT OPTIONAL PULONG OutputFilePathLength
    );


NTSTATUS
NTAPI
NtAddDriverEntry (
    IN PEFI_DRIVER_ENTRY DriverEntry,
    OUT OPTIONAL PULONG Id
    );


NTSTATUS
NTAPI
NtDeleteDriverEntry (
    IN ULONG Id
    );


NTSTATUS
NTAPI
NtModifyDriverEntry (
    IN PEFI_DRIVER_ENTRY DriverEntry
    );


NTSTATUS
NTAPI
NtEnumerateDriverEntries (
    OUT PVOID Buffer,
    IN OUT PULONG BufferLength
    );


NTSTATUS
NTAPI
NtQueryDriverEntryOrder (
    OUT PULONG Ids,
    IN OUT PULONG Count
    );


NTSTATUS
NTAPI
NtSetDriverEntryOrder (
    IN PULONG Ids,
    IN ULONG Count
    );


NTSTATUS
NTAPI
NtClearEvent (
    IN HANDLE EventHandle
    );


NTSTATUS
NTAPI
NtCreateEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState
    );


NTSTATUS
NTAPI
NtOpenEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtPulseEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );


NTSTATUS
NTAPI
NtQueryEvent (
    IN HANDLE EventHandle,
    IN EVENT_INFORMATION_CLASS EventInformationClass,
    OUT PVOID EventInformation,
    IN ULONG EventInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtResetEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );


NTSTATUS
NTAPI
NtSetEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );


NTSTATUS
NTAPI
NtSetEventBoostPriority (
    IN HANDLE EventHandle
    );


NTSTATUS
NTAPI
NtCreateEventPair (
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtOpenEventPair (
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtWaitLowEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtWaitHighEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtSetLowWaitHighEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtSetHighWaitLowEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtSetLowEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtSetHighEventPair (
    IN HANDLE EventPairHandle
    );


NTSTATUS
NTAPI
NtCreateMutant (
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN InitialOwner
    );


NTSTATUS
NTAPI
NtOpenMutant (
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQueryMutant (
    IN HANDLE MutantHandle,
    IN MUTANT_INFORMATION_CLASS MutantInformationClass,
    OUT PVOID MutantInformation,
    IN ULONG MutantInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtReleaseMutant (
    IN HANDLE MutantHandle,
    OUT OPTIONAL PLONG PreviousCount
    );


NTSTATUS
NTAPI
NtCreateSemaphore (
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN LONG InitialCount,
    IN LONG MaximumCount
    );


NTSTATUS
NTAPI
NtOpenSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQuerySemaphore (
    IN HANDLE SemaphoreHandle,
    IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    OUT PVOID SemaphoreInformation,
    IN ULONG SemaphoreInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtReleaseSemaphore(
    IN HANDLE SemaphoreHandle,
    IN LONG ReleaseCount,
    OUT OPTIONAL PLONG PreviousCount
    );


NTSTATUS
NTAPI
NtCreateTimer (
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN TIMER_TYPE TimerType
    );


NTSTATUS
NTAPI
NtOpenTimer (
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtCancelTimer (
    IN HANDLE TimerHandle,
    OUT OPTIONAL PBOOLEAN CurrentState
    );


NTSTATUS
NTAPI
NtQueryTimer (
    IN HANDLE TimerHandle,
    IN TIMER_INFORMATION_CLASS TimerInformationClass,
    OUT PVOID TimerInformation,
    IN ULONG TimerInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetTimer (
    IN HANDLE TimerHandle,
    IN PLARGE_INTEGER DueTime,
    IN OPTIONAL PTIMER_APC_ROUTINE TimerApcRoutine,
    IN OPTIONAL PVOID TimerContext,
    IN BOOLEAN ResumeTimer,
    IN OPTIONAL LONG Period,
    OUT OPTIONAL PBOOLEAN PreviousState
    );


NTSTATUS
NTAPI
NtQuerySystemTime (
    OUT PLARGE_INTEGER SystemTime
    );


NTSTATUS
NTAPI
NtSetSystemTime (
    IN OPTIONAL PLARGE_INTEGER SystemTime,
    OUT OPTIONAL PLARGE_INTEGER PreviousTime
    );


NTSTATUS
NTAPI
NtQueryTimerResolution (
    OUT PULONG MaximumTime,
    OUT PULONG MinimumTime,
    OUT PULONG CurrentTime
    );


NTSTATUS
NTAPI
NtSetTimerResolution (
    IN ULONG DesiredTime,
    IN BOOLEAN SetResolution,
    OUT PULONG ActualTime
    );


NTSTATUS
NTAPI
NtAllocateLocallyUniqueId (
    OUT PLUID Luid
    );


NTSTATUS
NTAPI
NtSetUuidSeed (
    IN PCHAR Seed
    );


NTSTATUS
NTAPI
NtAllocateUuids (
    OUT PULARGE_INTEGER Time,
    OUT PULONG Range,
    OUT PULONG Sequence,
    OUT PCHAR Seed
    );


NTSTATUS
NTAPI
NtCreateProfile (
    OUT PHANDLE ProfileHandle,
    IN HANDLE Process OPTIONAL,
    IN PVOID ProfileBase,
    IN SIZE_T ProfileSize,
    IN ULONG BucketSize,
    IN PULONG Buffer,
    IN ULONG BufferSize,
    IN KPROFILE_SOURCE ProfileSource,
    IN KAFFINITY Affinity
    );


NTSTATUS
NTAPI
NtStartProfile (
    IN HANDLE ProfileHandle
    );


NTSTATUS
NTAPI
NtStopProfile (
    IN HANDLE ProfileHandle
    );


NTSTATUS
NTAPI
NtSetIntervalProfile (
    IN ULONG Interval,
    IN KPROFILE_SOURCE Source
    );


NTSTATUS
NTAPI
NtQueryIntervalProfile (
    IN KPROFILE_SOURCE ProfileSource,
    OUT PULONG Interval
    );


NTSTATUS
NTAPI
NtQueryPerformanceCounter (
    OUT PLARGE_INTEGER PerformanceCounter,
    OUT OPTIONAL PLARGE_INTEGER PerformanceFrequency
    );


NTSTATUS
NTAPI
NtCreateKeyedEvent (
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Flags
    );


NTSTATUS
NTAPI
NtOpenKeyedEvent (
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtReleaseKeyedEvent (
    IN HANDLE KeyedEventHandle,
    IN PVOID KeyValue,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtWaitForKeyedEvent (
    IN HANDLE KeyedEventHandle,
    IN PVOID KeyValue,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtQuerySystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetSystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength
    );


NTSTATUS
NTAPI
NtSystemDebugControl (
    IN SYSDBG_COMMAND Command,
    IN OPTIONAL PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtRaiseHardError (
    IN NTSTATUS ErrorStatus,
    IN ULONG NumberOfParameters,
    IN ULONG UnicodeStringParameterMask,
    IN OPTIONAL PULONG_PTR Parameters,
    IN ULONG ValidResponseOptions,
    OUT PULONG Response
    );


NTSTATUS
NTAPI
NtQueryDefaultLocale (
    IN BOOLEAN UserProfile,
    OUT PLCID DefaultLocaleId
    );


NTSTATUS
NTAPI
NtSetDefaultLocale (
    IN BOOLEAN UserProfile,
    IN LCID DefaultLocaleId
    );


NTSTATUS
NTAPI
NtQueryInstallUILanguage (
    OUT LANGID *InstallUILanguageId
    );


NTSTATUS
NTAPI
NtQueryDefaultUILanguage (
    OUT LANGID *DefaultUILanguageId
    );


NTSTATUS
NTAPI
NtSetDefaultUILanguage (
    IN LANGID DefaultUILanguageId
    );


NTSTATUS
NTAPI
NtSetDefaultHardErrorPort(
    IN HANDLE DefaultHardErrorPort
    );


NTSTATUS
NTAPI
NtShutdownSystem (
    IN SHUTDOWN_ACTION Action
    );


NTSTATUS
NTAPI
NtDisplayString (
    IN PUNICODE_STRING String
    );


NTSTATUS
NTAPI
NtAddAtom (
    IN OPTIONAL PWSTR AtomName,
    IN ULONG Length,
    OUT OPTIONAL PRTL_ATOM Atom
    );


NTSTATUS
NTAPI
NtFindAtom (
    IN OPTIONAL PWSTR AtomName,
    IN ULONG Length,
    OUT OPTIONAL PRTL_ATOM Atom
    );


NTSTATUS
NTAPI
NtDeleteAtom (
    IN RTL_ATOM Atom
    );


NTSTATUS
NTAPI
NtQueryInformationAtom(
    IN RTL_ATOM Atom,
    IN ATOM_INFORMATION_CLASS AtomInformationClass,
    OUT OPTIONAL PVOID AtomInformation,
    IN ULONG AtomInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtCancelIoFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );


NTSTATUS
NTAPI
NtCreateNamedPipeFile (
     OUT PHANDLE FileHandle,
     IN ULONG DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     OUT PIO_STATUS_BLOCK IoStatusBlock,
     IN ULONG ShareAccess,
     IN ULONG CreateDisposition,
     IN ULONG CreateOptions,
     IN ULONG NamedPipeType,
     IN ULONG ReadMode,
     IN ULONG CompletionMode,
     IN ULONG MaximumInstances,
     IN ULONG InboundQuota,
     IN ULONG OutboundQuota,
     IN OPTIONAL PLARGE_INTEGER DefaultTimeout
     );


NTSTATUS
NTAPI
NtCreateMailslotFile (
     OUT PHANDLE FileHandle,
     IN ULONG DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     OUT PIO_STATUS_BLOCK IoStatusBlock,
     IN ULONG CreateOptions,
     IN ULONG MailslotQuota,
     IN ULONG MaximumMessageSize,
     IN PLARGE_INTEGER ReadTimeout
     );


NTSTATUS
NTAPI
NtDeleteFile (
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtFlushBuffersFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );


NTSTATUS
NTAPI
NtNotifyChangeDirectoryFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree
    );


NTSTATUS
NTAPI
NtQueryAttributesFile (
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileInformation
    );


NTSTATUS
NTAPI
NtQueryFullAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );


NTSTATUS
NTAPI
NtQueryEaFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN PVOID EaList,
    IN ULONG EaListLength,
    IN OPTIONAL PULONG EaIndex OPTIONAL,
    IN BOOLEAN RestartScan
    );


NTSTATUS
NTAPI
NtCreateFile (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN OPTIONAL PVOID EaBuffer,
    IN ULONG EaLength
    );


NTSTATUS
NTAPI
NtDeviceIoControlFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN OPTIONAL PVOID  InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID  OutputBuffer,
    IN ULONG OutputBufferLength
    );


NTSTATUS
NTAPI
NtFsControlFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN OPTIONAL PVOID  InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID  OutputBuffer,
    IN ULONG OutputBufferLength
    );


NTSTATUS
NTAPI
NtLockFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock
    );


NTSTATUS
NTAPI
NtOpenFile (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );


NTSTATUS
NTAPI
NtQueryDirectoryFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PUNICODE_STRING FileName,
    IN BOOLEAN RestartScan
    );


NTSTATUS
NTAPI
NtQueryInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );


NTSTATUS
NTAPI
NtQueryQuotaInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PVOID  SidList,
    IN ULONG SidListLength,
    IN OPTIONAL PSID StartSid,
    IN BOOLEAN RestartScan
    );


NTSTATUS
NTAPI
NtQueryVolumeInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );


NTSTATUS
NTAPI
NtReadFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );


NTSTATUS
NTAPI
NtSetInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );


NTSTATUS
NTAPI
NtSetQuotaInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    );


NTSTATUS
NTAPI
NtSetVolumeInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );


NTSTATUS
NTAPI
NtWriteFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );


NTSTATUS
NTAPI
NtUnlockFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key
    );


NTSTATUS
NTAPI
NtReadFileScatter (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );


NTSTATUS
NTAPI
NtSetEaFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    );


NTSTATUS
NTAPI
NtWriteFileGather (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );


NTSTATUS
NTAPI
NtLoadDriver (
    IN PUNICODE_STRING DriverServiceName
    );


NTSTATUS
NTAPI
NtUnloadDriver (
    IN PUNICODE_STRING DriverServiceName
    );


NTSTATUS
NTAPI
NtCreateIoCompletion (
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Count OPTIONAL
    );


NTSTATUS
NTAPI
NtOpenIoCompletion (
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQueryIoCompletion (
    IN HANDLE IoCompletionHandle,
    IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    OUT PVOID IoCompletionInformation,
    IN ULONG IoCompletionInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetIoCompletion (
    IN HANDLE IoCompletionHandle,
    IN PVOID KeyContext,
    IN OPTIONAL PVOID ApcContext,
    IN NTSTATUS IoStatus,
    IN ULONG_PTR IoStatusInformation
    );


NTSTATUS
NTAPI
NtRemoveIoCompletion (
    IN HANDLE IoCompletionHandle,
    OUT PVOID *KeyContext,
    OUT PVOID *ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtCallbackReturn (
    IN PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputLength,
    IN NTSTATUS Status
    );


NTSTATUS
NTAPI
NtQueryDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level
    );


NTSTATUS
NTAPI
NtSetDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level,
    IN BOOLEAN State
    );


NTSTATUS
NTAPI
NtYieldExecution (
    VOID
    );


NTSTATUS
NTAPI
NtCreatePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN OPTIONAL ULONG MaxPoolUsage
    );


NTSTATUS
NTAPI
NtCreateWaitablePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN OPTIONAL ULONG MaxPoolUsage
    );


NTSTATUS
NTAPI
NtConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT OPTIONAL PPORT_VIEW ClientView,
    IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
    OUT OPTIONAL PULONG MaxMessageLength,
    IN OUT OPTIONAL PVOID ConnectionInformation,
    IN OUT OPTIONAL PULONG ConnectionInformationLength
    );


NTSTATUS
NTAPI
NtSecureConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT OPTIONAL PPORT_VIEW ClientView,
    IN OPTIONAL PSID RequiredServerSid,
    IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
    OUT OPTIONAL PULONG MaxMessageLength,
    IN OUT OPTIONAL PVOID ConnectionInformation,
    IN OUT OPTIONAL PULONG ConnectionInformationLength
    );


NTSTATUS
NTAPI
NtListenPort(
    IN HANDLE PortHandle,
    OUT PPORT_MESSAGE ConnectionRequest
    );


NTSTATUS
NTAPI
NtAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN OPTIONAL PVOID PortContext,
    IN PPORT_MESSAGE ConnectionRequest,
    IN BOOLEAN AcceptConnection,
    IN OUT OPTIONAL PPORT_VIEW ServerView,
    OUT OPTIONAL PREMOTE_PORT_VIEW ClientView
    );


NTSTATUS
NTAPI
NtCompleteConnectPort(
    IN HANDLE PortHandle
    );


NTSTATUS
NTAPI
NtRequestPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage
    );


NTSTATUS
NTAPI
NtRequestWaitReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage
    );


NTSTATUS
NTAPI
NtReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE ReplyMessage
    );


NTSTATUS
NTAPI
NtReplyWaitReplyPort(
    IN HANDLE PortHandle,
    IN OUT PPORT_MESSAGE ReplyMessage
    );


NTSTATUS
NTAPI
NtReplyWaitReceivePort(
    IN HANDLE PortHandle,
    OUT OPTIONAL PVOID *PortContext ,
    IN OPTIONAL PPORT_MESSAGE ReplyMessage,
    OUT PPORT_MESSAGE ReceiveMessage
    );


NTSTATUS
NTAPI
NtReplyWaitReceivePortEx(
    IN HANDLE PortHandle,
    OUT OPTIONAL PVOID *PortContext,
    IN OPTIONAL PPORT_MESSAGE ReplyMessage,
    OUT PPORT_MESSAGE ReceiveMessage,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtImpersonateClientOfPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message
    );


NTSTATUS
NTAPI
NtReadRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG DataEntryIndex,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesRead
    );


NTSTATUS
NTAPI
NtWriteRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG DataEntryIndex,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesWritten
    );


NTSTATUS
NTAPI
NtQueryInformationPort(
    IN HANDLE PortHandle,
    IN PORT_INFORMATION_CLASS PortInformationClass,
    OUT PVOID PortInformation,
    IN ULONG Length,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtCreateSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle
    );


NTSTATUS
NTAPI
NtOpenSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtMapViewOfSection (
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
    );


NTSTATUS
NTAPI
NtUnmapViewOfSection (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );


NTSTATUS
NTAPI
NtExtendSection (
    IN HANDLE SectionHandle,
    IN OUT PLARGE_INTEGER NewSectionSize
    );


NTSTATUS
NTAPI
NtAreMappedFilesTheSame (
    IN PVOID File1MappedAsAnImage,
    IN PVOID File2MappedAsFile
    );


NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );


NTSTATUS
NTAPI
NtFreeVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
    );


NTSTATUS
NTAPI
NtReadVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesRead
    );


NTSTATUS
NTAPI
NtWriteVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    IN CONST VOID *Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesWritten
    );


NTSTATUS
NTAPI
NtFlushVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    OUT PIO_STATUS_BLOCK IoStatus
    );


NTSTATUS
NTAPI
NtLockVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType
    );


NTSTATUS
NTAPI
NtUnlockVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType
    );


NTSTATUS
NTAPI
NtProtectVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );


NTSTATUS
NTAPI
NtQueryVirtualMemory (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT OPTIONAL PSIZE_T ReturnLength
    );


NTSTATUS
NTAPI
NtQuerySection (
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN SIZE_T SectionInformationLength,
    OUT OPTIONAL PSIZE_T ReturnLength
    );


NTSTATUS
NTAPI
NtMapUserPhysicalPages (
    IN PVOID VirtualAddress,
    IN ULONG_PTR NumberOfPages,
    IN OPTIONAL PULONG_PTR UserPfnArray
    );


NTSTATUS
NTAPI
NtMapUserPhysicalPagesScatter (
    IN PVOID *VirtualAddresses,
    IN ULONG_PTR NumberOfPages,
    IN OPTIONAL PULONG_PTR UserPfnArray
    );


NTSTATUS
NTAPI
NtAllocateUserPhysicalPages (
    IN HANDLE ProcessHandle,
    IN OUT PULONG_PTR NumberOfPages,
    OUT PULONG_PTR UserPfnArray
    );


NTSTATUS
NTAPI
NtFreeUserPhysicalPages (
    IN HANDLE ProcessHandle,
    IN OUT PULONG_PTR NumberOfPages,
    IN PULONG_PTR UserPfnArray
    );


NTSTATUS
NTAPI
NtGetWriteWatch (
    IN HANDLE ProcessHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize,
    OUT PVOID *UserAddressArray,
    IN OUT PULONG_PTR EntriesInUserAddressArray,
    OUT PULONG Granularity
    );


NTSTATUS
NTAPI
NtResetWriteWatch (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize
    );


NTSTATUS
NTAPI
NtCreatePagingFile (
    IN PUNICODE_STRING PageFileName,
    IN PLARGE_INTEGER MinimumSize,
    IN PLARGE_INTEGER MaximumSize,
    IN ULONG Priority
    );


NTSTATUS
NTAPI
NtFlushInstructionCache (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    IN SIZE_T Length
    );


NTSTATUS
NTAPI
NtFlushWriteBuffer (
    VOID
    );


NTSTATUS
NTAPI
NtQueryObject (
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetInformationObject (
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    IN PVOID ObjectInformation,
    IN ULONG ObjectInformationLength
    );


NTSTATUS
NTAPI
NtDuplicateObject (
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN OPTIONAL HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options
    );


NTSTATUS
NTAPI
NtMakeTemporaryObject (
    IN HANDLE Handle
    );


NTSTATUS
NTAPI
NtMakePermanentObject (
    IN HANDLE Handle
    );


NTSTATUS
NTAPI
NtSignalAndWaitForSingleObject (
    IN HANDLE SignalHandle,
    IN HANDLE WaitHandle,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtWaitForSingleObject (
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtWaitForMultipleObjects (
    IN ULONG Count,
    IN HANDLE Handles[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtWaitForMultipleObjects32 (
    IN ULONG Count,
    IN LONG Handles[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );


NTSTATUS
NTAPI
NtSetSecurityObject (
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );


NTSTATUS
NTAPI
NtQuerySecurityObject (
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ULONG Length,
    OUT PULONG LengthNeeded
    );


NTSTATUS
NTAPI
NtClose (
    IN HANDLE Handle
    );


NTSTATUS
NTAPI
NtCreateDirectoryObject (
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtOpenDirectoryObject (
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQueryDirectoryObject (
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT  PULONG Context,
    OUT PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtCreateSymbolicLinkObject (
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget
    );


NTSTATUS
NTAPI
NtOpenSymbolicLinkObject (
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQuerySymbolicLinkObject (
    IN HANDLE LinkHandle,
    IN OUT  PUNICODE_STRING LinkTarget,
    OUT PULONG ReturnedLength
    );


NTSTATUS
NTAPI
NtGetPlugPlayEvent (
    IN HANDLE EventHandle,
    IN OPTIONAL PVOID Context,
    OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
    IN  ULONG EventBufferSize
    );


NTSTATUS
NTAPI
NtPlugPlayControl(
    IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
    IN OUT PVOID PnPControlData,
    IN ULONG PnPControlDataLength
    );


NTSTATUS
NTAPI
NtPowerInformation(
    IN POWER_INFORMATION_LEVEL InformationLevel,
    IN OPTIONAL PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID OutputBuffer,
    IN ULONG OutputBufferLength
    );


NTSTATUS
NTAPI
NtSetThreadExecutionState(
    IN EXECUTION_STATE esFlags,               // ES_xxx flags
    OUT EXECUTION_STATE *PreviousFlags
    );


NTSTATUS
NTAPI
NtRequestWakeupLatency(
    IN LATENCY_TIME latency
    );


// NTSTATUS
// NTAPI
// NtInitiatePowerAction(
//     IN POWER_ACTION SystemAction,
//     IN SYSTEM_POWER_STATE MinSystemState,
//     IN ULONG Flags,                 // POWER_ACTION_xxx flags
//     IN BOOLEAN Asynchronous
//     );


// NTSTATUS
// NTAPI
// NtSetSystemPowerState(
//     IN POWER_ACTION SystemAction,
//     IN SYSTEM_POWER_STATE MinSystemState,
//     IN ULONG Flags                  // POWER_ACTION_xxx flags
//     );


// NTSTATUS
// NTAPI
// NtGetDevicePowerState(
//     IN HANDLE Device,
//     OUT DEVICE_POWER_STATE *State
//     );


NTSTATUS
NTAPI
NtCancelDeviceWakeupRequest(
    IN HANDLE Device
    );


NTSTATUS
NTAPI
NtRequestDeviceWakeup(
    IN HANDLE Device
    );


NTSTATUS
NTAPI
NtCreateProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN OPTIONAL HANDLE SectionHandle,
    IN OPTIONAL HANDLE DebugPort,
    IN OPTIONAL HANDLE ExceptionPort
    );


NTSTATUS
NTAPI
NtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN OPTIONAL HANDLE SectionHandle,
    IN OPTIONAL HANDLE DebugPort,
    IN OPTIONAL HANDLE ExceptionPort,
    IN ULONG JobMemberLevel
    );


NTSTATUS
NTAPI
NtOpenProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PCLIENT_ID ClientId
    );

NTSTATUS
NTAPI
NtTerminateProcess(
	IN OPTIONAL HANDLE   ProcessHandle,
	IN          NTSTATUS ExitStatus
	);

NTSTATUS
NTAPI
NtTerminateProcess (
    IN OPTIONAL HANDLE ProcessHandle,
    IN NTSTATUS ExitStatus
    );


NTSTATUS
NTAPI
NtQueryInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtGetNextProcess (
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewProcessHandle
    );


NTSTATUS
NTAPI
NtGetNextThread (
    IN HANDLE ProcessHandle,
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewThreadHandle
    );


NTSTATUS
NTAPI
NtQueryPortInformationProcess (
    VOID
    );


NTSTATUS
NTAPI
NtSetInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
    );


NTSTATUS
NTAPI
NtCreateThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PINITIAL_TEB InitialTeb,
    IN BOOLEAN CreateSuspended
    );

NTSTATUS
NTAPI NtCreateThreadEx (
    PHANDLE     hThread,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       lpStartAddress,
    PVOID       lpParameter,
    ULONG       Flags,
    SIZE_T      StackZeroBits,
    SIZE_T      SizeOfStackCommit,
    SIZE_T      SizeOfStackReserve,
    PVOID       lpBytesBuffer
);

NTSTATUS
NTAPI
NtOpenThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PCLIENT_ID ClientId
    );


NTSTATUS
NTAPI
NtTerminateThread (
    IN OPTIONAL HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus
    );


NTSTATUS
NTAPI
NtSuspendThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );


NTSTATUS
NTAPI
NtResumeThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );


NTSTATUS
NTAPI
NtSuspendProcess (
	HANDLE ProcessHandle
	);


NTSTATUS
NTAPI
NtResumeProcess (
    IN HANDLE ProcessHandle
    );


NTSTATUS
NTAPI
NtGetContextThread (
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext
    );


NTSTATUS
NTAPI
NtSetContextThread (
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext
    );


NTSTATUS
NTAPI
NtQueryInformationThread (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetInformationThread (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
    );

NTSTATUS NtSetInformationVirtualMemory(
    IN HANDLE                           ProcessHandle,
    IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    IN ULONG_PTR                        NumberOfEntries,
    IN PMEMORY_RANGE_ENTRY              VirtualAddresses,
    IN PVOID                            VmInformation,
    IN ULONG                            VmInformationLength
);

NTSTATUS
NTAPI
NtAlertThread (
    IN HANDLE ThreadHandle
    );


NTSTATUS
NTAPI
NtAlertResumeThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );


NTSTATUS
NTAPI
NtImpersonateThread (
    IN HANDLE ServerThreadHandle,
    IN HANDLE ClientThreadHandle,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos
    );


NTSTATUS
NTAPI
NtTestAlert (
    VOID
    );


NTSTATUS
NTAPI
NtRegisterThreadTerminatePort (
    IN HANDLE PortHandle
    );


NTSTATUS
NTAPI
NtSetLdtEntries (
    IN ULONG Selector0,
    IN ULONG Entry0Low,
    IN ULONG Entry0Hi,
    IN ULONG Selector1,
    IN ULONG Entry1Low,
    IN ULONG Entry1Hi
    );


NTSTATUS
NTAPI
NtQueueApcThread (
    IN HANDLE ThreadHandle,
    IN PPS_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcArgument1,
    IN OPTIONAL PVOID ApcArgument2,
    IN OPTIONAL PVOID ApcArgument3
    );


NTSTATUS
NTAPI
NtCreateJobObject (
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtOpenJobObject (
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtAssignProcessToJobObject (
    IN HANDLE JobHandle,
    IN HANDLE ProcessHandle
    );


NTSTATUS
NTAPI
NtTerminateJobObject (
    IN HANDLE JobHandle,
    IN NTSTATUS ExitStatus
    );


NTSTATUS
NTAPI
NtIsProcessInJob (
    IN HANDLE ProcessHandle,
    IN OPTIONAL HANDLE JobHandle
    );


NTSTATUS
NTAPI
NtCreateJobSet (
    IN ULONG NumJob,
    IN PJOB_SET_ARRAY UserJobSet,
    IN ULONG Flags
    );


NTSTATUS
NTAPI
NtQueryInformationJobObject (
    IN OPTIONAL HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    OUT PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetInformationJobObject (
    IN HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    IN PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength
    );


NTSTATUS
NTAPI
NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    IN OPTIONAL PUNICODE_STRING Class,
    IN ULONG CreateOptions,
    OUT OPTIONAL PULONG Disposition
    );


NTSTATUS
NTAPI
NtDeleteKey(
    IN HANDLE KeyHandle
    );


NTSTATUS
NTAPI
NtDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName
    );


NTSTATUS
NTAPI
NtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT OPTIONAL PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );


NTSTATUS
NTAPI
NtEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT OPTIONAL PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );


NTSTATUS
NTAPI
NtFlushKey(
    IN HANDLE KeyHandle
    );


NTSTATUS
NTAPI
NtInitializeRegistry(
    IN USHORT BootCondition
    );


NTSTATUS
NTAPI
NtNotifyChangeKey(
    IN HANDLE KeyHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT OPTIONAL PVOID Buffer,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous
    );


NTSTATUS
NTAPI
NtNotifyChangeMultipleKeys(
    IN HANDLE MasterKeyHandle,
    IN OPTIONAL ULONG Count,
    IN OPTIONAL OBJECT_ATTRIBUTES SlaveObjects[],
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT OPTIONAL PVOID Buffer,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous
    );


NTSTATUS
NTAPI
NtLoadKey(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile
    );


NTSTATUS
NTAPI
NtLoadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags
    );


NTSTATUS
NTAPI
NtLoadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags,
    IN OPTIONAL HANDLE TrustClassKey
    );


NTSTATUS
NTAPI
NtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );


NTSTATUS
NTAPI
NtQueryKey(
    IN HANDLE KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT OPTIONAL PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );


NTSTATUS
NTAPI
NtQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT OPTIONAL PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );


NTSTATUS
NTAPI
NtQueryMultipleValueKey(
    IN HANDLE KeyHandle,
    IN OUT PKEY_VALUE_ENTRY ValueEntries,
    IN ULONG EntryCount,
    OUT PVOID ValueBuffer,
    IN OUT PULONG BufferLength,
    OUT OPTIONAL PULONG RequiredBufferLength
    );


NTSTATUS
NTAPI
NtReplaceKey(
    IN POBJECT_ATTRIBUTES NewFile,
    IN HANDLE TargetHandle,
    IN POBJECT_ATTRIBUTES OldFile
    );


NTSTATUS
NTAPI
NtRenameKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING  NewName
    );


NTSTATUS
NTAPI
NtCompactKeys(
    IN ULONG Count,
    IN HANDLE KeyArray[]
            );


NTSTATUS
NTAPI
NtCompressKey(
    IN HANDLE Key
            );


NTSTATUS
NTAPI
NtRestoreKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG Flags
    );


NTSTATUS
NTAPI
NtSaveKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle
    );


NTSTATUS
NTAPI
NtSaveKeyEx(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG  Format
    );


NTSTATUS
NTAPI
NtSaveMergedKeys(
    IN HANDLE HighPrecedenceKeyHandle,
    IN HANDLE LowPrecedenceKeyHandle,
    IN HANDLE FileHandle
    );


NTSTATUS
NTAPI
NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN OPTIONAL ULONG TitleIndex,
    IN ULONG Type,
    IN OPTIONAL PVOID Data,
    IN ULONG DataSize
    );


NTSTATUS
NTAPI
NtUnloadKey(
    IN POBJECT_ATTRIBUTES TargetKey
    );


NTSTATUS
NTAPI
NtUnloadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG Flags
    );


NTSTATUS
NTAPI
NtUnloadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN OPTIONAL HANDLE Event
    );


NTSTATUS
NTAPI
NtSetInformationKey(
    IN HANDLE KeyHandle,
    IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    IN PVOID KeySetInformation,
    IN ULONG KeySetInformationLength
    );


NTSTATUS
NTAPI
NtQueryOpenSubKeys(
    IN POBJECT_ATTRIBUTES TargetKey,
    OUT PULONG  HandleCount
    );


NTSTATUS
NTAPI
NtQueryOpenSubKeysEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG BufferLength,
    OUT PVOID Buffer,
    OUT PULONG RequiredSize
    );


NTSTATUS
NTAPI
NtLockRegistryKey(
    IN HANDLE KeyHandle
    );


NTSTATUS
NTAPI
NtLockProductActivationKeys(
    IN OUT OPTIONAL ULONG *pPrivateVer,
    OUT OPTIONAL ULONG *pSafeMode
    );


NTSTATUS
NTAPI
NtAccessCheck (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );


NTSTATUS
NTAPI
NtAccessCheckByType (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );


NTSTATUS
NTAPI
NtAccessCheckByTypeResultList (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );


NTSTATUS
NTAPI
NtCreateToken(
    OUT PHANDLE TokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN TOKEN_TYPE TokenType,
    IN PLUID AuthenticationId,
    IN PLARGE_INTEGER ExpirationTime,
    IN PTOKEN_USER User,
    IN PTOKEN_GROUPS Groups,
    IN PTOKEN_PRIVILEGES Privileges,
    IN OPTIONAL PTOKEN_OWNER Owner,
    IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
    IN OPTIONAL PTOKEN_DEFAULT_DACL DefaultDacl,
    IN PTOKEN_SOURCE TokenSource
    );


NTSTATUS
NTAPI
NtCompareTokens(
    IN HANDLE FirstTokenHandle,
    IN HANDLE SecondTokenHandle,
    OUT PBOOLEAN Equal
    );


NTSTATUS
NTAPI
NtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle
    );


NTSTATUS
NTAPI
NtOpenThreadTokenEx(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle
    );


NTSTATUS
NTAPI
NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
    );


NTSTATUS
NTAPI
NtOpenProcessTokenEx(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle
    );


NTSTATUS
NTAPI
NtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle
    );


NTSTATUS
NTAPI
NtFilterToken (
    IN HANDLE ExistingTokenHandle,
    IN ULONG Flags,
    IN OPTIONAL PTOKEN_GROUPS SidsToDisable,
    IN OPTIONAL PTOKEN_PRIVILEGES PrivilegesToDelete,
    IN OPTIONAL PTOKEN_GROUPS RestrictedSids,
    OUT PHANDLE NewTokenHandle
    );


NTSTATUS
NTAPI
NtImpersonateAnonymousToken(
    IN HANDLE ThreadHandle
    );


NTSTATUS
NTAPI
NtQueryInformationToken (
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtSetInformationToken (
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    IN PVOID TokenInformation,
    IN ULONG TokenInformationLength
    );


NTSTATUS
NTAPI
NtAdjustPrivilegesToken (
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN OPTIONAL PTOKEN_PRIVILEGES NewState,
    IN OPTIONAL ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtAdjustGroupsToken (
    IN HANDLE TokenHandle,
    IN BOOLEAN ResetToDefault,
    IN PTOKEN_GROUPS NewState ,
    IN OPTIONAL ULONG BufferLength ,
    OUT PTOKEN_GROUPS PreviousState ,
    OUT PULONG ReturnLength
    );


NTSTATUS
NTAPI
NtPrivilegeCheck (
    IN HANDLE ClientToken,
    IN OUT  PPRIVILEGE_SET RequiredPrivileges,
    OUT PBOOLEAN Result
    );


NTSTATUS
NTAPI
NtAccessCheckAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ACCESS_MASK DesiredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtAccessCheckByTypeAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtAccessCheckByTypeResultListAndAuditAlarmByHandle (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN HANDLE ClientToken,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtOpenObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN ACCESS_MASK GrantedAccess,
    IN OPTIONAL PPRIVILEGE_SET Privileges,
    IN BOOLEAN ObjectCreation,
    IN BOOLEAN AccessGranted,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtPrivilegeObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted
    );


NTSTATUS
NTAPI
NtCloseObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN BOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtDeleteObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN BOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
NtPrivilegedServiceAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN PUNICODE_STRING ServiceName,
    IN HANDLE ClientToken,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted
    );


NTSTATUS
NTAPI
NtContinue (
    IN PCONTEXT ContextRecord,
    IN BOOLEAN TestAlert
    );


NTSTATUS
NTAPI
NtRaiseException (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN BOOLEAN FirstChance
    );

// end_ntapi


// begin_zwapi
NTSTATUS
NTAPI
ZwDelayExecution (
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval
    );



NTSTATUS
NTAPI
ZwQuerySystemEnvironmentValue (
    IN PUNICODE_STRING VariableName,
    OUT PWSTR VariableValue,
    IN USHORT ValueLength,
    OUT OPTIONAL PUSHORT ReturnLength
    );



NTSTATUS
NTAPI
ZwSetSystemEnvironmentValue (
    IN PUNICODE_STRING VariableName,
    IN PUNICODE_STRING VariableValue
    );



NTSTATUS
NTAPI
ZwQuerySystemEnvironmentValueEx (
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    OUT OPTIONAL PVOID Value,
    IN OUT PULONG ValueLength,
    OUT OPTIONAL PULONG Attributes
    );



NTSTATUS
NTAPI
ZwSetSystemEnvironmentValueEx (
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    IN OPTIONAL PVOID Value,
    IN ULONG ValueLength,
    IN ULONG Attributes
    );



NTSTATUS
NTAPI
ZwEnumerateSystemEnvironmentValuesEx (
    IN ULONG InformationClass,
    OUT PVOID Buffer,
    IN OUT PULONG BufferLength
    );



NTSTATUS
NTAPI
ZwAddBootEntry (
    IN PBOOT_ENTRY BootEntry,
    OUT OPTIONAL PULONG Id
    );



NTSTATUS
NTAPI
ZwDeleteBootEntry (
    IN ULONG Id
    );



NTSTATUS
NTAPI
ZwModifyBootEntry (
    IN PBOOT_ENTRY BootEntry
    );



NTSTATUS
NTAPI
ZwEnumerateBootEntries (
    OUT OPTIONAL PVOID Buffer,
    IN OUT PULONG BufferLength
    );



NTSTATUS
NTAPI
ZwQueryBootEntryOrder (
    OUT OPTIONAL PULONG Ids,
    IN OUT PULONG Count
    );



NTSTATUS
NTAPI
ZwSetBootEntryOrder (
    IN PULONG Ids,
    IN ULONG Count
    );



NTSTATUS
NTAPI
ZwQueryBootOptions (
    OUT OPTIONAL PBOOT_OPTIONS BootOptions,
    IN OUT PULONG BootOptionsLength
    );



NTSTATUS
NTAPI
ZwSetBootOptions (
    IN PBOOT_OPTIONS BootOptions,
    IN ULONG FieldsToChange
    );



NTSTATUS
NTAPI
ZwTranslateFilePath (
    IN PFILE_PATH InputFilePath,
    IN ULONG OutputType,
    OUT OPTIONAL PFILE_PATH OutputFilePath,
    IN OUT OPTIONAL PULONG OutputFilePathLength
    );



NTSTATUS
NTAPI
ZwAddDriverEntry (
    IN PEFI_DRIVER_ENTRY DriverEntry,
    OUT OPTIONAL PULONG Id
    );



NTSTATUS
NTAPI
ZwDeleteDriverEntry (
    IN ULONG Id
    );



NTSTATUS
NTAPI
ZwModifyDriverEntry (
    IN PEFI_DRIVER_ENTRY DriverEntry
    );



NTSTATUS
NTAPI
ZwEnumerateDriverEntries (
    OUT PVOID Buffer,
    IN OUT PULONG BufferLength
    );



NTSTATUS
NTAPI
ZwQueryDriverEntryOrder (
    OUT PULONG Ids,
    IN OUT PULONG Count
    );



NTSTATUS
NTAPI
ZwSetDriverEntryOrder (
    IN PULONG Ids,
    IN ULONG Count
    );



NTSTATUS
NTAPI
ZwClearEvent (
    IN HANDLE EventHandle
    );



NTSTATUS
NTAPI
ZwCreateEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState
    );



NTSTATUS
NTAPI
ZwOpenEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwPulseEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );



NTSTATUS
NTAPI
ZwQueryEvent (
    IN HANDLE EventHandle,
    IN EVENT_INFORMATION_CLASS EventInformationClass,
    OUT PVOID EventInformation,
    IN ULONG EventInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwResetEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );



NTSTATUS
NTAPI
ZwSetEvent (
    IN HANDLE EventHandle,
    OUT OPTIONAL PLONG PreviousState
    );



NTSTATUS
NTAPI
ZwSetEventBoostPriority (
    IN HANDLE EventHandle
    );



NTSTATUS
NTAPI
ZwCreateEventPair (
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwOpenEventPair (
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwWaitLowEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwWaitHighEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwSetLowWaitHighEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwSetHighWaitLowEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwSetLowEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwSetHighEventPair (
    IN HANDLE EventPairHandle
    );



NTSTATUS
NTAPI
ZwCreateMutant (
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN InitialOwner
    );



NTSTATUS
NTAPI
ZwOpenMutant (
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQueryMutant (
    IN HANDLE MutantHandle,
    IN MUTANT_INFORMATION_CLASS MutantInformationClass,
    OUT PVOID MutantInformation,
    IN ULONG MutantInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwReleaseMutant (
    IN HANDLE MutantHandle,
    OUT OPTIONAL PLONG PreviousCount
    );



NTSTATUS
NTAPI
ZwCreateSemaphore (
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN LONG InitialCount,
    IN LONG MaximumCount
    );



NTSTATUS
NTAPI
ZwOpenSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQuerySemaphore (
    IN HANDLE SemaphoreHandle,
    IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    OUT PVOID SemaphoreInformation,
    IN ULONG SemaphoreInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwReleaseSemaphore(
    IN HANDLE SemaphoreHandle,
    IN LONG ReleaseCount,
    OUT OPTIONAL PLONG PreviousCount
    );



NTSTATUS
NTAPI
ZwCreateTimer (
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN TIMER_TYPE TimerType
    );



NTSTATUS
NTAPI
ZwOpenTimer (
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwCancelTimer (
    IN HANDLE TimerHandle,
    OUT OPTIONAL PBOOLEAN CurrentState
    );



NTSTATUS
NTAPI
ZwQueryTimer (
    IN HANDLE TimerHandle,
    IN TIMER_INFORMATION_CLASS TimerInformationClass,
    OUT PVOID TimerInformation,
    IN ULONG TimerInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetTimer (
    IN HANDLE TimerHandle,
    IN PLARGE_INTEGER DueTime,
    IN OPTIONAL PTIMER_APC_ROUTINE TimerApcRoutine,
    IN OPTIONAL PVOID TimerContext,
    IN BOOLEAN ResumeTimer,
    IN OPTIONAL LONG Period,
    OUT OPTIONAL PBOOLEAN PreviousState
    );



NTSTATUS
NTAPI
ZwQuerySystemTime (
    OUT PLARGE_INTEGER SystemTime
    );



NTSTATUS
NTAPI
ZwSetSystemTime (
    IN OPTIONAL PLARGE_INTEGER SystemTime,
    OUT OPTIONAL PLARGE_INTEGER PreviousTime
    );



NTSTATUS
NTAPI
ZwQueryTimerResolution (
    OUT PULONG MaximumTime,
    OUT PULONG MinimumTime,
    OUT PULONG CurrentTime
    );



NTSTATUS
NTAPI
ZwSetTimerResolution (
    IN ULONG DesiredTime,
    IN BOOLEAN SetResolution,
    OUT PULONG ActualTime
    );



NTSTATUS
NTAPI
ZwAllocateLocallyUniqueId (
    OUT PLUID Luid
    );



NTSTATUS
NTAPI
ZwSetUuidSeed (
    IN PCHAR Seed
    );



NTSTATUS
NTAPI
ZwAllocateUuids (
    OUT PULARGE_INTEGER Time,
    OUT PULONG Range,
    OUT PULONG Sequence,
    OUT PCHAR Seed
    );



NTSTATUS
NTAPI
ZwCreateProfile (
    OUT PHANDLE ProfileHandle,
    IN HANDLE Process OPTIONAL,
    IN PVOID ProfileBase,
    IN SIZE_T ProfileSize,
    IN ULONG BucketSize,
    IN PULONG Buffer,
    IN ULONG BufferSize,
    IN KPROFILE_SOURCE ProfileSource,
    IN KAFFINITY Affinity
    );



NTSTATUS
NTAPI
ZwStartProfile (
    IN HANDLE ProfileHandle
    );



NTSTATUS
NTAPI
ZwStopProfile (
    IN HANDLE ProfileHandle
    );



NTSTATUS
NTAPI
ZwSetIntervalProfile (
    IN ULONG Interval,
    IN KPROFILE_SOURCE Source
    );



NTSTATUS
NTAPI
ZwQueryIntervalProfile (
    IN KPROFILE_SOURCE ProfileSource,
    OUT PULONG Interval
    );



NTSTATUS
NTAPI
ZwQueryPerformanceCounter (
    OUT PLARGE_INTEGER PerformanceCounter,
    OUT OPTIONAL PLARGE_INTEGER PerformanceFrequency
    );



NTSTATUS
NTAPI
ZwCreateKeyedEvent (
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Flags
    );



NTSTATUS
NTAPI
ZwOpenKeyedEvent (
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwReleaseKeyedEvent (
    IN HANDLE KeyedEventHandle,
    IN PVOID KeyValue,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwWaitForKeyedEvent (
    IN HANDLE KeyedEventHandle,
    IN PVOID KeyValue,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwQuerySystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetSystemInformation (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength
    );



NTSTATUS
NTAPI
ZwSystemDebugControl (
    IN SYSDBG_COMMAND Command,
    IN OPTIONAL PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwRaiseHardError (
    IN NTSTATUS ErrorStatus,
    IN ULONG NumberOfParameters,
    IN ULONG UnicodeStringParameterMask,
    IN OPTIONAL PULONG_PTR Parameters,
    IN ULONG ValidResponseOptions,
    OUT PULONG Response
    );



NTSTATUS
NTAPI
ZwQueryDefaultLocale (
    IN BOOLEAN UserProfile,
    OUT PLCID DefaultLocaleId
    );



NTSTATUS
NTAPI
ZwSetDefaultLocale (
    IN BOOLEAN UserProfile,
    IN LCID DefaultLocaleId
    );



NTSTATUS
NTAPI
ZwQueryInstallUILanguage (
    OUT LANGID *InstallUILanguageId
    );



NTSTATUS
NTAPI
ZwQueryDefaultUILanguage (
    OUT LANGID *DefaultUILanguageId
    );



NTSTATUS
NTAPI
ZwSetDefaultUILanguage (
    IN LANGID DefaultUILanguageId
    );



NTSTATUS
NTAPI
ZwSetDefaultHardErrorPort(
    IN HANDLE DefaultHardErrorPort
    );



NTSTATUS
NTAPI
ZwShutdownSystem (
    IN SHUTDOWN_ACTION Action
    );



NTSTATUS
NTAPI
ZwDisplayString (
    IN PUNICODE_STRING String
    );



NTSTATUS
NTAPI
ZwAddAtom (
    IN OPTIONAL PWSTR AtomName,
    IN ULONG Length,
    OUT OPTIONAL PRTL_ATOM Atom
    );



NTSTATUS
NTAPI
ZwFindAtom (
    IN OPTIONAL PWSTR AtomName,
    IN ULONG Length,
    OUT OPTIONAL PRTL_ATOM Atom
    );



NTSTATUS
NTAPI
ZwDeleteAtom (
    IN RTL_ATOM Atom
    );



NTSTATUS
NTAPI
ZwQueryInformationAtom(
    IN RTL_ATOM Atom,
    IN ATOM_INFORMATION_CLASS AtomInformationClass,
    OUT OPTIONAL PVOID AtomInformation,
    IN ULONG AtomInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwCancelIoFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );



NTSTATUS
NTAPI
ZwCreateNamedPipeFile (
     OUT PHANDLE FileHandle,
     IN ULONG DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     OUT PIO_STATUS_BLOCK IoStatusBlock,
     IN ULONG ShareAccess,
     IN ULONG CreateDisposition,
     IN ULONG CreateOptions,
     IN ULONG NamedPipeType,
     IN ULONG ReadMode,
     IN ULONG CompletionMode,
     IN ULONG MaximumInstances,
     IN ULONG InboundQuota,
     IN ULONG OutboundQuota,
     IN OPTIONAL PLARGE_INTEGER DefaultTimeout
     );



NTSTATUS
NTAPI
ZwCreateMailslotFile (
     OUT PHANDLE FileHandle,
     IN ULONG DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     OUT PIO_STATUS_BLOCK IoStatusBlock,
     IN ULONG CreateOptions,
     IN ULONG MailslotQuota,
     IN ULONG MaximumMessageSize,
     IN PLARGE_INTEGER ReadTimeout
     );



NTSTATUS
NTAPI
ZwDeleteFile (
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwFlushBuffersFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );



NTSTATUS
NTAPI
ZwNotifyChangeDirectoryFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree
    );



NTSTATUS
NTAPI
ZwQueryAttributesFile (
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileInformation
    );



NTSTATUS
NTAPI
ZwQueryFullAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );



NTSTATUS
NTAPI
ZwQueryEaFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN PVOID EaList,
    IN ULONG EaListLength,
    IN OPTIONAL PULONG EaIndex OPTIONAL,
    IN BOOLEAN RestartScan
    );


NTSTATUS
NTAPI
ZwCreateFile (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER AllocationSize,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN OPTIONAL PVOID EaBuffer,
    IN ULONG EaLength
    );



NTSTATUS
NTAPI
ZwDeviceIoControlFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN OPTIONAL PVOID  InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID  OutputBuffer,
    IN ULONG OutputBufferLength
    );



NTSTATUS
NTAPI
ZwFsControlFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN OPTIONAL PVOID  InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID  OutputBuffer,
    IN ULONG OutputBufferLength
    );



NTSTATUS
NTAPI
ZwLockFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock
    );



NTSTATUS
NTAPI
ZwOpenFile (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );



NTSTATUS
NTAPI
ZwQueryDirectoryFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PUNICODE_STRING FileName,
    IN BOOLEAN RestartScan
    );



NTSTATUS
NTAPI
ZwQueryInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );



NTSTATUS
NTAPI
ZwQueryQuotaInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN OPTIONAL PVOID  SidList,
    IN ULONG SidListLength,
    IN OPTIONAL PSID StartSid,
    IN BOOLEAN RestartScan
    );



NTSTATUS
NTAPI
ZwQueryVolumeInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );



NTSTATUS
NTAPI
ZwReadFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );



NTSTATUS
NTAPI
ZwSetInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );



NTSTATUS
NTAPI
ZwSetQuotaInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    );



NTSTATUS
NTAPI
ZwSetVolumeInformationFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );



NTSTATUS
NTAPI
ZwWriteFile (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );



NTSTATUS
NTAPI
ZwUnlockFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key
    );



NTSTATUS
NTAPI
ZwReadFileScatter (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );



NTSTATUS
NTAPI
ZwSetEaFile (
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length
    );



NTSTATUS
NTAPI
ZwWriteFileGather (
    IN HANDLE FileHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN OPTIONAL PLARGE_INTEGER ByteOffset,
    IN OPTIONAL PULONG Key
    );



NTSTATUS
NTAPI
ZwLoadDriver (
    IN PUNICODE_STRING DriverServiceName
    );



NTSTATUS
NTAPI
ZwUnloadDriver (
    IN PUNICODE_STRING DriverServiceName
    );



NTSTATUS
NTAPI
ZwCreateIoCompletion (
    OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Count OPTIONAL
    );



NTSTATUS
NTAPI
ZwOpenIoCompletion (
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQueryIoCompletion (
    IN HANDLE IoCompletionHandle,
    IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    OUT PVOID IoCompletionInformation,
    IN ULONG IoCompletionInformationLength,
		OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetIoCompletion (
    IN HANDLE IoCompletionHandle,
    IN PVOID KeyContext,
    IN OPTIONAL PVOID ApcContext,
    IN NTSTATUS IoStatus,
    IN ULONG_PTR IoStatusInformation
    );



NTSTATUS
NTAPI
ZwRemoveIoCompletion (
    IN HANDLE IoCompletionHandle,
    OUT PVOID *KeyContext,
    OUT PVOID *ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwCallbackReturn (
    IN PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputLength,
    IN NTSTATUS Status
    );



NTSTATUS
NTAPI
ZwQueryDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level
    );



NTSTATUS
NTAPI
ZwSetDebugFilterState (
    IN ULONG ComponentId,
    IN ULONG Level,
    IN BOOLEAN State
    );



NTSTATUS
NTAPI
ZwYieldExecution (
    VOID
    );



NTSTATUS
NTAPI
ZwCreatePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN OPTIONAL ULONG MaxPoolUsage
    );



NTSTATUS
NTAPI
ZwCreateWaitablePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN OPTIONAL ULONG MaxPoolUsage
    );



NTSTATUS
NTAPI
ZwConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT OPTIONAL PPORT_VIEW ClientView,
    IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
    OUT OPTIONAL PULONG MaxMessageLength,
    IN OUT OPTIONAL PVOID ConnectionInformation,
    IN OUT OPTIONAL PULONG ConnectionInformationLength
    );



NTSTATUS
NTAPI
ZwSecureConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT OPTIONAL PPORT_VIEW ClientView,
    IN OPTIONAL PSID RequiredServerSid,
    IN OUT OPTIONAL PREMOTE_PORT_VIEW ServerView,
    OUT OPTIONAL PULONG MaxMessageLength,
    IN OUT OPTIONAL PVOID ConnectionInformation,
    IN OUT OPTIONAL PULONG ConnectionInformationLength
    );



NTSTATUS
NTAPI
ZwListenPort(
    IN HANDLE PortHandle,
    OUT PPORT_MESSAGE ConnectionRequest
    );



NTSTATUS
NTAPI
ZwAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN OPTIONAL PVOID PortContext,
    IN PPORT_MESSAGE ConnectionRequest,
    IN BOOLEAN AcceptConnection,
    IN OUT OPTIONAL PPORT_VIEW ServerView,
    OUT OPTIONAL PREMOTE_PORT_VIEW ClientView
    );



NTSTATUS
NTAPI
ZwCompleteConnectPort(
    IN HANDLE PortHandle
    );



NTSTATUS
NTAPI
ZwRequestPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage
    );



NTSTATUS
NTAPI
ZwRequestWaitReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage
    );



NTSTATUS
NTAPI
ZwReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE ReplyMessage
    );



NTSTATUS
NTAPI
ZwReplyWaitReplyPort(
    IN HANDLE PortHandle,
    IN OUT PPORT_MESSAGE ReplyMessage
    );



NTSTATUS
NTAPI
ZwReplyWaitReceivePort(
    IN HANDLE PortHandle,
    OUT OPTIONAL PVOID *PortContext ,
    IN OPTIONAL PPORT_MESSAGE ReplyMessage,
    OUT PPORT_MESSAGE ReceiveMessage
    );



NTSTATUS
NTAPI
ZwReplyWaitReceivePortEx(
    IN HANDLE PortHandle,
    OUT OPTIONAL PVOID *PortContext,
    IN OPTIONAL PPORT_MESSAGE ReplyMessage,
    OUT PPORT_MESSAGE ReceiveMessage,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwImpersonateClientOfPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message
    );



NTSTATUS
NTAPI
ZwReadRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG DataEntryIndex,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesRead
    );



NTSTATUS
NTAPI
ZwWriteRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG DataEntryIndex,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesWritten
    );



NTSTATUS
NTAPI
ZwQueryInformationPort(
    IN HANDLE PortHandle,
    IN PORT_INFORMATION_CLASS PortInformationClass,
    OUT PVOID PortInformation,
    IN ULONG Length,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwCreateSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN OPTIONAL HANDLE FileHandle
    );



NTSTATUS
NTAPI
ZwOpenSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwMapViewOfSection (
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT  PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT  OPTIONAL PLARGE_INTEGER SectionOffset,
    IN OUT  PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
    );



NTSTATUS
NTAPI
ZwUnmapViewOfSection (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );



NTSTATUS
NTAPI
ZwExtendSection (
    IN HANDLE SectionHandle,
    IN OUT PLARGE_INTEGER NewSectionSize
    );



NTSTATUS
NTAPI
ZwAreMappedFilesTheSame (
    IN PVOID File1MappedAsAnImage,
    IN PVOID File2MappedAsFile
    );



NTSTATUS
NTAPI
ZwAllocateVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );



NTSTATUS
NTAPI
ZwFreeVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
    );



NTSTATUS
NTAPI
ZwReadVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesRead
    );



NTSTATUS
NTAPI
ZwWriteVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    IN CONST VOID *Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesWritten
    );



NTSTATUS
NTAPI
ZwFlushVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    OUT PIO_STATUS_BLOCK IoStatus
    );



NTSTATUS
NTAPI
ZwLockVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType
    );



NTSTATUS
NTAPI
ZwUnlockVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG MapType
    );



NTSTATUS
NTAPI
ZwProtectVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );



NTSTATUS
NTAPI
ZwQueryVirtualMemory (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT OPTIONAL PSIZE_T ReturnLength
    );



NTSTATUS
NTAPI
ZwQuerySection (
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN SIZE_T SectionInformationLength,
    OUT OPTIONAL PSIZE_T ReturnLength
    );



NTSTATUS
NTAPI
ZwMapUserPhysicalPages (
    IN PVOID VirtualAddress,
    IN ULONG_PTR NumberOfPages,
    IN OPTIONAL PULONG_PTR UserPfnArray
    );



NTSTATUS
NTAPI
ZwMapUserPhysicalPagesScatter (
    IN PVOID *VirtualAddresses,
    IN ULONG_PTR NumberOfPages,
    IN OPTIONAL PULONG_PTR UserPfnArray
    );



NTSTATUS
NTAPI
ZwAllocateUserPhysicalPages (
    IN HANDLE ProcessHandle,
    IN OUT PULONG_PTR NumberOfPages,
    OUT PULONG_PTR UserPfnArray
    );



NTSTATUS
NTAPI
ZwFreeUserPhysicalPages (
    IN HANDLE ProcessHandle,
    IN OUT PULONG_PTR NumberOfPages,
    IN PULONG_PTR UserPfnArray
    );



NTSTATUS
NTAPI
ZwGetWriteWatch (
    IN HANDLE ProcessHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize,
    OUT PVOID *UserAddressArray,
    IN OUT PULONG_PTR EntriesInUserAddressArray,
    OUT PULONG Granularity
    );



NTSTATUS
NTAPI
ZwResetWriteWatch (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN SIZE_T RegionSize
    );



NTSTATUS
NTAPI
ZwCreatePagingFile (
    IN PUNICODE_STRING PageFileName,
    IN PLARGE_INTEGER MinimumSize,
    IN PLARGE_INTEGER MaximumSize,
    IN ULONG Priority
    );



NTSTATUS
NTAPI
ZwFlushInstructionCache (
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    IN SIZE_T Length
    );



NTSTATUS
NTAPI
ZwFlushWriteBuffer (
    VOID
    );



NTSTATUS
NTAPI
ZwQueryObject (
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetInformationObject (
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    IN PVOID ObjectInformation,
    IN ULONG ObjectInformationLength
    );



NTSTATUS
NTAPI
ZwDuplicateObject (
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN OPTIONAL HANDLE TargetProcessHandle,
    OUT PHANDLE TargetHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options
    );



NTSTATUS
NTAPI
ZwMakeTemporaryObject (
    IN HANDLE Handle
    );



NTSTATUS
NTAPI
ZwMakePermanentObject (
    IN HANDLE Handle
    );



NTSTATUS
NTAPI
ZwSignalAndWaitForSingleObject (
    IN HANDLE SignalHandle,
    IN HANDLE WaitHandle,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwWaitForSingleObject (
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwWaitForMultipleObjects (
    IN ULONG Count,
    IN HANDLE Handles[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwWaitForMultipleObjects32 (
    IN ULONG Count,
    IN LONG Handles[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN OPTIONAL PLARGE_INTEGER Timeout
    );



NTSTATUS
NTAPI
ZwSetSecurityObject (
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );



NTSTATUS
NTAPI
ZwQuerySecurityObject (
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ULONG Length,
    OUT PULONG LengthNeeded
    );



NTSTATUS
NTAPI
ZwClose (
    IN HANDLE Handle
    );



NTSTATUS
NTAPI
ZwCreateDirectoryObject (
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwOpenDirectoryObject (
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQueryDirectoryObject (
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT  PULONG Context,
    OUT PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwCreateSymbolicLinkObject (
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget
    );



NTSTATUS
NTAPI
ZwOpenSymbolicLinkObject (
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQuerySymbolicLinkObject (
    IN HANDLE LinkHandle,
    IN OUT  PUNICODE_STRING LinkTarget,
    OUT PULONG ReturnedLength
    );



NTSTATUS
NTAPI
ZwGetPlugPlayEvent (
    IN HANDLE EventHandle,
    IN OPTIONAL PVOID Context,
    OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
    IN  ULONG EventBufferSize
    );



NTSTATUS
NTAPI
ZwPlugPlayControl(
    IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
    IN OUT PVOID PnPControlData,
    IN ULONG PnPControlDataLength
    );



NTSTATUS
NTAPI
ZwPowerInformation(
    IN POWER_INFORMATION_LEVEL InformationLevel,
    IN OPTIONAL PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT OPTIONAL PVOID OutputBuffer,
    IN ULONG OutputBufferLength
    );



NTSTATUS
NTAPI
ZwSetThreadExecutionState(
    IN EXECUTION_STATE esFlags,               // ES_xxx flags
    OUT EXECUTION_STATE *PreviousFlags
    );



NTSTATUS
NTAPI
ZwRequestWakeupLatency(
    IN LATENCY_TIME latency
    );



// NTSTATUS
// NTAPI
// ZwInitiatePowerAction(
//     IN POWER_ACTION SystemAction,
//     IN SYSTEM_POWER_STATE MinSystemState,
//     IN ULONG Flags,                 // POWER_ACTION_xxx flags
//     IN BOOLEAN Asynchronous
//     );



// NTSTATUS
// NTAPI
// ZwSetSystemPowerState(
//     IN POWER_ACTION SystemAction,
//     IN SYSTEM_POWER_STATE MinSystemState,
//     IN ULONG Flags                  // POWER_ACTION_xxx flags
//     );



// NTSTATUS
// NTAPI
// ZwGetDevicePowerState(
//     IN HANDLE Device,
//     OUT DEVICE_POWER_STATE *State
//     );



NTSTATUS
NTAPI
ZwCancelDeviceWakeupRequest(
    IN HANDLE Device
    );



NTSTATUS
NTAPI
ZwRequestDeviceWakeup(
    IN HANDLE Device
    );



NTSTATUS
NTAPI
ZwCreateProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN OPTIONAL HANDLE SectionHandle,
    IN OPTIONAL HANDLE DebugPort,
    IN OPTIONAL HANDLE ExceptionPort
    );



NTSTATUS
NTAPI
ZwCreateProcessEx (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN OPTIONAL HANDLE SectionHandle,
    IN OPTIONAL HANDLE DebugPort,
    IN OPTIONAL HANDLE ExceptionPort,
    IN ULONG JobMemberLevel
    );



NTSTATUS
NTAPI
ZwOpenProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PCLIENT_ID ClientId
    );



NTSTATUS
NTAPI
ZwTerminateProcess (
    IN OPTIONAL HANDLE ProcessHandle,
    IN NTSTATUS ExitStatus
    );



NTSTATUS
NTAPI
ZwQueryInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwGetNextProcess (
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewProcessHandle
    );



NTSTATUS
NTAPI
ZwGetNextThread (
    IN HANDLE ProcessHandle,
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewThreadHandle
    );



NTSTATUS
NTAPI
ZwQueryPortInformationProcess (
    VOID
    );



NTSTATUS
NTAPI
ZwSetInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
    );



NTSTATUS
NTAPI
ZwCreateThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PINITIAL_TEB InitialTeb,
    IN BOOLEAN CreateSuspended
    );



NTSTATUS
NTAPI
ZwOpenThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN OPTIONAL PCLIENT_ID ClientId
    );



NTSTATUS
NTAPI
ZwTerminateThread (
    IN OPTIONAL HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus
    );



NTSTATUS
NTAPI
ZwSuspendThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );



NTSTATUS
NTAPI
ZwResumeThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );



NTSTATUS
NTAPI
ZwSuspendProcess (
    IN HANDLE ProcessHandle
    );



NTSTATUS
NTAPI
ZwResumeProcess (
    IN HANDLE ProcessHandle
    );



NTSTATUS
NTAPI
ZwGetContextThread (
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext
    );



NTSTATUS
NTAPI
ZwSetContextThread (
    IN HANDLE ThreadHandle,
    IN PCONTEXT ThreadContext
    );



NTSTATUS
NTAPI
ZwQueryInformationThread (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetInformationThread (
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
    );



NTSTATUS
NTAPI
ZwAlertThread (
    IN HANDLE ThreadHandle
    );



NTSTATUS
NTAPI
ZwAlertResumeThread (
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
    );



NTSTATUS
NTAPI
ZwImpersonateThread (
    IN HANDLE ServerThreadHandle,
    IN HANDLE ClientThreadHandle,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos
    );



NTSTATUS
NTAPI
ZwTestAlert (
    VOID
    );



NTSTATUS
NTAPI
ZwRegisterThreadTerminatePort (
    IN HANDLE PortHandle
    );



NTSTATUS
NTAPI
ZwSetLdtEntries (
    IN ULONG Selector0,
    IN ULONG Entry0Low,
    IN ULONG Entry0Hi,
    IN ULONG Selector1,
    IN ULONG Entry1Low,
    IN ULONG Entry1Hi
    );



NTSTATUS
NTAPI
ZwQueueApcThread (
    IN HANDLE ThreadHandle,
    IN PPS_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcArgument1,
    IN OPTIONAL PVOID ApcArgument2,
    IN OPTIONAL PVOID ApcArgument3
    );



NTSTATUS
NTAPI
ZwCreateJobObject (
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwOpenJobObject (
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwAssignProcessToJobObject (
    IN HANDLE JobHandle,
    IN HANDLE ProcessHandle
    );



NTSTATUS
NTAPI
ZwTerminateJobObject (
    IN HANDLE JobHandle,
    IN NTSTATUS ExitStatus
    );



NTSTATUS
NTAPI
ZwIsProcessInJob (
    IN HANDLE ProcessHandle,
    IN OPTIONAL HANDLE JobHandle
    );



NTSTATUS
NTAPI
ZwCreateJobSet (
    IN ULONG NumJob,
    IN PJOB_SET_ARRAY UserJobSet,
    IN ULONG Flags
    );



NTSTATUS
NTAPI
ZwQueryInformationJobObject (
    IN OPTIONAL HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    OUT PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetInformationJobObject (
    IN HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    IN PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength
    );



NTSTATUS
NTAPI
ZwCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    IN OPTIONAL PUNICODE_STRING Class,
    IN ULONG CreateOptions,
    OUT OPTIONAL PULONG Disposition
    );



NTSTATUS
NTAPI
ZwDeleteKey(
    IN HANDLE KeyHandle
    );



NTSTATUS
NTAPI
ZwDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName
    );



NTSTATUS
NTAPI
ZwEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT OPTIONAL PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );



NTSTATUS
NTAPI
ZwEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT OPTIONAL PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );



NTSTATUS
NTAPI
ZwFlushKey(
    IN HANDLE KeyHandle
    );



NTSTATUS
NTAPI
ZwInitializeRegistry(
    IN USHORT BootCondition
    );



NTSTATUS
NTAPI
ZwNotifyChangeKey(
    IN HANDLE KeyHandle,
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT OPTIONAL PVOID Buffer,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous
    );



NTSTATUS
NTAPI
ZwNotifyChangeMultipleKeys(
    IN HANDLE MasterKeyHandle,
    IN OPTIONAL ULONG Count,
    IN OPTIONAL OBJECT_ATTRIBUTES SlaveObjects[],
    IN OPTIONAL HANDLE Event,
    IN OPTIONAL PIO_APC_ROUTINE ApcRoutine,
    IN OPTIONAL PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT OPTIONAL PVOID Buffer,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous
    );



NTSTATUS
NTAPI
ZwLoadKey(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile
    );



NTSTATUS
NTAPI
ZwLoadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags
    );



NTSTATUS
NTAPI
ZwLoadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags,
    IN OPTIONAL HANDLE TrustClassKey
    );



NTSTATUS
NTAPI
ZwOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );



NTSTATUS
NTAPI
ZwQueryKey(
    IN HANDLE KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT OPTIONAL PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );



NTSTATUS
NTAPI
ZwQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT OPTIONAL PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );



NTSTATUS
NTAPI
ZwQueryMultipleValueKey(
    IN HANDLE KeyHandle,
    IN OUT PKEY_VALUE_ENTRY ValueEntries,
    IN ULONG EntryCount,
    OUT PVOID ValueBuffer,
    IN OUT PULONG BufferLength,
    OUT OPTIONAL PULONG RequiredBufferLength
    );



NTSTATUS
NTAPI
ZwReplaceKey(
    IN POBJECT_ATTRIBUTES NewFile,
    IN HANDLE TargetHandle,
    IN POBJECT_ATTRIBUTES OldFile
    );



NTSTATUS
NTAPI
ZwRenameKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING  NewName
    );



NTSTATUS
NTAPI
ZwCompactKeys(
    IN ULONG Count,
    IN HANDLE KeyArray[]
            );



NTSTATUS
NTAPI
ZwCompressKey(
    IN HANDLE Key
            );



NTSTATUS
NTAPI
ZwRestoreKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG Flags
    );



NTSTATUS
NTAPI
ZwSaveKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle
    );



NTSTATUS
NTAPI
ZwSaveKeyEx(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG  Format
    );



NTSTATUS
NTAPI
ZwSaveMergedKeys(
    IN HANDLE HighPrecedenceKeyHandle,
    IN HANDLE LowPrecedenceKeyHandle,
    IN HANDLE FileHandle
    );



NTSTATUS
NTAPI
ZwSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN OPTIONAL ULONG TitleIndex,
    IN ULONG Type,
    IN OPTIONAL PVOID Data,
    IN ULONG DataSize
    );



NTSTATUS
NTAPI
ZwUnloadKey(
    IN POBJECT_ATTRIBUTES TargetKey
    );



NTSTATUS
NTAPI
ZwUnloadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG Flags
    );



NTSTATUS
NTAPI
ZwUnloadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN OPTIONAL HANDLE Event
    );



NTSTATUS
NTAPI
ZwSetInformationKey(
    IN HANDLE KeyHandle,
    IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    IN PVOID KeySetInformation,
    IN ULONG KeySetInformationLength
    );



NTSTATUS
NTAPI
ZwQueryOpenSubKeys(
    IN POBJECT_ATTRIBUTES TargetKey,
    OUT PULONG  HandleCount
    );



NTSTATUS
NTAPI
ZwQueryOpenSubKeysEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG BufferLength,
    OUT PVOID Buffer,
    OUT PULONG RequiredSize
    );



NTSTATUS
NTAPI
ZwLockRegistryKey(
    IN HANDLE KeyHandle
    );



NTSTATUS
NTAPI
ZwLockProductActivationKeys(
    IN OUT OPTIONAL ULONG *pPrivateVer,
    OUT OPTIONAL ULONG *pSafeMode
    );



NTSTATUS
NTAPI
ZwAccessCheck (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );



NTSTATUS
NTAPI
ZwAccessCheckByType (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );



NTSTATUS
NTAPI
ZwAccessCheckByTypeResultList (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT  PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus
    );



NTSTATUS
NTAPI
ZwCreateToken(
    OUT PHANDLE TokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
    IN TOKEN_TYPE TokenType,
    IN PLUID AuthenticationId,
    IN PLARGE_INTEGER ExpirationTime,
    IN PTOKEN_USER User,
    IN PTOKEN_GROUPS Groups,
    IN PTOKEN_PRIVILEGES Privileges,
    IN OPTIONAL PTOKEN_OWNER Owner,
    IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
    IN OPTIONAL PTOKEN_DEFAULT_DACL DefaultDacl,
    IN PTOKEN_SOURCE TokenSource
    );



NTSTATUS
NTAPI
ZwCompareTokens(
    IN HANDLE FirstTokenHandle,
    IN HANDLE SecondTokenHandle,
    OUT PBOOLEAN Equal
    );



NTSTATUS
NTAPI
ZwOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle
    );



NTSTATUS
NTAPI
ZwOpenThreadTokenEx(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle
    );



NTSTATUS
NTAPI
ZwOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
    );



NTSTATUS
NTAPI
ZwOpenProcessTokenEx(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle
    );



NTSTATUS
NTAPI
ZwDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle
    );



NTSTATUS
NTAPI
ZwFilterToken (
    IN HANDLE ExistingTokenHandle,
    IN ULONG Flags,
    IN OPTIONAL PTOKEN_GROUPS SidsToDisable,
    IN OPTIONAL PTOKEN_PRIVILEGES PrivilegesToDelete,
    IN OPTIONAL PTOKEN_GROUPS RestrictedSids,
    OUT PHANDLE NewTokenHandle
    );



NTSTATUS
NTAPI
ZwImpersonateAnonymousToken(
    IN HANDLE ThreadHandle
    );



NTSTATUS
NTAPI
ZwQueryInformationToken (
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwSetInformationToken (
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    IN PVOID TokenInformation,
    IN ULONG TokenInformationLength
    );



NTSTATUS
NTAPI
ZwAdjustPrivilegesToken (
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN OPTIONAL PTOKEN_PRIVILEGES NewState,
    IN OPTIONAL ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState,
    OUT OPTIONAL PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwAdjustGroupsToken (
    IN HANDLE TokenHandle,
    IN BOOLEAN ResetToDefault,
    IN PTOKEN_GROUPS NewState ,
    IN OPTIONAL ULONG BufferLength ,
    OUT PTOKEN_GROUPS PreviousState ,
    OUT PULONG ReturnLength
    );



NTSTATUS
NTAPI
ZwPrivilegeCheck (
    IN HANDLE ClientToken,
    IN OUT  PPRIVILEGE_SET RequiredPrivileges,
    OUT PBOOLEAN Result
    );



NTSTATUS
NTAPI
ZwAccessCheckAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ACCESS_MASK DesiredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );



NTSTATUS
NTAPI
ZwAccessCheckByTypeAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );



NTSTATUS
NTAPI
ZwAccessCheckByTypeResultListAndAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );



NTSTATUS
NTAPI
ZwAccessCheckByTypeResultListAndAuditAlarmByHandle (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN HANDLE ClientToken,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN OPTIONAL PSID PrincipalSelfSid,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PNTSTATUS AccessStatus,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
ZwOpenObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN OPTIONAL PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN ACCESS_MASK GrantedAccess,
    IN OPTIONAL PPRIVILEGE_SET Privileges,
    IN BOOLEAN ObjectCreation,
    IN BOOLEAN AccessGranted,
    OUT PBOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
ZwPrivilegeObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted
    );


NTSTATUS
NTAPI
ZwCloseObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN BOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
ZwDeleteObjectAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN OPTIONAL PVOID HandleId,
    IN BOOLEAN GenerateOnClose
    );


NTSTATUS
NTAPI
ZwPrivilegedServiceAuditAlarm (
    IN PUNICODE_STRING SubsystemName,
    IN PUNICODE_STRING ServiceName,
    IN HANDLE ClientToken,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted
    );


NTSTATUS
NTAPI
ZwContinue (
    IN PCONTEXT ContextRecord,
    IN BOOLEAN TestAlert
    );


NTSTATUS
NTAPI
ZwRaiseException (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN BOOLEAN FirstChance
    );

// end_zwapi

ULONG
DbgPrint(
	IN PCH Format,
	...
	);

VOID NTAPI
DebugService2 (
    PVOID Arg1,
    PVOID Arg2,
    ULONG Service
    );


/*
__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerAdd (
    LARGE_INTEGER Addend1,
    LARGE_INTEGER Addend2
    );

__inline
LARGE_INTEGER
NTAPI
RtlEnlargedIntegerMultiply (
    LONG Multiplicand,
    LONG Multiplier
    );

__inline
LARGE_INTEGER
NTAPI
RtlEnlargedUnsignedMultiply (
    ULONG Multiplicand,
    ULONG Multiplier
    );

__inline
ULONG
NTAPI
RtlEnlargedUnsignedDivide (
    IN ULARGE_INTEGER Dividend,
    IN ULONG Divisor,
    IN PULONG Remainder OPTIONAL
    );

__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerNegate (
    LARGE_INTEGER Subtrahend
    );
__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerSubtract (
    LARGE_INTEGER Minuend,
    LARGE_INTEGER Subtrahend
    );
*/
LARGE_INTEGER
NTAPI
RtlExtendedMagicDivide (
    LARGE_INTEGER Dividend,
    LARGE_INTEGER MagicDivisor,
    CCHAR ShiftCount
    );

LARGE_INTEGER
NTAPI
RtlExtendedLargeIntegerDivide (
    LARGE_INTEGER Dividend,
    ULONG Divisor,
    PULONG Remainder
    );

LARGE_INTEGER
NTAPI
RtlLargeIntegerDivide (
    LARGE_INTEGER Dividend,
    LARGE_INTEGER Divisor,
    PLARGE_INTEGER Remainder
    );

LARGE_INTEGER
NTAPI
RtlExtendedIntegerMultiply (
    LARGE_INTEGER Multiplicand,
    LONG Multiplier
    );

/*
__inline
LARGE_INTEGER
NTAPI
RtlConvertLongToLargeInteger (
    LONG SignedInteger
    );


__inline
LARGE_INTEGER
NTAPI
RtlConvertUlongToLargeInteger (
    ULONG UnsignedInteger
    );

__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerShiftLeft (
    LARGE_INTEGER LargeInteger,
    CCHAR ShiftCount
    );

__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerShiftRight (
    LARGE_INTEGER LargeInteger,
    CCHAR ShiftCount
    );

__inline
LARGE_INTEGER
NTAPI
RtlLargeIntegerArithmeticShift (
    LARGE_INTEGER LargeInteger,
    CCHAR ShiftCount
    );
__inline
BOOLEAN
NTAPI
RtlCheckBit (
    PRTL_BITMAP BitMapHeader,
    ULONG BitPosition
    );
*/

BOOLEAN
NTAPI
RtlIsValidOemCharacter (
    IN OUT PWCHAR Char
    );

PIMAGE_NT_HEADERS
NTAPI
RtlpImageNtHeader(
    PVOID Base
    );

RTL_PATH_TYPE
RtlDetermineDosPathNameType_U(
	IN PCWSTR DosFileName
	);

PRTL_TRACE_DATABASE
RtlTraceDatabaseCreate (
    IN ULONG Buckets,
    IN SIZE_T MaximumSize OPTIONAL,
    IN ULONG Flags, // OPTIONAL in User mode
    IN ULONG Tag,   // OPTIONAL in User mode
    IN RTL_TRACE_HASH_FUNCTION HashFunction OPTIONAL
    );

BOOLEAN
RtlTraceDatabaseValidate (
    IN PRTL_TRACE_DATABASE Database
    );

BOOLEAN
RtlTraceDatabaseAdd (
    IN PRTL_TRACE_DATABASE Database,
    IN ULONG Count,
    IN PVOID * Trace,
    OUT PRTL_TRACE_BLOCK * TraceBlock OPTIONAL
    );

BOOLEAN
RtlTraceDatabaseFind (
    PRTL_TRACE_DATABASE Database,
    IN ULONG Count,
    IN PVOID * Trace,
    OUT PRTL_TRACE_BLOCK * TraceBlock OPTIONAL
    );

BOOLEAN
RtlTraceDatabaseEnumerate (
    PRTL_TRACE_DATABASE Database,
    OUT PRTL_TRACE_ENUMERATE Enumerate,
    OUT PRTL_TRACE_BLOCK * TraceBlock
    );

VOID
RtlTraceDatabaseLock (
    IN PRTL_TRACE_DATABASE Database
    );

VOID
RtlTraceDatabaseUnlock (
    IN PRTL_TRACE_DATABASE Database
    );

VOID
RtlpGetStackLimits (
    OUT PULONG_PTR LowLimit,
    OUT PULONG_PTR HighLimit
    );

NTSTATUS
NTAPI
RtlEnterCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
    );

NTSTATUS
NTAPI
RtlLeaveCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
    );

LOGICAL
NTAPI
RtlIsCriticalSectionLocked (
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

LOGICAL
NTAPI
RtlIsCriticalSectionLockedByThread (
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

ULONG
NTAPI
RtlGetCriticalSectionRecursionCount (
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

LOGICAL
NTAPI
RtlTryEnterCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
    );

NTSTATUS
NTAPI
RtlInitializeCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
    );

VOID
NTAPI
RtlEnableEarlyCriticalSectionEventCreation(
    VOID
    );

NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(
    PRTL_CRITICAL_SECTION CriticalSection,
    ULONG SpinCount
    );

ULONG
NTAPI
RtlSetCriticalSectionSpinCount(
    PRTL_CRITICAL_SECTION CriticalSection,
    ULONG SpinCount
    );

NTSTATUS
NTAPI
RtlDeleteCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
    );

NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll (
    IN PVOID DllHandle
    );

NTSTATUS
NTAPI
LdrLoadDll(
	IN OPTIONAL PWSTR DllPath,
	IN OPTIONAL PULONG DllCharacteristics,
	IN PUNICODE_STRING DllName,
	OUT PVOID *DllHandle
	);

NTSTATUS
NTAPI
LdrUnloadDll(
	IN PVOID DllHandle
	);

NTSTATUS
NTAPI
LdrGetDllHandle(
	IN OPTIONAL PWSTR DllPath,
	IN OPTIONAL PULONG DllCharacteristics,
	IN PUNICODE_STRING DllName,
	OUT PVOID *DllHandle
	);

NTSTATUS
NTAPI
LdrGetDllHandleEx(
	IN ULONG Flags,
	IN OPTIONAL PCWSTR DllPath,
	IN OPTIONAL PULONG DllCharacteristics,
	IN PUNICODE_STRING DllName,
	OUT OPTIONAL PVOID *DllHandle
	);

NTSTATUS
NTAPI
LdrGetDllHandleByMapping(
	IN PVOID Base,
	OUT PVOID *DllHandle
	);

NTSTATUS
NTAPI
LdrGetDllHandleByName(
	IN OPTIONAL PUNICODE_STRING BaseDllName,
	IN OPTIONAL PUNICODE_STRING FullDllName,
	OUT PVOID *DllHandle
	);

NTSTATUS
NTAPI
LdrAddRefDll(
	IN ULONG Flags,
	IN PVOID DllHandle
	);

NTSTATUS
NTAPI
LdrGetProcedureAddress(
	IN PVOID DllHandle,
	IN OPTIONAL PANSI_STRING ProcedureName,
	IN OPTIONAL ULONG ProcedureNumber,
	OUT PVOID *ProcedureAddress
	);

NTSTATUS
NTAPI
LdrGetProcedureAddressEx(
	IN PVOID DllHandle,
	IN OPTIONAL PANSI_STRING ProcedureName,
	IN OPTIONAL ULONG ProcedureNumber,
	OUT PVOID *ProcedureAddress,
	IN ULONG Flags
	);

NTSTATUS
NTAPI
LdrLockLoaderLock(
	IN ULONG Flags,
	OUT OPTIONAL ULONG *Disposition,
	OUT PVOID *Cookie
	);

NTSTATUS
NTAPI
LdrRelocateImage(
	IN PVOID NewBase,
	IN PSTR LoaderName,
	IN NTSTATUS Success,
	IN NTSTATUS Conflict,
	IN NTSTATUS Invalid
	);

NTSTATUS
NTAPI
LdrRelocateImageWithBias(
	IN PVOID NewBase,
	IN LONGLONG Bias,
	IN PSTR LoaderName,
	IN NTSTATUS Success,
	IN NTSTATUS Conflict,
	IN NTSTATUS Invalid
	);

PIMAGE_BASE_RELOCATION
NTAPI
LdrProcessRelocationBlock(
	IN ULONG_PTR VA,
	IN ULONG SizeOfBlock,
	IN PUSHORT NextOffset,
	IN LONG_PTR Diff
	);

BOOLEAN
NTAPI
LdrVerifyMappedImageMatchesChecksum(
	IN PVOID BaseAddress,
	IN SIZE_T NumberOfBytes,
	IN ULONG FileLength
	);

NTSTATUS
NTAPI
LdrQueryModuleServiceTags(
	IN PVOID DllHandle,
	OUT PULONG ServiceTagBuffer,
	IN OUT PULONG BufferSize
	);

NTSTATUS
NTAPI
LdrRegisterDllNotification(
	IN ULONG Flags,
	IN PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
	IN PVOID Context,
	OUT PVOID *Cookie
	);

NTSTATUS
NTAPI
LdrUnregisterDllNotification(
	IN PVOID Cookie
	);

ULONG
NTAPI
CsrGetProcessId(
	);

void
NTAPI
A_SHAFinal(
	PSHA_CTX Context,
	PULONG Result
	);


PVOID
NTAPI
A_SHAUpdate(
	IN OUT PSHA_CTX,
	IN PCHAR,
	IN UINT
	);

PVOID
NTAPI
A_SHAInit(
	IN OUT PSHA_CTX,
	OUT PVOID
	);

BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    IN PCWSTR DosFileName,
    OUT PUNICODE_STRING NtFileName,
    OUT PWSTR *FilePart OPTIONAL,
    PVOID Reserved
    );

NTSTATUS
NTAPI
RtlDosPathNameToNtPathName_U_WithStatus(
    IN PCWSTR DosFileName,
    OUT PUNICODE_STRING NtFileName,
    OUT PWSTR *FilePart OPTIONAL,
    PVOID Reserved // Must be NULL
	);

PVOID
NTAPI
RtlAddVectoredExceptionHandler (
    IN ULONG First,
    IN PVECTORED_EXCEPTION_HANDLER Handler
    );

PVOID
NTAPI
RtlAddVectoredContinueHandler (
    IN ULONG First,
    IN PVECTORED_EXCEPTION_HANDLER Handler
    );

NTSTATUS
NTAPI
RtlAnalyzeProfile (
    VOID
    );

BOOLEAN
NTAPI
RtlCallVectoredContinueHandlers (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord
    );

PVOID
RtlEncodePointer(
     PVOID Ptr
     );

PVOID
RtlDecodePointer(
     PVOID Ptr
     );

PVOID
RtlEncodeSystemPointer(
     PVOID Ptr
     );

PVOID
RtlDecodeSystemPointer(
     PVOID Ptr
     );

VOID
NTAPI
RtlDeleteResource(
    PRTL_RESOURCE Resource
    );

NTSTATUS
NTAPI
RtlDeleteSecurityObject(
    PSECURITY_DESCRIPTOR * ObjectDescriptor
    );

BOOLEAN
RtlDllShutdownInProgress(
    VOID
    );

ULONG
NTAPI
RtlGetCurrentProcessorNumber (
    VOID
    );

#define RTL_UNLOAD_EVENT_TRACE_NUMBER 16

typedef struct _RTL_UNLOAD_EVENT_TRACE {
    PVOID BaseAddress;   // Base address of dll
    SIZE_T SizeOfImage;  // Size of image
    ULONG Sequence;      // Sequence number for this event
    ULONG TimeDateStamp; // Time and date of image
    ULONG CheckSum;      // Image checksum
    WCHAR ImageName[32]; // Image name
} RTL_UNLOAD_EVENT_TRACE, *PRTL_UNLOAD_EVENT_TRACE;

typedef struct _RTL_UNLOAD_EVENT_TRACE64 {
    ULONGLONG BaseAddress;   // Base address of dll
    ULONGLONG SizeOfImage;  // Size of image
    ULONG Sequence;      // Sequence number for this event
    ULONG TimeDateStamp; // Time and date of image
    ULONG CheckSum;      // Image checksum
    WCHAR ImageName[32]; // Image name
} RTL_UNLOAD_EVENT_TRACE64, *PRTL_UNLOAD_EVENT_TRACE64;

typedef struct _RTL_UNLOAD_EVENT_TRACE32 {
    ULONG BaseAddress;   // Base address of dll
    ULONG SizeOfImage;  // Size of image
    ULONG Sequence;      // Sequence number for this event
    ULONG TimeDateStamp; // Time and date of image
    ULONG CheckSum;      // Image checksum
    WCHAR ImageName[32]; // Image name
} RTL_UNLOAD_EVENT_TRACE32, *PRTL_UNLOAD_EVENT_TRACE32;

PRTL_UNLOAD_EVENT_TRACE
NTAPI
RtlGetUnloadEventTrace(
    VOID
    );

NTSTATUS
NTAPI
RtlInitializeProfile(
    BOOLEAN KernelToo
    );

typedef BOOLEAN
(NTAPI *
PRTL_IS_THREAD_WITHIN_LOADER_CALLOUT)(
    VOID
    );

BOOLEAN
NTAPI
RtlIsThreadWithinLoaderCallout (
    VOID
    );

NTSTATUS
NTAPI
RtlSetLFHDebuggingInformation(
	PVOID LFHHeap,
	PHEAP_DEBUGGING_INFORMATION DebuggingInformation
	);

ULONG
NTAPI
RtlMultipleAllocateHeap (
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN SIZE_T Size,
    IN ULONG Count,
    OUT PVOID * Array
    );

ULONG
NTAPI
RtlMultipleFreeHeap (
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN ULONG Count,
    OUT PVOID * Array
    );

NTSTATUS
NTAPI
RtlNewSecurityObjectEx (
    IN PSECURITY_DESCRIPTOR ParentDescriptor OPTIONAL,
    IN PSECURITY_DESCRIPTOR CreatorDescriptor OPTIONAL,
    OUT PSECURITY_DESCRIPTOR * NewDescriptor,
    IN GUID *ObjectType OPTIONAL,
    IN BOOLEAN IsDirectoryObject,
    IN ULONG AutoInheritFlags,
    IN HANDLE Token,
    IN PGENERIC_MAPPING GenericMapping
    );

NTSTATUS
NTAPI
RtlNewSecurityObjectWithMultipleInheritance (
    IN PSECURITY_DESCRIPTOR ParentDescriptor OPTIONAL,
    IN PSECURITY_DESCRIPTOR CreatorDescriptor OPTIONAL,
    OUT PSECURITY_DESCRIPTOR * NewDescriptor,
    IN GUID **pObjectType OPTIONAL,
    IN ULONG GuidCount,
    IN BOOLEAN IsDirectoryObject,
    IN ULONG AutoInheritFlags,
    IN HANDLE Token,
    IN PGENERIC_MAPPING GenericMapping
    );

#if !defined(_WINDOWS_)
NTSTATUS
NTAPI
RtlSetHeapInformation (
    IN PVOID HeapHandle,
    IN HEAP_INFORMATION_CLASS HeapInformationClass,
    IN PVOID HeapInformation OPTIONAL,
    IN SIZE_T HeapInformationLength OPTIONAL
    );

NTSTATUS
NTAPI
RtlQueryHeapInformation (
    IN PVOID HeapHandle,
    IN HEAP_INFORMATION_CLASS HeapInformationClass,
    OUT PVOID HeapInformation OPTIONAL,
    IN SIZE_T HeapInformationLength OPTIONAL,
    OUT PSIZE_T ReturnLength OPTIONAL
    );
#endif

NTSTATUS
NTAPI
RtlQuerySecurityObject (
     PSECURITY_DESCRIPTOR ObjectDescriptor,
     SECURITY_INFORMATION SecurityInformation,
     PSECURITY_DESCRIPTOR ResultantDescriptor,
     ULONG DescriptorLength,
     PULONG ReturnLength
     );

NTSTATUS
NTAPI
RtlRegisterWait(
    OUT PHANDLE WaitHandle,
    IN  HANDLE  Handle,
    IN  WAITORTIMERCALLBACKFUNC Function,
    IN  PVOID Context,
    IN  ULONG  Milliseconds,
    IN  ULONG  Flags
    );

ULONG
NTAPI
RtlRemoveVectoredContinueHandler (
    IN PVOID Handle
    );

ULONG
NTAPI
RtlRemoveVectoredExceptionHandler (
    IN PVOID Handle
    );

NTSTATUS
NTAPI
RtlSetIoCompletionCallback(
    IN  HANDLE  FileHandle,
    IN  APC_CALLBACK_FUNCTION  CompletionProc,
    IN  ULONG Flags
    );

NTSTATUS
NTAPI
RtlSetSecurityObject(
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR ModificationDescriptor,
    PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    PGENERIC_MAPPING GenericMapping,
    HANDLE Token
    );

NTSTATUS
NTAPI
RtlSetSecurityObjectEx(
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR ModificationDescriptor,
    IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
    IN ULONG AutoInheritFlags,
    IN PGENERIC_MAPPING GenericMapping,
    IN HANDLE Token OPTIONAL
    );

typedef ULONG (NTAPI RTLP_UNHANDLED_EXCEPTION_FILTER) (
    struct _EXCEPTION_POINTERS *ExceptionInfo
    );

typedef RTLP_UNHANDLED_EXCEPTION_FILTER *PRTLP_UNHANDLED_EXCEPTION_FILTER;

VOID
RtlSetUnhandledExceptionFilter (
    PRTLP_UNHANDLED_EXCEPTION_FILTER UnhandledExceptionFilter
    );

NTSTATUS
NTAPI
RtlStartProfile (
    VOID
    );

NTSTATUS
NTAPI
RtlStopProfile (
    VOID
    );

NTSTATUS
RtlWow64EnableFsRedirection(
    IN BOOLEAN Wow64FsEnableRedirection
    );


NTSTATUS
RtlWow64EnableFsRedirectionEx(
    IN PVOID Wow64FsEnableRedirection,
    OUT PVOID *OldFsRedirectionLevel
    );

NTSTATUS
NTAPI
RtlRegisterWait(
    OUT PHANDLE WaitHandle,
    IN  HANDLE  Handle,
    IN  WAITORTIMERCALLBACKFUNC Function,
    IN  PVOID Context,
    IN  ULONG  Milliseconds,
    IN  ULONG  Flags
    );

NTSTATUS
NTAPI
RtlDeregisterWait(
    IN HANDLE WaitHandle
    );

NTSTATUS
NTAPI
RtlDeregisterWaitEx(
    IN HANDLE WaitHandle,
    IN HANDLE Event
    );

#define RtlEqualMemory(Destination,Source,Length) (!memcmp((Destination),(Source),(Length)))
#define RtlMoveMemory(Destination,Source,Length) memmove((Destination),(Source),(Length))
#define RtlCopyMemory(Destination,Source,Length) memcpy((Destination),(Source),(Length))
#define RtlFillMemory(Destination,Length,Fill) memset((Destination),(Fill),(Length))
#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

NTSTATUS NTAPI RtlCopyMappedMemory (
    PVOID       pDest,
    CONST PVOID pSrc,
    SIZE_T      bytesToCopy
);

typedef
VOID
(*PKNORMAL_ROUTINE)
(IN PVOID NormalContext,
 IN PVOID SystemArgument1,
 IN PVOID SystemArgument2
 );

VOID
KiUserCallbackDispatcher(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG INputLength
	);

NTSTATUS
NTAPI
CsrClientConnectToServer(
    IN PWSTR ObjectDirectory,
    IN ULONG ServertDllIndex,
    IN PCSR_CALLBACK_INFO CallbackInformation OPTIONAL,
    IN PVOID ConnectionInformation,
    IN OUT PULONG ConnectionInformationLength OPTIONAL,
    OUT PBOOLEAN CalledFromServer OPTIONAL
    );


NTSTATUS
NTAPI
CsrClientCallServer(
    IN OUT PCSR_API_MSG m,
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer OPTIONAL,
    IN CSR_API_NUMBER ApiNumber,
    IN ULONG ArgLength
    );


PCSR_CAPTURE_HEADER
NTAPI
CsrAllocateCaptureBuffer(
    IN ULONG CountMessagePointers,
    IN ULONG CountCapturePointers,
    IN ULONG Size
    );

VOID
NTAPI
CsrFreeCaptureBuffer(
    IN PCSR_CAPTURE_HEADER CaptureBuffer
    );


ULONG
NTAPI
CsrAllocateMessagePointer(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN ULONG Length,
    OUT PVOID *Pointer
    );

VOID
NTAPI
CsrCaptureMessageBuffer(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN PVOID Buffer OPTIONAL,
    IN ULONG Length,
    OUT PVOID *CapturedBuffer
    );

VOID
NTAPI
CsrCaptureMessageString(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN PCSTR String,
    IN ULONG Length,
    IN ULONG MaximumLength,
    OUT PSTRING CapturedString
    );

PLARGE_INTEGER
NTAPI
CsrCaptureTimeout(
    IN ULONG Milliseconds,
    OUT PLARGE_INTEGER Timeout
    );

VOID
NTAPI
CsrProbeForWrite(
    IN PVOID Address,
    IN ULONG Length,
    IN ULONG Alignment
    );

VOID
NTAPI
CsrProbeForRead(
    IN PVOID Address,
    IN ULONG Length,
    IN ULONG Alignment
    );

NTSTATUS
NTAPI
CsrNewThread(
    VOID
    );

NTSTATUS
NTAPI
CsrIdentifyAlertableThread(
    VOID
    );

NTSTATUS
NTAPI
CsrSetPriorityClass(
    IN HANDLE ProcessHandle,
    IN OUT PULONG PriorityClass
    );

//added 20/03/2011
NTSTATUS
NTAPI
RtlCreateProcessReflection(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN OPTIONAL PVOID StartRoutine,
	IN OPTIONAL PVOID StartContext,
	IN OPTIONAL HANDLE EventHandle,
	OUT OPTIONAL PRTL_PROCESS_REFLECTION_INFORMATION ReflectionInformation
	);


NTSTATUS
NTAPI
RtlCloneUserProcess(
	IN ULONG ProcessFlags,
	IN OPTIONAL PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
	IN OPTIONAL PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	IN OPTIONAL HANDLE DebugPort,
	OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation
	);


VOID
NTAPI
LdrShutdownProcess(
	);

NTSTATUS
NTAPI
RtlQueryProcessModuleInformation(
    IN HANDLE hProcess OPTIONAL,
    IN ULONG Flags,
    IN OUT PRTL_DEBUG_INFORMATION Buffer
    );

NTSTATUS
NTAPI
RtlQueryProcessBackTraceInformation(
    IN OUT PRTL_DEBUG_INFORMATION Buffer
    );

NTSTATUS
NTAPI
RtlQueryProcessHeapInformation(
    IN OUT PRTL_DEBUG_INFORMATION Buffer
    );

NTSTATUS
NTAPI
RtlQueryProcessLockInformation(
    IN OUT PRTL_DEBUG_INFORMATION Buffer
    );

PRTL_DEBUG_INFORMATION
NTAPI
RtlCreateQueryDebugBuffer(
    IN ULONG MaximumCommit OPTIONAL,
    IN BOOLEAN UseEventPair
    );

NTSTATUS
NTAPI
RtlDestroyQueryDebugBuffer(
    IN PRTL_DEBUG_INFORMATION Buffer
    );

NTSTATUS
NTAPI
RtlQueryProcessDebugInformation(
    IN HANDLE UniqueProcessId,
    IN ULONG Flags,
    IN OUT PRTL_DEBUG_INFORMATION Buffer
    );

NTSTATUS
NTAPI
RtlCreateTimer(
    IN HANDLE TimerQueueHandle,
    OUT HANDLE *Handle,
    IN WAITORTIMERCALLBACKFUNC Function,
    IN PVOID Context,
    IN ULONG DueTime,
    IN ULONG Period,
    IN ULONG Flags
    );

NTSTATUS NTAPI RtlCreateTimerQueue(
    PHANDLE TimerQueueHandle
);

NTSTATUS
NTAPI
RtlUpdateTimer(
    IN HANDLE TimerQueueHandle,
    IN HANDLE TimerHandle,
    IN ULONG  DueTime,
    IN ULONG  Period
    );

NTSTATUS
NTAPI
RtlDeleteTimer(
    IN HANDLE TimerQueueHandle,
    IN HANDLE TimerToCancel,
    IN HANDLE Event
    );

NTSTATUS
NTAPI
RtlDeleteTimerQueue(
    IN HANDLE TimerQueueHandle
    );

NTSTATUS
NTAPI
RtlDeleteTimerQueueEx(
    IN HANDLE TimerQueueHandle,
    IN HANDLE Event
    );


BOOLEAN
NTAPI
RtlDoesFileExists_U(
    PCWSTR FileName
    );


ULONG
RtlGetCurrentDirectory_U(
	ULONG nBufferLength,
	PWSTR lpBuffer
	);

NTSTATUS
RtlSetCurrentDirectory_U(
	PUNICODE_STRING PathName
	);


ULONG
RtlDosSearchPath_U(
	IN PWSTR lpPath,
	IN PWSTR lpFileName,
	IN PWSTR lpExtension OPTIONAL,
	IN ULONG nBufferLength,
	OUT PWSTR lpBuffer,
	OUT PWSTR *lpFilePart
	);


void
NTAPI
RtlInitString(
    PSTRING DestinationString,
    PCSZ SourceString
    );

ULONG
NTAPI
RtlGetFullPathName_U(
    IN PCWSTR lpFileName,
    IN ULONG nBufferLength,
    OUT PWSTR lpBuffer,
    OUT OPTIONAL PWSTR *lpFilePart
    );

LONG
NTAPI
RtlCompareString(
    const STRING * String1,
    const STRING * String2,
    BOOLEAN CaseInSensitive
    );


NTSTATUS
NTAPI
LdrRegisterDllNotification(
	IN ULONG Flags,
	IN PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
	IN PVOID Context,
	OUT PVOID *Cookie
	);


NTSTATUS
NTAPI
LdrUnregisterDllNotification(
	IN PVOID Cookie
	);


ULONG
NTAPI
EtwRegisterSecurityProvider();

ULONG
NTAPI
EtwWriteUMSecurityEvent(
    PCEVENT_DESCRIPTOR EventDescriptor,
    USHORT EventProperty,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData);


ULONG
NTAPI
EtwEventWriteEndScenario(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);

ULONG
NTAPI
EtwEventWriteFull(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	USHORT EventProperty,
	LPCGUID ActivityId,
	LPCGUID RelatedActivityId,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);


ULONG
NTAPI
EtwEventWriteStartScenario(
	REGHANDLE RegHandle,
	PCEVENT_DESCRIPTOR EventDescriptor,
	ULONG UserDataCount,
	PEVENT_DATA_DESCRIPTOR UserData
	);


//
// old channel apis, from nt4
//

NTSTATUS
NTAPI
NtCreateChannel (
    OUT PHANDLE ChannelHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

NTSTATUS
NTAPI
NtOpenChannel (
    OUT PHANDLE ChannelHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSTATUS
NTAPI
NtListenChannel (
    IN HANDLE ChannelHandle,
    OUT PCHANNEL_MESSAGE *Message
	);

NTSTATUS
NTAPI
NtSendWaitReplyChannel (
    IN HANDLE ChannelHandle,
    IN PVOID Text,
    IN ULONG Length,
    OUT PCHANNEL_MESSAGE *Message
    );

NTSTATUS
NTAPI
NtReplyWaitSendChannel (
    IN PVOID Text,
    IN ULONG Length,
    OUT PCHANNEL_MESSAGE *Message
    );


ULONG
NTAPI
AlpcUnregisterCompletionListWorkerThread(
		PVOID CompletionList
		);


void
NTAPI
RtlUpdateClonedCriticalSection(
		PRTL_CRITICAL_SECTION CriticalSection
		);

NTSTATUS
NTAPI
RtlGetFullPathName_UstrEx(
		PUNICODE_STRING FileName,
		PUNICODE_STRING StaticString,
		PUNICODE_STRING DynamicString,
		PPUNICODE_STRING StringUsed,
		PULONG FilePartPrefixCch,
		PUCHAR NameInvalid,
		PRTL_PATH_TYPE InputPathType,
		PULONG BytesRequired);

int
NTAPI
LdrInitShimEngineDynamic(
		PVOID pShimEngineModule);

NTSTATUS
NTAPI
NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    IN OPTIONAL PUNICODE_STRING Class,
    IN ULONG CreateOptions,
    OUT OPTIONAL PULONG Disposition
    );

NTSTATUS
NTAPI
NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN OPTIONAL ULONG TitleIndex,
    IN ULONG Type,
    IN OPTIONAL PVOID Data,
    IN ULONG DataSize
    );

NTSTATUS
NTAPI
NtDeleteFile (
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSTATUS
NTAPI
RtlGetVersion(
	OUT PRTL_OSVERSIONINFOW lpVersionInformation
	);
		
NTSTATUS
NTAPI
ZwWow64QueryInformationProcess64(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );


NTSTATUS
NTAPI
ZwWow64QueryVirtualMemory64(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT OPTIONAL PSIZE_T ReturnLength
    );


NTSTATUS
NTAPI
ZwWow64ReadVirtualMemory64(
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesRead
    );


NTSTATUS
NTAPI
ZwWow64WriteVirtualMemory64(
    IN HANDLE ProcessHandle,
    IN OPTIONAL PVOID BaseAddress,
    IN CONST VOID *Buffer,
    IN SIZE_T BufferSize,
    OUT OPTIONAL PSIZE_T NumberOfBytesWritten
    );

void
NTAPI
ZwWow64GetCurrentProcessorNumberEx(
		OUT PPROCESSOR_NUMBER ProcNumber
);

PCSR_CAPTURE_HEADER
NTAPI
ZwWow64CsrAllocateCaptureBuffer(
    IN ULONG CountMessagePointers,
    IN ULONG CountCapturePointers,
    IN ULONG Size
    );

ULONG
NTAPI
ZwWow64CsrAllocateMessagePointer(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN ULONG Length,
    OUT PVOID *Pointer
    );

void
NTAPI
ZwWow64CsrCaptureMessageBuffer(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN PVOID Buffer OPTIONAL,
    IN ULONG Length,
    OUT PVOID *CapturedBuffer
    );

void
NTAPI
ZwWow64CsrCaptureMessageString(
    IN OUT PCSR_CAPTURE_HEADER CaptureBuffer,
    IN PCSTR String,
    IN ULONG Length,
    IN ULONG MaximumLength,
    OUT PSTRING CapturedString
    );

NTSTATUS
NTAPI
ZwWow64CsrClientConnectToServer(
    IN PWSTR ObjectDirectory,
    IN ULONG ServerDllIndex,
    IN PCSR_CALLBACK_INFO CallbackInformation OPTIONAL,
    IN PVOID ConnectionInformation,
    IN OUT PULONG ConnectionInformationLength OPTIONAL,
    OUT PBOOLEAN CalledFromServer OPTIONAL
    );

void
NTAPI
ZwWow64CsrFreeCaptureBuffer(
    IN PCSR_CAPTURE_HEADER CaptureBuffer
    );

NTSTATUS
NTAPI
ZwWow64CsrIdentifyAlertableThread( 
    void
    );

NTSTATUS
NTAPI
ZwWow64DebuggerCall (
    IN ULONG ServiceClass,
    IN ULONG Arg1,
    IN ULONG Arg2
    );

NTSTATUS
NTAPI
RtlCleanUpTEBLangLists(
		void
		);

VOID
KiUserApcDispatcher (
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	PKNORMAL_ROUTINE NormalRoutine
	);

VOID
KiUserExceptionDispatcher (
	PEXCEPTION_RECORD ExceptionRecord,
	PCONTEXT ContextFrame
	);

NTSTATUS
NTAPI
NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);

NTSTATUS
NTAPI
NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
	);

NTSTATUS
NTAPI
NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus
	);

NTSTATUS
NTAPI
NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
	);

NTSTATUS
NTAPI
NtSetInformationDebugObject(
	IN HANDLE DebugObjectHandle,
	IN DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
	IN PVOID DebugInformation,
	IN ULONG DebugInformationLength,
	OUT OPTIONAL PULONG ReturnLength
	);

NTSTATUS
NTAPI
NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN OPTIONAL PLARGE_INTEGER Timeout,
	OUT PVOID WaitStateChange
	);

// Debugging UI

NTSTATUS
NTAPI
DbgUiConnectToDbg(
	VOID
	);

HANDLE
NTAPI
DbgUiGetThreadDebugObject(
	VOID
	);

VOID
NTAPI
DbgUiSetThreadDebugObject(
	IN HANDLE DebugObject
	);

NTSTATUS
NTAPI
DbgUiWaitStateChange(
	OUT PDBGUI_WAIT_STATE_CHANGE StateChange,
	IN OPTIONAL PLARGE_INTEGER Timeout
	);

NTSTATUS
NTAPI
DbgUiContinue(
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus
	);

NTSTATUS
NTAPI
DbgUiStopDebugging(
	IN HANDLE Process
	);

NTSTATUS
NTAPI
DbgUiDebugActiveProcess(
	IN HANDLE Process
	);

VOID
NTAPI
DbgUiRemoteBreakin(
	IN PVOID Context
	);

NTSTATUS
NTAPI
DbgUiIssueRemoteBreakin(
	IN HANDLE Process
	);

VOID
NTAPI
RtlExitUserProcess(
	IN NTSTATUS ExitStatus
	);

NTSTATUS
NTAPI
RtlQueueWorkItem(
	IN WORKERCALLBACKFUNC CallbackFunction,
	IN OPTIONAL PVOID Context,
	IN ULONG Flags
	);


NTSTATUS
NTAPI
RtlCreateUserStack(
	SIZE_T CommittedStackSize,
	SIZE_T MaximumStackSize,
	SIZE_T ZeroBits,
	ULONG PageSize,
	ULONG ReserveAlignment,
	PINITIAL_TEB InitialTeb
	);


LRESULT
NTAPI
NtdllDefWindowProc_W(
	);


LRESULT
NTAPI
NtdllDefWindowProc_A(
	);


NTSTATUS
NTAPI
LdrQueryProcessModuleInformation(
	PRTL_PROCESS_MODULES ModuleInformation,
	ULONG ModuleInformationLength,
	PULONG ReturnLength
	);

NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    PULONG Seed
	);

NTSYSAPI
BOOL
NTAPI
ImpersonateLoggedOnUser(
 	IN HANDLE hToken
	);

NTSYSAPI
BOOL
NTAPI
DuplicateHandle(
	IN  HANDLE   hSourceProcessHandle,
	IN  HANDLE   hSourceHandle,
	IN  HANDLE   hTargetProcessHandle,
 	OUT LPHANDLE lpTargetHandle,
	IN  DWORD    dwDesiredAccess,
	IN  BOOL     bInheritHandle,
	IN  DWORD    dwOptions
	);

BOOL
WINAPI
AttachConsole(
  IN DWORD dwProcessId
);

HANDLE
WINAPI
GetStdHandle(
  IN DWORD nStdHandle
);

/*
BOOL
WINAPI
WriteConsoleA(
  IN  HANDLE  hConsoleOutput,
  IN  VOID    *lpBuffer,
  IN  DWORD   nNumberOfCharsToWrite,
  OUT LPDWORD lpNumberOfCharsWritten,
  IN  LPVOID  lpReserved
);
*/
typedef struct addrinfo {
  int             ai_flags;
  int             ai_family;
  int             ai_socktype;
  int             ai_protocol;
  size_t          ai_addrlen;
  char            *ai_canonname;
  struct sockaddr *ai_addr;
  struct addrinfo *ai_next;
} ADDRINFOA, *PADDRINFOA;

INT
WSAAPI
getaddrinfo(
	IN OPTIONAL PCSTR           pNodeName,
	IN OPTIONAL PCSTR           pServiceName,
	IN OPTIONAL const ADDRINFOA *pHints,
	OUT         PADDRINFOA      *ppResult
	);

VOID
WSAAPI
freeaddrinfo(
	IN PADDRINFOA pAddrInfo
	);

//
// end non-crt prototypes
//


//
// nt crt
//
//please do not change swprintf stuff otherwise win32 mode is always trashed
#if !defined(_NO_NTDLL_CRT_)

//readded 4 jan 2012
//win64 mode does not need this
//for using this routines ntdllp.lib is required
#if !defined(_M_X64)
IMPORT_FN size_t __cdecl wcslen(const wchar_t *);
IMPORT_FN wchar_t * __cdecl wcscat(wchar_t *dst, const wchar_t *src);
IMPORT_FN int __cdecl wcscmp(const wchar_t *src, const wchar_t *dst);
IMPORT_FN int __cdecl _wcsicmp(const wchar_t *, const wchar_t *);
IMPORT_FN int __cdecl _wcsnicmp(const wchar_t *, const wchar_t *, size_t);
IMPORT_FN wchar_t * __cdecl _wcslwr(wchar_t *);
IMPORT_FN wchar_t * __cdecl _wcsupr(wchar_t *);
IMPORT_FN wchar_t * __cdecl wcschr(const wchar_t *string, wchar_t ch);
IMPORT_FN wchar_t * __cdecl wcscpy(wchar_t *dst, const wchar_t *src);
IMPORT_FN wchar_t * __cdecl wcsncat(wchar_t *front, const wchar_t *back, size_t count);
IMPORT_FN wchar_t * __cdecl wcsncpy(wchar_t *dest, const wchar_t *source, size_t count);
#endif //_M_X64

#endif	// _NO_NTDLL_CRT_

#ifdef __cplusplus
}
#endif


#endif /* _NTDLL_ */
