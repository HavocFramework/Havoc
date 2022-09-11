
#ifndef DEMON_ENVIROMENTBLOCK_H
#define DEMON_ENVIROMENTBLOCK_H

#include <winternl.h>

typedef PVOID PACTIVATION_CONTEXT;

// NT types
typedef struct _MIMI_CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENTID;

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK * pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct DEMON__TEB
{
    NT_TIB				NtTib;
    PVOID				EnvironmentPointer;
    CLIENT_ID			ClientId;
    PVOID				ActiveRpcHandle;
    PVOID				ThreadLocalStoragePointer;
    _PPEB	            ProcessEnvironmentBlock;
    ULONG               LastErrorValue;
    ULONG               CountOfOwnedCriticalSections;
    PVOID				CsrClientThread;
    PVOID				Win32ThreadInfo;
    ULONG               User32Reserved[26];
    ULONG               UserReserved[5];
    PVOID				WOW32Reserved;
    LCID                CurrentLocale;
    ULONG               FpSoftwareStatusRegister;
    PVOID				SystemReserved1[54];
    LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
    ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
    GDI_TEB_BATCH			GdiTebBatch;
    CLIENT_ID				RealClientId;
    PVOID					GdiCachedProcessHandle;
    ULONG                   GdiClientPID;
    ULONG                   GdiClientTID;
    PVOID					GdiThreadLocalInfo;
    PSIZE_T					Win32ClientInfo[62];
    PVOID					glDispatchTable[233];
    PSIZE_T					glReserved1[29];
    PVOID					glReserved2;
    PVOID					glSectionInfo;
    PVOID					glSection;
    PVOID					glTable;
    PVOID					glCurrentRC;
    PVOID					glContext;
    NTSTATUS                LastStatusValue;
    UNICODE_STRING			StaticUnicodeString;
    WCHAR                   StaticUnicodeBuffer[261];
    PVOID					DeallocationStack;
    PVOID					TlsSlots[64];
    LIST_ENTRY				TlsLinks;
    PVOID					Vdm;
    PVOID					ReservedForNtRpc;
    PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                   HardErrorMode;
#else
    ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
    GUID                    ActivityId;
    PVOID					SubProcessTag;
    PVOID					EtwLocalData;
    PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
    PVOID					WinSockData;
    ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    BOOLEAN                SpareBool0;
    BOOLEAN                SpareBool1;
    BOOLEAN                SpareBool2;
#else
    BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
    UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
    ULONG                  GuaranteedStackBytes;
#else
    ULONG                  Spare3;
#endif
    PVOID				   ReservedForPerf;
    PVOID				   ReservedForOle;
    ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID				   SavedPriorityState;
    ULONG_PTR			   SoftPatchPtr1;
    ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
    ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
    PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
    PVOID                  DeallocationBStore;
    PVOID                  BStoreLimit;
#endif
    ULONG                  ImpersonationLocale;
    ULONG                  IsImpersonating;
    PVOID                  NlsCache;
    PVOID                  pShimData;
    ULONG                  HeapVirtualAffinity;
    HANDLE                 CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
    PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PVOID PreferredLangauges;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        struct
        {
            USHORT SpareCrossTebFlags : 16;
        };
        USHORT CrossTebFlags;
    };
    union
    {
        struct
        {
            USHORT DbgSafeThunkCall : 1;
            USHORT DbgInDebugPrint : 1;
            USHORT DbgHasFiberData : 1;
            USHORT DbgSkipThreadAttach : 1;
            USHORT DbgWerInShipAssertCode : 1;
            USHORT DbgIssuedInitialBp : 1;
            USHORT DbgClonedThread : 1;
            USHORT SpareSameTebBits : 9;
        };
        USHORT SameTebFlags;
    };
    PVOID TxnScopeEntercallback;
    PVOID TxnScopeExitCAllback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG ProcessRundown;
    ULONG64 LastSwitchTime;
    ULONG64 TotalSwitchOutTime;
    LARGE_INTEGER WaitReasonBitMap;
#else
    BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} _TEB, * _PTEB;

#ifdef _WIN64
#define NtCurrentTEB() \
    ( ( _PTEB ) __readgsqword( 0x30 ) )
#elif _WIN32
#define NtCurrentTEB() \
    ( ( _PTEB ) __readgsqword( 0x18 ) )

#endif


#endif //DEMON_ENVIROMENTBLOCK_H
