#ifndef DEMON_STRINGS_H
#define DEMON_STRINGS_H

#define PROCESS_ARCH_UNKNOWN				0
#define PROCESS_ARCH_X86					1
#define PROCESS_ARCH_X64					2
#define PROCESS_ARCH_IA64					3

#ifdef _WIN64
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X64
#else
#define PROCESS_AGENT_ARCH PROCESS_ARCH_X86
#endif

// Hashes for the dynamic winapi loading via a hashing algorithm
#define FuncHash_GetTokenInformation        881854923972837164
#define FuncHash_CreatePipe                 8244700854143020775
#define FuncHash_ReadFile                   7571513842702625
#define FuncHash_RevertToSelf               14100625964972061354
#define FuncHash_Sleep                      210689975806
#define FuncHash_TerminateProcess           3268205303374481261
#define FuncHash_GetUserNameA               13544547492196232006
#define FuncHash_ExitProcess                13824059171100242846
#define FuncHash_RtlGetVersion              4893460183577242141
#define FuncHash_RtlCreateUserThread        1016696724611196162
#define FuncHash_ResumeThread               14100509000585325166
#define FuncHash_OpenThread                 8245254994680133519
#define FuncHash_Thread32Next               14206118522476693985
#define FuncHash_Thread32First              7633309398982761034
#define FuncHash_VirtualProtectEx           5341311935265804842
#define FuncHash_LookupAccountSidA          3739427023317208365
#define FuncHash_InitializeProcThreadAttributeList 6595998938373999155
#define FuncHash_UpdateProcThreadAttribute  6332977549253614184

// Beacon API
#define COFFAPI_BEACONDATAPARSER                0xe2494ba2
#define COFFAPI_BEACONDATAINT                   0xaf1afdd2
#define COFFAPI_BEACONDATASHORT                 0xe2835ef7
#define COFFAPI_BEACONDATALENGTH                0x22641d29
#define COFFAPI_BEACONDATAEXTRACT               0x80d46722

#define COFFAPI_BEACONFORMATALLOC               0x4caae0e1
#define COFFAPI_BEACONFORMATRESET               0x4ddac759
#define COFFAPI_BEACONFORMATFREE                0x7e749f38
#define COFFAPI_BEACONFORMATAPPEND              0xe25167ce
#define COFFAPI_BEACONFORMATPRINTF              0x56f4aa9
#define COFFAPI_BEACONFORMATTOSTRING            0xb59f4df0
#define COFFAPI_BEACONFORMATINT                 0x3a229cc1

#define COFFAPI_BEACONPRINTF                    0x700d8660
#define COFFAPI_BEACONOUTPUT                    0x6df4b81e
#define COFFAPI_BEACONUSETOKEN                  0x889e48bb
#define COFFAPI_BEACONREVERTTOKEN               0xf2744ba6
#define COFFAPI_BEACONISADMIN                   0x566264d2
#define COFFAPI_BEACONGETSPAWNTO                0x1e7c9fb9
#define COFFAPI_BEACONSPAWNTEMPORARYPROCESS     0xd6c57438
#define COFFAPI_BEACONINJECTPROCESS             0xea75b09
#define COFFAPI_BEACONINJECTTEMPORARYPROCESS    0x9e22498c
#define COFFAPI_BEACONCLEANUPPROCESS            0xcee62b74

#define COFFAPI_TOWIDECHAR                      0x59fcf3cf
#define COFFAPI_LOADLIBRARYA                    0x5fbff0fb
#define COFFAPI_GETPROCADDRESS                  0xcf31bb1f
#define COFFAPI_GETMODULEHANDLE                 0x5a153f58
#define COFFAPI_FREELIBRARY                     0x30eece3c

#define HASH_KERNEL32                           0xadd31df0
#define HASH_NTDLL                              0x70e61753

#endif
