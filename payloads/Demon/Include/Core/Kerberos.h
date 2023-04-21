
#ifndef DEMON_KERBEROS_H
#define DEMON_KERBEROS_H

//#include <ntsecapi.h>

#define KERBEROS_COMMAND_LUID  0x0
#define KERBEROS_COMMAND_KLIST 0x1
#define KERBEROS_COMMAND_PURGE 0x2
#define KERBEROS_COMMAND_PTT   0x3

#define _KerbSubmitTicketMessage 21

#define KERB_USE_DEFAULT_TICKET_FLAGS 0x0

#define KERB_RETRIEVE_TICKET_DEFAULT 0x0
#define KERB_RETRIEVE_TICKET_DONT_USE_CACHE 0x1
#define KERB_RETRIEVE_TICKET_USE_CACHE_ONLY 0x2
#define KERB_RETRIEVE_TICKET_USE_CREDHANDLE 0x4
#define KERB_RETRIEVE_TICKET_AS_KERB_CRED 0x8
#define KERB_RETRIEVE_TICKET_WITH_SEC_CRED 0x10
#define KERB_RETRIEVE_TICKET_CACHE_TICKET 0x20

#define FIELD_LENGTH 512

typedef struct _TICKET_INFORMATION {
  WCHAR         ClientName[FIELD_LENGTH];
  WCHAR         ClientRealm[FIELD_LENGTH];
  WCHAR         ServerName[FIELD_LENGTH];
  WCHAR         ServerRealm[FIELD_LENGTH];
  LARGE_INTEGER StartTime;
  LARGE_INTEGER EndTime;
  LARGE_INTEGER RenewTime;
  LONG          EncryptionType;
  ULONG         TicketFlags;
  BUFFER        Ticket;
  struct _TICKET_INFORMATION* Next;
} TICKET_INFORMATION,*PTICKET_INFORMATION;

typedef struct _SESSION_INFORMATION {
  WCHAR               UserName[FIELD_LENGTH];
  WCHAR               Domain[FIELD_LENGTH];
  LUID                LogonId;
  ULONG               Session;
  WCHAR               UserSID[FIELD_LENGTH];
  LARGE_INTEGER       LogonTime;
  ULONG               LogonType;
  WCHAR               AuthenticationPackage[FIELD_LENGTH];
  WCHAR               LogonServer[FIELD_LENGTH];
  WCHAR               LogonServerDNSDomain[FIELD_LENGTH];
  WCHAR               Upn[FIELD_LENGTH];
  PTICKET_INFORMATION Tickets;
  struct _SESSION_INFORMATION* Next;
} SESSION_INFORMATION,*PSESSION_INFORMATION;

typedef enum _KERB_PROTOCOL_MESSAGE_TYPE {
  KerbDebugRequestMessage = 0,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
  KerbAddExtraCredentialsMessage = 17,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
  KerbRefreshSmartcardCredentialsMessage,
  //KerbAddExtraCredentialsMessage = 17,
  KerbQuerySupplementalCredentialsMessage,
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message,
  KerbSubmitTicketMessage,
  KerbAddExtraCredentialsExMessage,
  KerbQueryKdcProxyCacheMessage,
  KerbPurgeKdcProxyCacheMessage,
  KerbQueryTicketCacheEx3Message,
  KerbCleanupMachinePkinitCredsMessage,
  KerbAddBindingCacheEntryExMessage,
  KerbQueryBindingCacheMessage,
  KerbPurgeBindingCacheMessage,
  KerbPinKdcMessage,
  KerbUnpinAllKdcsMessage,
  KerbQueryDomainExtendedPoliciesMessage,
  KerbQueryS4U2ProxyCacheMessage,
  KerbRetrieveKeyTabMessage,
  KerbRefreshPolicyMessage,
  KerbPrintCloudKerberosDebugMessage
} KERB_PROTOCOL_MESSAGE_TYPE, *PKERB_PROTOCOL_MESSAGE_TYPE;

typedef struct KERB_CRYPTO_KEY {
    LONG KeyType;
    ULONG Length;
    PUCHAR Value;
} KERB_CRYPTO_KEY, *PKERB_CRYPTO_KEY;

typedef struct KERB_CRYPTO_KEY32 {
    LONG KeyType;
    ULONG Length;
    ULONG Offset;
} KERB_CRYPTO_KEY32, *PKERB_CRYPTO_KEY32;

typedef struct _KERB_SUBMIT_TKT_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    ULONG Flags;
    KERB_CRYPTO_KEY32 Key;
    ULONG KerbCredSize;
    ULONG KerbCredOffset;
} KERB_SUBMIT_TKT_REQUEST, *PKERB_SUBMIT_TKT_REQUEST;

typedef struct _KERB_PURGE_TKT_CACHE_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID                       LogonId;
  UNICODE_STRING             ServerName;
  UNICODE_STRING             RealmName;
} KERB_PURGE_TKT_CACHE_REQUEST, *PKERB_PURGE_TKT_CACHE_REQUEST;

typedef struct _KERB_TICKET_CACHE_INFO_EX {
  UNICODE_STRING ClientName;
  UNICODE_STRING ClientRealm;
  UNICODE_STRING ServerName;
  UNICODE_STRING ServerRealm;
  LARGE_INTEGER StartTime;
  LARGE_INTEGER EndTime;
  LARGE_INTEGER RenewTime;
  LONG EncryptionType;
  ULONG TicketFlags;
} KERB_TICKET_CACHE_INFO_EX,*PKERB_TICKET_CACHE_INFO_EX;

typedef struct _KERB_QUERY_TKT_CACHE_EX_RESPONSE {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  ULONG CountOfTickets;
  KERB_TICKET_CACHE_INFO_EX Tickets[ANYSIZE_ARRAY];
} KERB_QUERY_TKT_CACHE_EX_RESPONSE,*PKERB_QUERY_TKT_CACHE_EX_RESPONSE;

#ifndef __SECHANDLE_DEFINED__
  typedef struct _SecHandle {
    ULONG_PTR dwLower;
    ULONG_PTR dwUpper;
  } SecHandle,*PSecHandle;

#define __SECHANDLE_DEFINED__
#endif

typedef struct _KERB_RETRIEVE_TKT_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID LogonId;
  UNICODE_STRING TargetName;
  ULONG TicketFlags;
  ULONG CacheOptions;
  LONG EncryptionType;
  SecHandle CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST,*PKERB_RETRIEVE_TKT_REQUEST;

typedef struct _KERB_EXTERNAL_NAME {
  SHORT NameType;
  USHORT NameCount;
  UNICODE_STRING Names[ANYSIZE_ARRAY];
} KERB_EXTERNAL_NAME,*PKERB_EXTERNAL_NAME;

typedef struct _KERB_EXTERNAL_TICKET {
  PKERB_EXTERNAL_NAME ServiceName;
  PKERB_EXTERNAL_NAME TargetName;
  PKERB_EXTERNAL_NAME ClientName;
  UNICODE_STRING DomainName;
  UNICODE_STRING TargetDomainName;
  UNICODE_STRING AltTargetDomainName;
  KERB_CRYPTO_KEY SessionKey;
  ULONG TicketFlags;
  ULONG Flags;
  LARGE_INTEGER KeyExpirationTime;
  LARGE_INTEGER StartTime;
  LARGE_INTEGER EndTime;
  LARGE_INTEGER RenewUntil;
  LARGE_INTEGER TimeSkew;
  ULONG EncodedTicketSize;
  PUCHAR EncodedTicket;
} KERB_EXTERNAL_TICKET,*PKERB_EXTERNAL_TICKET;

typedef struct _KERB_RETRIEVE_TKT_RESPONSE {
  KERB_EXTERNAL_TICKET Ticket;
} KERB_RETRIEVE_TKT_RESPONSE,*PKERB_RETRIEVE_TKT_RESPONSE;

typedef struct _KERB_QUERY_TKT_CACHE_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID                       LogonId;
} KERB_QUERY_TKT_CACHE_REQUEST, *PKERB_QUERY_TKT_CACHE_REQUEST;

typedef struct _LOGON_SESSION_DATA {
    PSECURITY_LOGON_SESSION_DATA* sessionData;
    ULONG sessionCount;
} LOGON_SESSION_DATA, *PLOGON_SESSION_DATA;

BOOL                 Ptt( HANDLE hToken, PBYTE Ticket, DWORD TicketSize, LUID luid );
BOOL                 Purge( HANDLE hToken, LUID luid );
PSESSION_INFORMATION Klist( HANDLE hToken, LUID luid );
LUID*                GetLUID( HANDLE hToken );
#endif
