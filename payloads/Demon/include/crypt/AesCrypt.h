#ifndef _AES_H_
#define _AES_H_

#include <windows.h>

#define CTR 1
#define AES256 1

#ifndef CTR
#define CTR 1
#endif

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define AES_KEYLEN 32
#define AES_keyExpSize 240

typedef struct {
    UINT8 RoundKey[AES_keyExpSize];
    UINT8 Iv[AES_BLOCKLEN];
} AESCTX, *PAESCTX ;

void AesInit( PAESCTX ctx, const PUINT8 key, const PUINT8 iv);
void AesXCryptBuffer( PAESCTX ctx, PUINT8 buf, SIZE_T length);

#endif // _AES_H_