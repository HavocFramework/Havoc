#ifndef HAVOC_PYDEMONCLASS_H
#define HAVOC_PYDEMONCLASS_H

#include <global.hpp>

typedef struct
{
    PyObject_HEAD

    // Demon Info
    char* Listener;

    char* DemonID;
    char* ExternalIP;
    char* InternalIP;
    char* User;
    char* Computer;
    char* Domain;
    char* OS;
    char* OSBuild;
    char* OSArch;
    char* ProcessName;
    char* ProcessID;
    char* ProcessArch;

    // Other Members

    u32 CONSOLE_INFO;
    u32 CONSOLE_ERROR;
    u32 CONSOLE_TASK;

} PyDemonClass, *PPyDemonClass;

extern PyTypeObject PyDemonClass_Type;

void        DemonClass_dealloc( PPyDemonClass self );
PyObject*   DemonClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         DemonClass_init( PPyDemonClass self, PyObject *args, PyObject *kwds );

// Methods

// PyObject* DemonClass_( PPyDemonClass self, PyObject *args );

// Command
PyObject*   DemonClass_ProcList( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcKill( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcGetPid( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcPpid( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcBlockDll( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcCreate( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcModules( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcGrep( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ProcMemory( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_Dir( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Download( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Upload( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Spawn( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Run( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Shell( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_Powershell( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_ShellcodeInject( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ShellcodeInjectApc( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ShellcodeInjectSys( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ShellcodeSpawn( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ShellcodeSpawnApc( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_ShellcodeSpawnSys( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_DllInject( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DllSpawn( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_Execute( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_TokenGetuid( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenList( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenSteal( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenImpersonate( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenMake( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenRevert( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenRemove( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenClear( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenGetPrivs( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_TokenListPrivs( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_InlineExecute( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_DotnetInlineExecute( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DotnetListVersions( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DotnetExecute( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DotnetInject( PPyDemonClass self, PyObject *args );

PyObject*   DemonClass_Exit( PPyDemonClass self, PyObject *args );

// Utils
PyObject*   DemonClass_ConsoleWrite( PPyDemonClass self, PyObject *args );

#endif