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
PyObject*   DemonClass_ProcessCreate( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DllInject( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DllSpawn( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_InlineExecute( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_InlineExecuteGetOutput( PPyDemonClass self, PyObject *args );
PyObject*   DemonClass_DotnetInlineExecute( PPyDemonClass self, PyObject *args );

// Utils
PyObject*   DemonClass_ConsoleWrite( PPyDemonClass self, PyObject *args );

#endif