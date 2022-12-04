#ifndef HAVOC_PYAGENTCLASS_HPP
#define HAVOC_PYAGENTCLASS_HPP

#include <global.hpp>

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

typedef struct
{
    PyObject_HEAD

    PCHAR AgentID;

    u32 CONSOLE_INFO;
    u32 CONSOLE_ERROR;
    u32 CONSOLE_TASK;
} PyAgentClass, *PPyAgentClass;

extern PyTypeObject PyAgentClass_Type;

void      AgentClass_dealloc( PPyAgentClass self );
PyObject* AgentClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int       AgentClass_init( PPyAgentClass self, PyObject *args, PyObject *kwds );
PyObject* AgentClass_ConsoleWrite( PPyAgentClass self, PyObject *args );
PyObject* AgentClass_Command( PPyAgentClass self, PyObject *args );

#endif
