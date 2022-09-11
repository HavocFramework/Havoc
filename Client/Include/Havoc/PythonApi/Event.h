#ifndef HAVOC_EVENT_H
#define HAVOC_EVENT_H

#include <global.hpp>

typedef struct
{
    PyObject_HEAD

    PVOID SessionFuncList;

} PyEvents, *PPyEvents;

extern PyTypeObject PyEventClass_Type;

void        EventClass_dealloc( PPyEvents self );
PyObject*   EventClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         EventClass_init( PPyEvents self, PyObject *args, PyObject *kwds );

// Methods

PyObject*   EventClass_OnNewSession( PPyEvents self, PyObject *args );
PyObject*   EventClass_OnDemonOutput( PPyEvents self, PyObject *args );

#endif
