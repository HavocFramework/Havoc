#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/Event.h>

// TODO: finish this.

PyMemberDef PyEventClass_members[] = {
        // { "SessionFuncList", T_OBJECT, offsetof( PyEvents, SessionFuncList ), 0, "Session function list" },

        { NULL },
};

PyMethodDef PyEventClass_methods[] = {
        { "OnNewSession",   ( PyCFunction ) EventClass_OnNewSession, METH_VARARGS | METH_STATIC, "Event on new session" },

        { NULL },
};

PyTypeObject PyEventClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havoc.Event",                              /* tp_name */
        sizeof( PyEvents ),                         /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) EventClass_dealloc,          /* tp_dealloc */
        0,                                          /* tp_print */
        0,                                          /* tp_getattr */
        0,                                          /* tp_setattr */
        0,                                          /* tp_reserved */
        0,                                          /* tp_repr */
        0,                                          /* tp_as_number */
        0,                                          /* tp_as_sequence */
        0,                                          /* tp_as_mapping */
        0,                                          /* tp_hash */
        0,                                          /* tp_call */
        0,                                          /* tp_str */
        0,                                          /* tp_getattro */
        0,                                          /* tp_setattro */
        0,                                          /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,   /* tp_flags */
        "Havoc Event Object",                       /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyEventClass_methods,                       /* tp_methods */
        PyEventClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) EventClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        EventClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void EventClass_dealloc( PPyEvents self )
{
    Py_TYPE( self )->tp_free( ( PyObject* ) self );
}

PyObject* EventClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyEvents self = nullptr;

    self = ( PPyEvents ) PyType_Type.tp_alloc( type, 0 );

    return ( PyObject* ) self;
}

int EventClass_init( PPyEvents self, PyObject *args, PyObject *kwds )
{
    if ( PyType_Type.tp_init( ( PyObject* ) self, args, kwds ) < 0 )
        return -1;

    return 0;
}

// Methods

PyObject* EventClass_OnNewSession( PPyEvents self, PyObject *args )
{
    PyObject* Function = NULL;

    if ( ! PyArg_ParseTuple( args, "O", &Function ) )
        return NULL;

    // TODO: add Event list to current Teamserver Instance

    Py_RETURN_NONE;
}

PyObject* EventClass_OnDemonOutput( PPyEvents self, PyObject *args )
{

}