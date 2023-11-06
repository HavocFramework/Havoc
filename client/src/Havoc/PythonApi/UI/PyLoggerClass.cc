
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/UI/PyLoggerClass.hpp>


PyMemberDef PyLoggerClass_members[] = {

        { "title",       T_STRING, offsetof( PyLoggerClass, title ),    0, "title" },

        { NULL },
};

PyMethodDef PyLoggerClass_methods[] = {

        { "setBottomTab",               ( PyCFunction ) LoggerClass_setBottomTab,               METH_VARARGS, "Set widget as Bottom Tab" },
        { "setSmallTab",               ( PyCFunction ) LoggerClass_setSmallTab,               METH_VARARGS, "Set widget as Small Tab" },
        { "addText",               ( PyCFunction ) LoggerClass_addText,               METH_VARARGS, "add text to the logger widget" },
        { "clear",               ( PyCFunction ) LoggerClass_clear,               METH_VARARGS, "clears the logger" },

        { NULL },
};

PyTypeObject PyLoggerClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havocui.logger",                              /* tp_name */
        sizeof( PyLoggerClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) LoggerClass_dealloc,          /* tp_dealloc */
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
        "Logger Widget Havoc Object",                      /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyLoggerClass_methods,                       /* tp_methods */
        PyLoggerClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) LoggerClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        LoggerClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void LoggerClass_dealloc( PPyLoggerClass self )
{
    Py_XDECREF( self->title );
    delete self->LoggerWindow->window;
    free(self->LoggerWindow);

    Py_TYPE( self )->tp_free( ( PyObject* ) self );
}

PyObject* LoggerClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyLoggerClass self;

    self = ( PPyLoggerClass ) PyType_Type.tp_alloc( type, 0 );

    return ( PyObject* ) self;
}

int LoggerClass_init( PPyLoggerClass self, PyObject *args, PyObject *kwds )
{
    if ( PyType_Type.tp_init( ( PyObject* ) self, args, kwds ) < 0 )
        return -1;

    char*       title          = NULL;
    const char* kwdlist[]        = { "title", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "s", const_cast<char**>(kwdlist), &title ) )
        return -1;
    AllocMov( self->title, title, strlen(title) );
    self->LoggerWindow = (PPyLoggerQWindow)malloc(sizeof(PyLoggerQWindow));
    if (self->LoggerWindow == NULL)
        return -1;
    self->LoggerWindow->window = new QWidget();
    self->LoggerWindow->window->setWindowTitle(title);
    self->LoggerWindow->layout = new QGridLayout(self->LoggerWindow->window);
    self->LoggerWindow->layout->setContentsMargins(4, 4, 4, 4);

    self->LoggerWindow->LogSection = new QTextEdit(self->LoggerWindow->window);
    self->LoggerWindow->LogSection->setReadOnly(true);
    self->LoggerWindow->layout->addWidget(self->LoggerWindow->LogSection, 0, 0, 1, 1);

    return 0;
}

// Methods

PyObject* LoggerClass_setBottomTab( PPyLoggerClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewBottomTab( self->LoggerWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* LoggerClass_setSmallTab( PPyLoggerClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewSmallTab( self->LoggerWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* LoggerClass_addText( PPyLoggerClass self, PyObject *args )
{
    char* text = NULL;
    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QString Qtext = QString(text);
    self->LoggerWindow->LogSection->append(Qtext);
    Py_RETURN_NONE;
}

PyObject* LoggerClass_clear( PPyLoggerClass self, PyObject *args )
{
    self->LoggerWindow->LogSection->clear();
    Py_RETURN_NONE;
}
