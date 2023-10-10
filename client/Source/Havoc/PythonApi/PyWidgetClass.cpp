
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/PyWidgetClass.hpp>

PPyWidgetQWindow DialogWindow = NULL;

PyMemberDef PyWidgetClass_members[] = {

        { "title",       T_STRING, offsetof( PyWidgetClass, title ),    0, "title" },

        { NULL },
};

PyMethodDef PyWidgetClass_methods[] = {

        { "exec",                   ( PyCFunction ) WidgetClass_exec,                   METH_VARARGS, "Display the window" },
        { "close",           ( PyCFunction ) WidgetClass_close,           METH_VARARGS, "Close the window" },
        { "addLabel",               ( PyCFunction ) WidgetClass_addLabel,               METH_VARARGS, "Insert a label in the window" },
        { "addButton",               ( PyCFunction ) WidgetClass_addButton,               METH_VARARGS, "Insert a button in the window" },
        { "addCheckbox",               ( PyCFunction ) WidgetClass_addCheckbox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addCombobox",               ( PyCFunction ) WidgetClass_addCombobox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addLineedit",               ( PyCFunction ) WidgetClass_addLineedit,               METH_VARARGS, "Insert a Line edit in the window" },
        { "ConsoleWrite",           ( PyCFunction ) WidgetClass_ConsoleWrite,           METH_VARARGS, "Print message console" },

        { NULL },
};

PyTypeObject PyWidgetClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havocui.widget",                              /* tp_name */
        sizeof( PyWidgetClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) WidgetClass_dealloc,          /* tp_dealloc */
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
        "Widget Havoc Object",                      /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyWidgetClass_methods,                       /* tp_methods */
        PyWidgetClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) WidgetClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        WidgetClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void WidgetClass_dealloc( PPyWidgetClass self )
{
    Py_XDECREF( self->title );
    delete DialogWindow->window;
    free(DialogWindow);

    Py_TYPE( self )->tp_free( ( PyObject* ) self );
}

PyObject* WidgetClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyWidgetClass self;

    self = ( PPyWidgetClass ) PyType_Type.tp_alloc( type, 0 );

    return ( PyObject* ) self;
}

int WidgetClass_init( PPyWidgetClass self, PyObject *args, PyObject *kwds )
{
    if ( PyType_Type.tp_init( ( PyObject* ) self, args, kwds ) < 0 )
        return -1;

    char*       title          = NULL;
    const char* kwdlist[]        = { "title", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "s", const_cast<char**>(kwdlist), &title ) )
        return -1;
    AllocMov( self->title, title, strlen(title) );
    DialogWindow = (PPyWidgetQWindow)malloc(sizeof(PyWidgetQWindow));
    if (DialogWindow == NULL)
        return -1;
    DialogWindow->window = new QDialog(HavocX::HavocUserInterface->HavocWindow);
    DialogWindow->window->setWindowTitle(title);
    DialogWindow->layout = new QVBoxLayout(DialogWindow->window);

    return 0;
}

// Methods
PyObject* WidgetClass_exec( PPyWidgetClass self, PyObject *args )
{
    DialogWindow->window->exec();

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addLabel( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;

    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QLabel* label = new QLabel(text, DialogWindow->window);
    DialogWindow->layout->addWidget(label);

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addButton( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;
    PyObject* button_callback = nullptr;

    if( !PyArg_ParseTuple( args, "sO", &text, &button_callback) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(button_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QPushButton* button = new QPushButton(text, DialogWindow->window);
    DialogWindow->layout->addWidget(button);
    QObject::connect(button, &QPushButton::clicked, DialogWindow->window, [button_callback]() {
            PyObject_CallFunctionObjArgs(button_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addCheckbox( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;
    PyObject* checkbox_callback = nullptr;

    if( !PyArg_ParseTuple( args, "sO", &text, &checkbox_callback) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(checkbox_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QCheckBox* checkbox = new QCheckBox(text, DialogWindow->window);
    DialogWindow->layout->addWidget(checkbox);
    QObject::connect(checkbox, &QCheckBox::clicked, DialogWindow->window, [checkbox_callback]() {
            PyObject_CallFunctionObjArgs(checkbox_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addCombobox( PPyWidgetClass self, PyObject *args )
{
    Py_ssize_t tuple_size = PyTuple_Size(args);
    QComboBox* comboBox = new QComboBox(DialogWindow->window);

    PyObject* callable_obj = PyTuple_GetItem(args, 0);
    if ( !PyCallable_Check(callable_obj) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    for (Py_ssize_t i = 1; i < tuple_size; i++) {
        const char * string_obj = PyUnicode_AsUTF8(PyTuple_GetItem(args, i));

        comboBox->addItem(string_obj);
    }
    DialogWindow->layout->addWidget(comboBox);
    QObject::connect(comboBox, QOverload<int>::of(&QComboBox::activated), [callable_obj](int index) {
        PyObject* pArg = PyLong_FromLong(index);
        PyObject_CallFunctionObjArgs(callable_obj, pArg, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* WidgetClass_addLineedit( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;
    PyObject* line_callback = nullptr;

    if( !PyArg_ParseTuple( args, "sO", &text, &line_callback) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(line_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QLineEdit* line = new QLineEdit(DialogWindow->window);
    line->setPlaceholderText(text);
    DialogWindow->layout->addWidget(line);
    QObject::connect(line, &QLineEdit::editingFinished, DialogWindow->window, [line, line_callback]() {
            QString text = line->text();
            QByteArray byteArray = text.toUtf8();
            char *charArray = byteArray.data();
            PyObject* pyString = PyUnicode_DecodeFSDefault(charArray);
            PyObject_CallFunctionObjArgs(line_callback, pyString, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_close( PPyWidgetClass self, PyObject *args )
{
    DialogWindow->window->accept();

    Py_RETURN_NONE;
}

PyObject* WidgetClass_ConsoleWrite( PPyWidgetClass self, PyObject *args )
{
    printf("%s\n", self->title);

    Py_RETURN_NONE;
}
