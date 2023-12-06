
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/UI/PyWidgetClass.hpp>


PyMemberDef PyWidgetClass_members[] = {

        { "title",       T_STRING, offsetof( PyWidgetClass, title ),    0, "title" },

        { NULL },
};

PyMethodDef PyWidgetClass_methods[] = {

        { "setBottomTab",               ( PyCFunction ) WidgetClass_setBottomTab,               METH_VARARGS, "Set widget as Bottom Tab" },
        { "setSmallTab",               ( PyCFunction ) WidgetClass_setSmallTab,               METH_VARARGS, "Set widget as Small Tab" },
        { "addLabel",               ( PyCFunction ) WidgetClass_addLabel,               METH_VARARGS, "Insert a label in the widget" },
        { "addImage",               ( PyCFunction ) WidgetClass_addImage,               METH_VARARGS, "Insert an image in the widget" },
        { "addButton",               ( PyCFunction ) WidgetClass_addButton,               METH_VARARGS, "Insert a button in the widget" },
        { "addCheckbox",               ( PyCFunction ) WidgetClass_addCheckbox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addCombobox",               ( PyCFunction ) WidgetClass_addCombobox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addLineedit",               ( PyCFunction ) WidgetClass_addLineedit,               METH_VARARGS, "Insert a Line edit in the window" },
        { "addCalendar",               ( PyCFunction ) WidgetClass_addCalendar,               METH_VARARGS, "Insert a Calendar in the window" },
        { "addDial",               ( PyCFunction ) WidgetClass_addDial,               METH_VARARGS, "Insert a dial in the window" },
        { "addSlider",               ( PyCFunction ) WidgetClass_addSlider,               METH_VARARGS, "Insert a slider in the window" },
        { "replaceLabel",               ( PyCFunction ) WidgetClass_replaceLabel,               METH_VARARGS, "Replace a label with supplied text" },
        { "clear",               ( PyCFunction ) WidgetClass_clear,               METH_VARARGS, "clear a widget" },

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
    if (self) {
        if (self->title)
            Py_XDECREF( self->title );
        if (self->WidgetWindow && self->WidgetWindow->window)
            delete self->WidgetWindow->window;
        if (self->WidgetWindow)
            free(self->WidgetWindow);
        Py_TYPE( self )->tp_free( ( PyObject* ) self );
    }
}

PyObject* WidgetClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyWidgetClass self;

    self = ( PPyWidgetClass ) PyType_Type.tp_alloc( type, 0 );
    if (self == NULL)
        return NULL;
    self->title = NULL;
    self->WidgetWindow = NULL;
    self->WidgetWindow = (PPyWidgetQWindow)malloc(sizeof(PyWidgetQWindow));
    if (self->WidgetWindow == NULL)
        return NULL;
    self->WidgetWindow->window = NULL;
    self->WidgetWindow->layout = NULL;
    self->WidgetWindow->scroll= NULL;
    self->WidgetWindow->root = NULL;
    self->WidgetWindow->root_layout = NULL;
    return ( PyObject* ) self;
}

int WidgetClass_init( PPyWidgetClass self, PyObject *args, PyObject *kwds )
{
    char*       title           = NULL;
    PyObject*   scrollable      = NULL;
    const char* kwdlist[]       = { "title", "scrollable", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "s|O", const_cast<char**>(kwdlist), &title, &scrollable ) )
        return -1;
    AllocMov( self->title, title, strlen(title) );

    self->WidgetWindow->window = new QWidget();
    self->WidgetWindow->window->setWindowTitle(title);

    self->WidgetWindow->root = new QWidget();
    self->WidgetWindow->layout = new QVBoxLayout(self->WidgetWindow->root);

    if (scrollable && PyBool_Check(scrollable) && scrollable == Py_True) {
        self->WidgetWindow->scroll = new QScrollArea(self->WidgetWindow->window);
        self->WidgetWindow->scroll->setWidgetResizable(true);
        self->WidgetWindow->scroll->setWidget(self->WidgetWindow->root);
    }
    self->WidgetWindow->root_layout = new QVBoxLayout(self->WidgetWindow->window);
    if (scrollable && PyBool_Check(scrollable) && scrollable == Py_True)
        self->WidgetWindow->root_layout->addWidget(self->WidgetWindow->scroll);
    else
        self->WidgetWindow->root_layout->addWidget(self->WidgetWindow->root);
    return 0;
}

// Methods
PyObject* WidgetClass_addLabel( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;

    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QLabel* label = new QLabel(text, self->WidgetWindow->window);
    self->WidgetWindow->layout->addWidget(label);

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addImage( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;

    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QPixmap img(text);
    QLabel* label = new QLabel(self->WidgetWindow->window);
    label->setPixmap(img);
    self->WidgetWindow->layout->addWidget(label);

    Py_RETURN_NONE;
}

PyObject* WidgetClass_setBottomTab( PPyWidgetClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewBottomTab( self->WidgetWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* WidgetClass_setSmallTab( PPyWidgetClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewSmallTab( self->WidgetWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addButton( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;
    char *style = nullptr;
    PyObject* button_callback = nullptr;

    if( !PyArg_ParseTuple( args, "sO|s", &text, &button_callback, &style) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(button_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QPushButton* button = new QPushButton(text, self->WidgetWindow->window);
    if (style)
        button->setStyleSheet(style);
    self->WidgetWindow->layout->addWidget(button);
    QObject::connect(button, &QPushButton::clicked, self->WidgetWindow->window, [button_callback]() {
            PyObject_CallFunctionObjArgs(button_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addCheckbox( PPyWidgetClass self, PyObject *args )
{
    char *text = nullptr;
    char *style = nullptr;
    PyObject* checkbox_callback = nullptr;
    PyObject* is_checked = nullptr;

    if( !PyArg_ParseTuple( args, "sO|Os", &text, &checkbox_callback, &is_checked, &style) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(checkbox_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QCheckBox* checkbox = new QCheckBox(text, self->WidgetWindow->window);
    if (style)
        checkbox->setStyleSheet(style);
    if (is_checked && PyBool_Check(is_checked) && is_checked == Py_True)
        checkbox->setChecked(true);
    self->WidgetWindow->layout->addWidget(checkbox);
    QObject::connect(checkbox, &QCheckBox::clicked, self->WidgetWindow->window, [checkbox_callback]() {
            PyObject_CallFunctionObjArgs(checkbox_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addCombobox( PPyWidgetClass self, PyObject *args )
{
    Py_ssize_t tuple_size = PyTuple_Size(args);
    QComboBox* comboBox = new QComboBox(self->WidgetWindow->window);

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
    self->WidgetWindow->layout->addWidget(comboBox);
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
    QLineEdit* line = new QLineEdit(self->WidgetWindow->window);
    line->setPlaceholderText(text);
    self->WidgetWindow->layout->addWidget(line);
    QObject::connect(line, &QLineEdit::editingFinished, self->WidgetWindow->window, [line, line_callback]() {
            QString text = line->text();
            QByteArray byteArray = text.toUtf8();
            char *charArray = byteArray.data();
            PyObject* pyString = PyUnicode_DecodeFSDefault(charArray);
            PyObject_CallFunctionObjArgs(line_callback, pyString, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addCalendar( PPyWidgetClass self, PyObject *args )
{
    PyObject* cal_callback = nullptr;

    if( !PyArg_ParseTuple( args, "O", &cal_callback) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(cal_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }

    QCalendarWidget* cal = new QCalendarWidget(self->WidgetWindow->window);
    self->WidgetWindow->layout->addWidget(cal);

    QObject::connect(cal, &QCalendarWidget::selectionChanged, self->WidgetWindow->window, [cal, cal_callback]() {
            QDate selectedDate = cal->selectedDate();
            QString text = selectedDate.toString("yyyy-MM-dd");
            QByteArray byteArray = text.toUtf8();
            char *charArray = byteArray.data();
            PyObject* pyString = PyUnicode_DecodeFSDefault(charArray);
            PyObject_CallFunctionObjArgs(cal_callback, pyString, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* WidgetClass_addDial( PPyWidgetClass self, PyObject *args )
{
    PyObject* cal_callback = nullptr;

    if( !PyArg_ParseTuple( args, "O", &cal_callback) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(cal_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }

    QDial* dial = new QDial(self->WidgetWindow->window);
    self->WidgetWindow->layout->addWidget(dial);
    QObject::connect(dial, &QDial::valueChanged, self->WidgetWindow->window, [cal_callback](long value) {
            PyObject* pyLong = PyLong_FromLong(value);
            PyObject_CallFunctionObjArgs(cal_callback, pyLong, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* WidgetClass_addSlider( PPyWidgetClass self, PyObject *args )
{
    PyObject* cal_callback = nullptr;
    PyObject* vertical = nullptr;

    if( !PyArg_ParseTuple( args, "O|O", &cal_callback, &vertical) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(cal_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }

    QSlider* slider = nullptr;
    if (vertical && PyBool_Check(vertical) && vertical == Py_True) {
        slider = new QSlider(Qt::Vertical);
    } else {
        slider = new QSlider(Qt::Horizontal);
    }
    self->WidgetWindow->layout->addWidget(slider);
    QObject::connect(slider, &QSlider::valueChanged, self->WidgetWindow->window, [cal_callback](long value) {
            PyObject* pyLong = PyLong_FromLong(value);
            PyObject_CallFunctionObjArgs(cal_callback, pyLong, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* WidgetClass_replaceLabel( PPyWidgetClass self, PyObject *args )
{
    char* to_find = NULL;
    char* to_replace= NULL;
    QVBoxLayout *layout = self->WidgetWindow->layout;

    if( !PyArg_ParseTuple( args, "ss", &to_find, &to_replace) )
    {
        Py_RETURN_NONE;
    }
    QString targetText = QString(to_find);
    for (int i = 0; i < layout->count(); ++i) {
        QLayoutItem* item = layout->itemAt(i);
        if (item->widget() && item->widget()->inherits("QLabel")) {
            QLabel* label = qobject_cast<QLabel*>(item->widget());
            if (label && label->text() == targetText) {
                label->setText(to_replace);
                break;
            }
        }
    }
    Py_RETURN_NONE;
}

PyObject* WidgetClass_clear( PPyWidgetClass self, PyObject *args )
{
    QVBoxLayout *layout = self->WidgetWindow->layout;
    QLayoutItem* item;

    while ((item = layout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    Py_RETURN_NONE;
}
