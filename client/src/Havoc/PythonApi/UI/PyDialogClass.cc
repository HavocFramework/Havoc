
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/UI/PyDialogClass.hpp>


PyMemberDef PyDialogClass_members[] = {

        { "title",       T_STRING, offsetof( PyDialogClass, title ),    0, "title" },

        { NULL },
};

PyMethodDef PyDialogClass_methods[] = {

        { "exec",                   ( PyCFunction ) DialogClass_exec,                   METH_VARARGS, "Display the window" },
        { "close",           ( PyCFunction ) DialogClass_close,           METH_VARARGS, "Close the window" },
        { "addLabel",               ( PyCFunction ) DialogClass_addLabel,               METH_VARARGS, "Insert a label in the window" },
        { "addImage",               ( PyCFunction ) DialogClass_addImage,               METH_VARARGS, "Insert an image in the window" },
        { "addButton",               ( PyCFunction ) DialogClass_addButton,               METH_VARARGS, "Insert a button in the window" },
        { "addCheckbox",               ( PyCFunction ) DialogClass_addCheckbox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addCombobox",               ( PyCFunction ) DialogClass_addCombobox,               METH_VARARGS, "Insert a checkbox in the window" },
        { "addLineedit",               ( PyCFunction ) DialogClass_addLineedit,               METH_VARARGS, "Insert a Line edit in the window" },
        { "addCalendar",               ( PyCFunction ) DialogClass_addCalendar,               METH_VARARGS, "Insert a Calendar in the window" },
        { "addDial",                  ( PyCFunction ) DialogClass_addDial,               METH_VARARGS, "Insert a Dial in the window" },
        { "addSlider",                  ( PyCFunction ) DialogClass_addSlider,               METH_VARARGS, "Insert a Slider in the window" },
        { "replaceLabel",               ( PyCFunction ) DialogClass_replaceLabel,               METH_VARARGS, "Replace a label with supplied text" },
        { "clear",               ( PyCFunction ) DialogClass_clear,               METH_VARARGS, "clear the dialog" },

        { NULL },
};

PyTypeObject PyDialogClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havocui.dialog",                              /* tp_name */
        sizeof( PyDialogClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) DialogClass_dealloc,          /* tp_dealloc */
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
        "Dialog Havoc Object",                      /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyDialogClass_methods,                       /* tp_methods */
        PyDialogClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) DialogClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        DialogClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void DialogClass_dealloc( PPyDialogClass self )
{
    if (self) {
        if (self->title)
            Py_XDECREF( self->title );
        if (self->DialogWindow && self->DialogWindow->window)
            delete self->DialogWindow->window;
        if (self->DialogWindow)
            free(self->DialogWindow);
        Py_TYPE( self )->tp_free( ( PyObject* ) self );
    }
}

PyObject* DialogClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyDialogClass self;

    self = ( PPyDialogClass ) PyType_Type.tp_alloc( type, 0 );
    if (self == NULL)
        return NULL;
    self->DialogWindow = NULL;
    self->title = NULL;
    self->DialogWindow = (PPyDialogQWindow)malloc(sizeof(PyDialogQWindow));
    if (self->DialogWindow == NULL) {
        Py_TYPE( self )->tp_free( ( PyObject* ) self );
        return NULL;
    }
    self->DialogWindow->window = NULL;
    self->DialogWindow->layout = NULL;
    self->DialogWindow->scroll = NULL;
    self->DialogWindow->root = NULL;
    self->DialogWindow->root_layout = NULL;
    return ( PyObject* ) self;
}

int DialogClass_init( PPyDialogClass self, PyObject *args, PyObject *kwds )
{
    char*       title       = NULL;
    PyObject*   scrollable = NULL;
    int         width       = 400;
    int         height      = 300;
    const char* kwdlist[]   = { "title", "scrollable", "width", "height", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "s|Oii", const_cast<char**>(kwdlist), &title, &scrollable, &width, &height) )
        return -1;
    AllocMov( self->title, title, strlen(title) );

    self->DialogWindow->window = new QDialog(HavocX::HavocUserInterface->HavocWindow);
    self->DialogWindow->window->setWindowTitle(title);
    self->DialogWindow->window->resize(width, height);

    self->DialogWindow->root = new QWidget();
    self->DialogWindow->layout = new QVBoxLayout(self->DialogWindow->root);

    if (scrollable && PyBool_Check(scrollable) && scrollable == Py_True) {
        self->DialogWindow->scroll = new QScrollArea(self->DialogWindow->window);
        self->DialogWindow->scroll->setWidgetResizable(true);
        self->DialogWindow->scroll->setWidget(self->DialogWindow->root);
    }

    self->DialogWindow->root_layout = new QVBoxLayout(self->DialogWindow->window);
    if (scrollable && PyBool_Check(scrollable) && scrollable == Py_True)
        self->DialogWindow->root_layout->addWidget(self->DialogWindow->scroll);
    else
        self->DialogWindow->root_layout->addWidget(self->DialogWindow->root);
    return 0;
}

// Methods
PyObject* DialogClass_exec( PPyDialogClass self, PyObject *args )
{
    self->DialogWindow->window->exec();
    //HavocX::HavocUserInterface->NewBottomTab( self->DialogWindow, "test");

    Py_RETURN_NONE;
}

PyObject* DialogClass_addLabel( PPyDialogClass self, PyObject *args )
{
    char *text = nullptr;

    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QLabel* label = new QLabel(text, self->DialogWindow->window);
    self->DialogWindow->layout->addWidget(label);

    Py_RETURN_NONE;
}

PyObject* DialogClass_addImage( PPyDialogClass self, PyObject *args )
{
    char *text = nullptr;

    if( !PyArg_ParseTuple( args, "s", &text) )
    {
        Py_RETURN_NONE;
    }
    QPixmap img(text);
    QLabel* label = new QLabel(self->DialogWindow->window);
    label->setPixmap(img);
    self->DialogWindow->layout->addWidget(label);

    Py_RETURN_NONE;
}

PyObject* DialogClass_addButton( PPyDialogClass self, PyObject *args )
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
    QPushButton* button = new QPushButton(text, self->DialogWindow->window);
    if (style)
        button->setStyleSheet(style);
    self->DialogWindow->layout->addWidget(button);
    QObject::connect(button, &QPushButton::clicked, self->DialogWindow->window, [button_callback]() {
            PyObject_CallFunctionObjArgs(button_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* DialogClass_addCheckbox( PPyDialogClass self, PyObject *args )
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
    QCheckBox* checkbox = new QCheckBox(text, self->DialogWindow->window);
    if (style)
        checkbox->setStyleSheet(style);
    if (is_checked && PyBool_Check(is_checked) && is_checked == Py_True)
        checkbox->setChecked(true);
    self->DialogWindow->layout->addWidget(checkbox);
    QObject::connect(checkbox, &QCheckBox::clicked, self->DialogWindow->window, [checkbox_callback]() {
            PyObject_CallFunctionObjArgs(checkbox_callback, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* DialogClass_addCombobox( PPyDialogClass self, PyObject *args )
{
    Py_ssize_t tuple_size = PyTuple_Size(args);
    QComboBox* comboBox = new QComboBox(self->DialogWindow->window);

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
    self->DialogWindow->layout->addWidget(comboBox);
    QObject::connect(comboBox, QOverload<int>::of(&QComboBox::activated), [callable_obj](int index) {
        PyObject* pArg = PyLong_FromLong(index);
        PyObject_CallFunctionObjArgs(callable_obj, pArg, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* DialogClass_addLineedit( PPyDialogClass self, PyObject *args )
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
    QLineEdit* line = new QLineEdit(self->DialogWindow->window);
    line->setPlaceholderText(text);
    self->DialogWindow->layout->addWidget(line);
    QObject::connect(line, &QLineEdit::editingFinished, self->DialogWindow->window, [line, line_callback]() {
            QString text = line->text();
            QByteArray byteArray = text.toUtf8();
            char *charArray = byteArray.data();
            PyObject* pyString = PyUnicode_DecodeFSDefault(charArray);
            PyObject_CallFunctionObjArgs(line_callback, pyString, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* DialogClass_addCalendar( PPyDialogClass self, PyObject *args )
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

    QCalendarWidget* cal = new QCalendarWidget(self->DialogWindow->window);
    self->DialogWindow->layout->addWidget(cal);

    QObject::connect(cal, &QCalendarWidget::selectionChanged, self->DialogWindow->window, [cal, cal_callback]() {
            QDate selectedDate = cal->selectedDate();
            QString text = selectedDate.toString("yyyy-MM-dd");
            QByteArray byteArray = text.toUtf8();
            char *charArray = byteArray.data();
            PyObject* pyString = PyUnicode_DecodeFSDefault(charArray);
            PyObject_CallFunctionObjArgs(cal_callback, pyString, nullptr);
    });

    Py_RETURN_NONE;
}

PyObject* DialogClass_addDial( PPyDialogClass self, PyObject *args )
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

    QDial* dial = new QDial(self->DialogWindow->window);
    self->DialogWindow->layout->addWidget(dial);
    QObject::connect(dial, &QDial::valueChanged, self->DialogWindow->window, [cal_callback](long value) {
            PyObject* pyLong = PyLong_FromLong(value);
            PyObject_CallFunctionObjArgs(cal_callback, pyLong, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* DialogClass_addSlider( PPyDialogClass self, PyObject *args )
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
    self->DialogWindow->layout->addWidget(slider);
    QObject::connect(slider, &QSlider::valueChanged, self->DialogWindow->window, [cal_callback](long value) {
            PyObject* pyLong = PyLong_FromLong(value);
            PyObject_CallFunctionObjArgs(cal_callback, pyLong, nullptr);
    });
    Py_RETURN_NONE;
}

PyObject* DialogClass_replaceLabel( PPyDialogClass self, PyObject *args )
{
    char* to_find = NULL;
    char* to_replace= NULL;
    QVBoxLayout *layout = self->DialogWindow->layout;

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

PyObject* DialogClass_close( PPyDialogClass self, PyObject *args )
{
    self->DialogWindow->window->accept();

    Py_RETURN_NONE;
}

PyObject* DialogClass_clear( PPyDialogClass self, PyObject *args )
{
    QVBoxLayout *layout = self->DialogWindow->layout;
    QLayoutItem* item;

    while ((item = layout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    Py_RETURN_NONE;
}
