
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/UI/PyTreeClass.hpp>


PyMemberDef PyTreeClass_members[] = {

        { "title",       T_STRING, offsetof( PyTreeClass, title ),    0, "title" },

        { NULL },
};

PyMethodDef PyTreeClass_methods[] = {

        { "setBottomTab",               ( PyCFunction ) TreeClass_setBottomTab,               METH_VARARGS, "Set widget as Bottom Tab" },
        { "setSmallTab",               ( PyCFunction ) TreeClass_setSmallTab,               METH_VARARGS, "Set widget as Small Tab" },
        { "addRow",               ( PyCFunction ) TreeClass_addRow,               METH_VARARGS, "add a row to the tree" },
        { "setItem",               ( PyCFunction ) TreeClass_setItem,               METH_VARARGS, "set an item in the tree" },

        { NULL },
};

PyTypeObject PyTreeClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havocui.tree",                              /* tp_name */
        sizeof( PyTreeClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) TreeClass_dealloc,          /* tp_dealloc */
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
        "Tree Widget Havoc Object",                      /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyTreeClass_methods,                       /* tp_methods */
        PyTreeClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) TreeClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        TreeClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void TreeClass_dealloc( PPyTreeClass self )
{
    if (self) {
        if (self->title)
            Py_XDECREF( self->title );
        if (self->TreeWindow && self->TreeWindow->window)
            delete self->TreeWindow->window;
        if (self->TreeWindow)
            free(self->TreeWindow);
        Py_TYPE( self )->tp_free( ( PyObject* ) self );
    }
}

PyObject* TreeClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyTreeClass self;

    self = ( PPyTreeClass ) PyType_Type.tp_alloc( type, 0 );
    if (self == NULL)
        return NULL;
    self->title = NULL;
    self->TreeWindow = NULL;
    self->TreeWindow = (PPyTreeQWindow)malloc(sizeof(PyTreeQWindow));
    if (self->TreeWindow == NULL)
        return NULL;
    self->TreeWindow->window = NULL;
    self->TreeWindow->layout = NULL;
    self->TreeWindow->scroll= NULL;
    self->TreeWindow->root = NULL;
    self->TreeWindow->root_layout = NULL;
    return ( PyObject* ) self;
}

int TreeClass_init( PPyTreeClass self, PyObject *args, PyObject *kwds )
{
    char*       title          = NULL;
    PyObject* class_callback    = nullptr;
    const char* kwdlist[]        = { "title", "callback", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "sO", const_cast<char**>(kwdlist), &title, &class_callback ) )
        return -1;
    if ( !PyCallable_Check(class_callback) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return -1;
    }

    AllocMov( self->title, title, strlen(title) );

    self->TreeWindow->window = new QWidget();
    self->TreeWindow->window->setWindowTitle(title);

    self->TreeWindow->root = new QWidget();
    self->TreeWindow->layout = new QVBoxLayout(self->TreeWindow->root);

    self->TreeWindow->scroll = new QScrollArea(self->TreeWindow->window);
    self->TreeWindow->scroll->setWidgetResizable(true);
    self->TreeWindow->scroll->setWidget(self->TreeWindow->root);

    self->TreeWindow->root_layout = new QVBoxLayout(self->TreeWindow->window);
    self->TreeWindow->root_layout->addWidget(self->TreeWindow->scroll);

    self->TreeWindow->item_model = new QStandardItemModel();
    self->TreeWindow->item_model->setColumnCount(1);

    self->TreeWindow->root_item = new QStandardItem(title);
    self->TreeWindow->tree_view = new QTreeView();

    self->TreeWindow->tree_view->setModel(self->TreeWindow->item_model);
    self->TreeWindow->item_model->invisibleRootItem()->appendRow(self->TreeWindow->root_item);
    self->TreeWindow->layout->addWidget(self->TreeWindow->tree_view);

    QObject::connect(self->TreeWindow->tree_view->selectionModel(), &QItemSelectionModel::selectionChanged, [self, class_callback](const QItemSelection &selected, const QItemSelection &deselected) {
        for (const QModelIndex &index : selected.indexes()) {
            QStandardItem *selectedItem = self->TreeWindow->item_model->itemFromIndex(index);
            if (selectedItem) {
                const char *str = selectedItem->text().toUtf8().constData();
                PyObject* pystr = PyUnicode_DecodeFSDefault(str);
                PyObject_CallFunctionObjArgs(class_callback, pystr, nullptr);
            }
        }
    });

    return 0;
}

// Methods

PyObject* TreeClass_setBottomTab( PPyTreeClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewBottomTab( self->TreeWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* TreeClass_setSmallTab( PPyTreeClass self, PyObject *args )
{
    HavocX::HavocUserInterface->NewSmallTab( self->TreeWindow->window, self->title);

    Py_RETURN_NONE;
}

PyObject* TreeClass_addRow( PPyTreeClass self, PyObject *args )
{
    const char *title = nullptr;
    Py_ssize_t tuple_size = PyTuple_Size(args);

    title = (const char *)PyUnicode_AsUTF8(PyTuple_GetItem(args, 0));
    if (title == NULL) {
        PyErr_SetString(PyExc_TypeError, "First parameter must be a string");
    }

    QStandardItem* child = new QStandardItem(title);
    QList<QStandardItem*> child_data;

    for (Py_ssize_t i = 1; i < tuple_size; i++) {
        const char* child_str = PyUnicode_AsUTF8(PyTuple_GetItem(args, i));
        child_data.append(new QStandardItem(child_str));
    }
    child->appendColumn(child_data);
    self->TreeWindow->root_item->appendRow(child);

    Py_RETURN_NONE;
}

PyObject* TreeClass_setItem( PPyTreeClass self, PyObject *args )
{
    int x, y;
    char *str;
    if( !PyArg_ParseTuple( args, "iis", &x, &y, &str) )
    {
        Py_RETURN_NONE;
    }
    QStandardItem* element = new QStandardItem(str);

    self->TreeWindow->item_model->setItem(x, y, element);

    Py_RETURN_NONE;
}
