#include <Havoc/PythonApi/PythonApi.h>
#include <QFile>

namespace PythonAPI::HavocUI
{
    PyMethodDef PyMethode_HavocUI[] = {
            { "messagebox", PythonAPI::HavocUI::Core::MessageBox, METH_VARARGS, "Python interface for Havoc Messagebox" },

            { NULL, NULL, 0, NULL }
    };

    namespace PyModule
    {
        struct PyModuleDef havocui = {
                PyModuleDef_HEAD_INIT,
                "havocui",
                "Python module for Havoc Interface UI",
                -1,
                PyMethode_HavocUI
        };
    }
}

PyObject* PythonAPI::HavocUI::Core::MessageBox(PyObject *self, PyObject *args)
{
    char *title = nullptr, *content = nullptr;

    if( !PyArg_ParseTuple( args, "ss", &title, &content ) )
    {
        Py_RETURN_NONE;
    }

    QFile messageBoxStyleSheets(":/stylesheets/MessageBox");
    QMessageBox messageBox;

    messageBoxStyleSheets.open(QIODevice::ReadOnly);

    messageBox.setWindowTitle(title);
    messageBox.setText(content);
    messageBox.setIcon(QMessageBox::Information);
    messageBox.setStyleSheet(messageBoxStyleSheets.readAll());

    messageBox.exec();

    Py_RETURN_NONE;
}

PyMODINIT_FUNC PythonAPI::HavocUI::PyInit_HavocUI(void)
{
    return PyModule_Create( &PythonAPI::HavocUI::PyModule::havocui );
}