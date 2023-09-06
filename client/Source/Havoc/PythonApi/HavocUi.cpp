#include <Havoc/PythonApi/PythonApi.h>
#include <UserInterface/HavocUI.hpp>
#include <QFile>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>

namespace PythonAPI::HavocUI
{
    PyMethodDef PyMethode_HavocUI[] = {
            { "messagebox", PythonAPI::HavocUI::Core::MessageBox, METH_VARARGS, "Python interface for Havoc Messagebox" },
            { "createtab", PythonAPI::HavocUI::Core::CreateTab, METH_VARARGS, "Python interface for Havoc Tabs" },
            { "inputdialog", PythonAPI::HavocUI::Core::InputDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "openfiledialog", PythonAPI::HavocUI::Core::OpenFileDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "savefiledialog", PythonAPI::HavocUI::Core::SaveFileDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "questiondialog", PythonAPI::HavocUI::Core::QuestionDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },

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

PyObject* PythonAPI::HavocUI::Core::CreateTab(PyObject *self, PyObject *args)
{
    const char *title = nullptr;
    const char *in_menu = nullptr;

    if ( !HavocX::HavocUserInterface || !HavocX::HavocUserInterface->menubar )
    {
        Py_RETURN_NONE;
    }
    Py_ssize_t tuple_size = PyTuple_Size(args);
    title = (const char *)PyUnicode_AsUTF8(PyTuple_GetItem(args, 0));
    auto *menubar= HavocX::HavocUserInterface->menubar;
    auto tab = menubar->addMenu(title);
    if ( !tab )
    {
        Py_RETURN_NONE;
    }
    for (Py_ssize_t i = 1; i < tuple_size; i+=2) {
        const char * string_obj = PyUnicode_AsUTF8(PyTuple_GetItem(args, i));
        PyObject* callable_obj = PyTuple_GetItem(args, i + 1);
        if ( !PyCallable_Check(callable_obj) )
        {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }
        auto tupleCallback = new QAction( HavocX::HavocUserInterface->HavocWindow );

        tupleCallback->setObjectName(QString::fromUtf8(string_obj));
        tupleCallback->setText(string_obj);
        tab->addAction(tupleCallback);
        QMainWindow::connect( tupleCallback, &QAction::triggered, HavocX::HavocUserInterface->HavocWindow, [callable_obj]() {
            PyObject_CallFunctionObjArgs(callable_obj, nullptr);
        });
    }
    Py_RETURN_NONE;
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

PyObject* PythonAPI::HavocUI::Core::QuestionDialog(PyObject *self, PyObject *args)
{
    char *title = nullptr, *content = nullptr;

    if( !PyArg_ParseTuple( args, "ss", &title, &content ) )
    {
        Py_RETURN_NONE;
    }

    QMessageBox::StandardButton result = QMessageBox::question(HavocX::HavocUserInterface->HavocWindow, title, content, QMessageBox::Yes | QMessageBox::No);

    if (result == QMessageBox::Yes) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

PyObject* PythonAPI::HavocUI::Core::InputDialog(PyObject *self, PyObject *args)
{
    char *title = nullptr, *content = nullptr;

    if( !PyArg_ParseTuple( args, "ss", &title, &content ) )
    {
        Py_RETURN_NONE;
    }
    QString data = QInputDialog::getText(
                    HavocX::HavocUserInterface->HavocWindow, title, content);
    return PyBytes_FromString(data.toStdString().c_str());
}

PyObject* PythonAPI::HavocUI::Core::OpenFileDialog(PyObject *self, PyObject *args)
{
    char *title = nullptr;

    if( !PyArg_ParseTuple( args, "s", &title) )
    {
        Py_RETURN_NONE;
    }
    QString data = QFileDialog::getOpenFileName(
                    HavocX::HavocUserInterface->HavocWindow, title, QDir::homePath());
    return PyBytes_FromString(data.toStdString().c_str());
}

PyObject* PythonAPI::HavocUI::Core::SaveFileDialog(PyObject *self, PyObject *args)
{
    char *title = nullptr;

    if( !PyArg_ParseTuple( args, "s", &title) )
    {
        Py_RETURN_NONE;
    }
    QString data = QFileDialog::getSaveFileName(
                    HavocX::HavocUserInterface->HavocWindow, title, QDir::homePath());
    return PyBytes_FromString(data.toStdString().c_str());
}

PyMODINIT_FUNC PythonAPI::HavocUI::PyInit_HavocUI(void)
{
    return PyModule_Create( &PythonAPI::HavocUI::PyModule::havocui );
}
