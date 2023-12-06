#include <Havoc/PythonApi/PythonApi.h>
#include <UserInterface/HavocUI.hpp>

#include <Havoc/PythonApi/UI/PyWidgetClass.hpp>
#include <Havoc/PythonApi/UI/PyDialogClass.hpp>
#include <Havoc/PythonApi/UI/PyLoggerClass.hpp>
#include <Havoc/PythonApi/UI/PyTreeClass.hpp>

#include <QFile>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <QColorDialog>
#include <QProgressDialog>
#include <QTimer>
#include <QErrorMessage>

namespace PythonAPI::HavocUI
{
    PyMethodDef PyMethode_HavocUI[] = {
            { "messagebox", PythonAPI::HavocUI::Core::MessageBox, METH_VARARGS, "Python interface for Havoc Messagebox" },
            { "errormessage", PythonAPI::HavocUI::Core::ErrorMessage, METH_VARARGS, "Python interface for Havoc Error Message" },
            { "createtab", PythonAPI::HavocUI::Core::CreateTab, METH_VARARGS, "Python interface for Havoc Tabs" },
            { "inputdialog", PythonAPI::HavocUI::Core::InputDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "openfiledialog", PythonAPI::HavocUI::Core::OpenFileDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "savefiledialog", PythonAPI::HavocUI::Core::SaveFileDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "questiondialog", PythonAPI::HavocUI::Core::QuestionDialog, METH_VARARGS, "Python interface for Havoc InputDialog" },
            { "colordialog", PythonAPI::HavocUI::Core::ColorDialog, METH_VARARGS, "Python interface for Havoc ColorDialog" },
            { "progressdialog", PythonAPI::HavocUI::Core::ProgressDialog, METH_VARARGS, "Python interface for Havoc ColorDialog" },

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

PyObject* PythonAPI::HavocUI::Core::ErrorMessage(PyObject *self, PyObject *args)
{
    char *message = nullptr;

    if( !PyArg_ParseTuple( args, "s", &message ) )
    {
        Py_RETURN_NONE;
    }

    QErrorMessage* errorMessage = new QErrorMessage(HavocX::HavocUserInterface->HavocWindow);
    errorMessage->showMessage(message);

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

PyObject* PythonAPI::HavocUI::Core::ColorDialog(PyObject *self, PyObject *args)
{
    QColorDialog data = QColorDialog(HavocX::HavocUserInterface->HavocWindow);
    QColor sel = data.getColor();
    if (sel.isValid()) {
        QString colorHex = sel.name();
        return PyBytes_FromString(colorHex.toStdString().c_str());
    } else {
        Py_RETURN_NONE;
    }
}

PyObject* PythonAPI::HavocUI::Core::ProgressDialog(PyObject *self, PyObject *args)
{
    char *title = nullptr;
    char *text= nullptr;
    int max_num = 0;
    PyObject* callable_obj = nullptr;

    if( !PyArg_ParseTuple( args, "ssOi", &title, &text, &callable_obj, &max_num) )
    {
        Py_RETURN_NONE;
    }
    if ( !PyCallable_Check(callable_obj) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    QProgressDialog* dialog = new QProgressDialog(title, text, 0, max_num, HavocX::HavocUserInterface->HavocWindow);
    dialog->setAutoClose(false);
    QTimer* timer = new QTimer();

    QMainWindow::connect( timer, &QTimer::timeout, HavocX::HavocUserInterface->HavocWindow, [callable_obj, dialog, timer]() {
        PyObject *pResult = PyObject_CallFunctionObjArgs(callable_obj, nullptr);

        if (pResult != NULL) {
            if (PyLong_Check(pResult)) {
                long resultInt = PyLong_AsLong(pResult);
                dialog->setValue(resultInt);
                if (resultInt < 0) {
                    dialog->close();
                    timer->stop();
                }
            }
        } else {
            PyErr_SetString(PyExc_TypeError, "Function needs to return an int");
            dialog->close();
            timer->stop();
        }
    });
    QPushButton *cancelButton = dialog->findChild<QPushButton *>();
    QMainWindow::connect( cancelButton, &QPushButton::clicked, HavocX::HavocUserInterface->HavocWindow, [dialog, timer]() {
        dialog->close();
        timer->stop();
    });
    timer->start(max_num);
    dialog->exec();

    Py_RETURN_NONE;
}

PyMODINIT_FUNC PythonAPI::HavocUI::PyInit_HavocUI(void)
{
    PyObject* Module = PyModule_Create2( &PythonAPI::HavocUI::PyModule::havocui, PYTHON_API_VERSION );

    if ( PyType_Ready( &PyWidgetClass_Type ) < 0 )
        spdlog::error( "Couldn't check if WidgetClass is ready" );
    else
        PyModule_AddObject( Module, "Widget", (PyObject*) &PyWidgetClass_Type );

    if ( PyType_Ready( &PyDialogClass_Type ) < 0 )
        spdlog::error( "Couldn't check if DialogClass is ready" );
    else
        PyModule_AddObject( Module, "Dialog", (PyObject*) &PyDialogClass_Type );

    if ( PyType_Ready( &PyLoggerClass_Type ) < 0 )
        spdlog::error( "Couldn't check if LoggerClass is ready" );
    else
        PyModule_AddObject( Module, "Logger", (PyObject*) &PyLoggerClass_Type );

    if ( PyType_Ready( &PyTreeClass_Type ) < 0 )
        spdlog::error( "Couldn't check if TreeClass is ready" );
    else
        PyModule_AddObject( Module, "Tree", (PyObject*) &PyTreeClass_Type );

    return Module;
}
