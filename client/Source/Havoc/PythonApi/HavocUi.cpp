#include <Havoc/PythonApi/PythonApi.h>
#include <UserInterface/HavocUI.hpp>
#include <QFile>

namespace PythonAPI::HavocUI
{
    PyMethodDef PyMethode_HavocUI[] = {
            { "messagebox", PythonAPI::HavocUI::Core::MessageBox, METH_VARARGS, "Python interface for Havoc Messagebox" },
            { "createtab", PythonAPI::HavocUI::Core::CreateTab, METH_VARARGS, "Python interface for Havoc Tabs" },

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
    char *title = nullptr;
    char *in_menu = nullptr;
	PyObject *tmp_callback;
	PyObject *arglist;
	PyObject *result;
	static PyObject *my_callback = NULL;

    if( !PyArg_ParseTuple( args, "ss", &title, &in_menu) )
    {
        Py_RETURN_NONE;
    }
	/*if ( !PyCallable_Check(tmp_callback) )
	{
		PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
	}*/
	Py_XINCREF(tmp_callback);
	Py_XDECREF(my_callback);
	my_callback = tmp_callback;
	if ( !HavocX::HavocUserInterface || !HavocX::HavocUserInterface->menubar )
    {
        Py_RETURN_NONE;
    }
	auto *menubar= HavocX::HavocUserInterface->menubar;
	auto tab = menubar->addMenu(title);
    auto actionCallback = new QAction( HavocX::HavocUserInterface->HavocWindow );
	if ( !tab )
    {
        Py_RETURN_NONE;
    }
	tab->addMenu(in_menu);
/*    QMainWindow::connect( actionCallback, &QAction::triggered, *HavocX::HavocUserInterface, [&]() {
		arglist = Py_BuildValue("");
		result = PyObject_CallObject(tmp_callback, arglist);
		Py_DECREF(arglist);
		return result;
	});*/
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

PyMODINIT_FUNC PythonAPI::HavocUI::PyInit_HavocUI(void)
{
    return PyModule_Create( &PythonAPI::HavocUI::PyModule::havocui );
}
