
#ifndef HAVOC_PYTHONAPI_H
#define HAVOC_PYTHONAPI_H

#include <global.hpp>
#pragma push_macro("slots")
#undef slots
#include <Python.h>
#pragma pop_macro("slots")

#define PY_FUNCTION( x )    PyObject* x( PyObject *self, PyObject *args );
#define PY_FUNCTION_KW( x ) PyObject* x( PyObject *self, PyObject *args, PyObject* kwargs );

namespace PythonAPI
{
    namespace Havoc
    {
        extern PyMethodDef PyMethode_Havoc[];

        namespace Core
        {
            PY_FUNCTION( Load )
            PY_FUNCTION( GetDemons )
            PY_FUNCTION( RegisterModule )

            PY_FUNCTION_KW( RegisterCommand )
        }

        namespace PyModule
        {
            extern struct PyModuleDef havoc;
        }

        PyMODINIT_FUNC PyInit_Havoc(void);
    }

    namespace HavocUI
    {
        extern PyMethodDef PyMethode_HavocUI[];

        namespace Core
        {
            PY_FUNCTION( MessageBox )
        }

        namespace PyModule
        {
            extern struct PyModuleDef havocui;
        }

        PyMODINIT_FUNC PyInit_HavocUI(void);

    }
}

namespace emb
{
    typedef std::function<void(std::string)> stdout_write_type;

    struct Stdout
    {
        PyObject_HEAD
        stdout_write_type write;
    };

    PyObject* Stdout_write(PyObject* self, PyObject* args);
    PyObject* Stdout_flush(PyObject* self, PyObject* args);
    PyMODINIT_FUNC PyInit_emb(void);
    void set_stdout(stdout_write_type write);
    void reset_stdout();
};

#endif
