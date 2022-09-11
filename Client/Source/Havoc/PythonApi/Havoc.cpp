#include <global.hpp>
#include <QFile>

#include <Havoc/PythonApi/PythonApi.h>

#include <Havoc/PythonApi/PyDemonClass.h>
#include <Havoc/PythonApi/Event.h>

#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/DemonInteracted.h>

#include <QCompleter>

using namespace HavocNamespace::Util;

namespace PythonAPI::Havoc
{
    PyMethodDef PyMethode_Havoc[] = {
            { "LoadScript", PythonAPI::Havoc::Core::Load, METH_VARARGS, "load python script" },
            { "GetDemons", PythonAPI::Havoc::Core::GetDemons, METH_VARARGS, "get list of demon ID's" },
            { "RegisterCommand", PythonAPI::Havoc::Core::RegisterCommand, METH_VARARGS, "register a command/alias" },
            { "ConsoleWrite", PythonAPI::Havoc::Core::RegisterCommand, METH_VARARGS, "register a command/alias" },

            { NULL, NULL, 0, NULL }
    };

    namespace PyModule
    {
        struct PyModuleDef havoc = {
                PyModuleDef_HEAD_INIT,
                "havoc",
                "Python module to interact with Havoc",
                -1,
                PyMethode_Havoc
        };
    }
}

PyMODINIT_FUNC PythonAPI::Havoc::PyInit_Havoc( void )
{
    PyObject* Module = PyModule_Create2( &PythonAPI::Havoc::PyModule::havoc, PYTHON_API_VERSION );

    if ( PyType_Ready( &PyDemonClass_Type ) < 0 )
        spdlog::error( "Couldn't check if DemonClass is ready" );
    else
        PyModule_AddObject( Module, "Demon", (PyObject*) &PyDemonClass_Type );

    if ( PyType_Ready( &PyEventClass_Type ) < 0 )
        spdlog::error( "Couldn't check if Event class is ready" );
    else
        PyModule_AddObject( Module, "Event", (PyObject*) &PyEventClass_Type );

    return Module;
}

PyObject* PythonAPI::Havoc::Core::Load( PyObject *self, PyObject *args )
{
    char* FilePath = NULL;
    if( ! PyArg_ParseTuple( args, "s", &FilePath ) )
    {
        Py_RETURN_NONE;
    }

    QFile script( FilePath );
    script.open( QFile::ReadOnly );

    spdlog::info("Load Script: {}", FilePath);

    PyRun_SimpleStringFlags( script.readAll().toStdString().c_str(), NULL );

    Py_RETURN_NONE;
}

PyObject* PythonAPI::Havoc::Core::GetDemons( PyObject *self, PyObject *args )
{
    auto      DemonSessions    = HavocX::Teamserver.Sessions;
    uint32_t  NumberOfSessions = DemonSessions.size();
    PyObject* DemonObjects     = PyList_New( NumberOfSessions );
    PyObject* DemonID          = NULL;

    for ( int i = 0; i < NumberOfSessions; ++i )
    {
        DemonID = Py_BuildValue( "s", DemonSessions[ i ].Name.toStdString().c_str() );
        PyList_SetItem( DemonObjects, i, DemonID );
    }

    return DemonObjects;
}

PyObject* PythonAPI::Havoc::Core::RegisterCommand( PyObject *self, PyObject *args )
{
    RegisteredCommand RCommand = { };

    void* Function      = NULL;
    char* Module        = NULL;
    char* Command       = NULL;
    char* Description   = NULL;
    u32   Behavior      = 0;
    char* Usage         = NULL;
    char* Example       = NULL;
    auto  CompleteText = QString();

    if( ! PyArg_ParseTuple( args, "Osssiss", &Function, &Module, &Command, &Description, &Behavior, &Usage, &Example ) )
        Py_RETURN_NONE;

    RCommand.Function  = Function;
    RCommand.Module    = Module;
    RCommand.Command   = Command;
    RCommand.Help      = Description;
    RCommand.Behaviour = Behavior;
    RCommand.Usage     = Usage;
    RCommand.Example   = Example;

    // Check if command already exists... if it is already existing then replace it with new one.
    for ( u32 i = 0; i < HavocX::Teamserver.RegisteredCommands.size(); i++ )
    {
        auto c = HavocX::Teamserver.RegisteredCommands[ i ];

        if ( ( c.Command == RCommand.Command ) && ( c.Module == RCommand.Module ) )
        {
            spdlog::info( "Command already exists" );
            HavocX::Teamserver.RegisteredCommands[ i ] = RCommand;

            Py_RETURN_NONE;
        }
    }

    if ( ! RCommand.Module.empty() )
        CompleteText = QString( RCommand.Module.c_str() ) + " " + QString( RCommand.Command.c_str() );
    else
        CompleteText = QString( RCommand.Command.c_str() );

    // TODO: further test this. Reload or load new scripts that make use of RegisterCommand
    auto Sessions = HavocX::Teamserver.Sessions;
    for ( u32 i = 0; i < Sessions.size(); i++ )
    {
        Sessions[ i ].InteractedWidget->AutoCompleteAdd( CompleteText );
        Sessions[ i ].InteractedWidget->AutoCompleteAdd( "help " + CompleteText );
    }

    HavocX::Teamserver.AddedCommands << CompleteText;

    // Add new command
    HavocX::Teamserver.RegisteredCommands.push_back( RCommand );

    Py_RETURN_NONE;
}
