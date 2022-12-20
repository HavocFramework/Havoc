#include <global.hpp>
#include <QFile>

#include <Havoc/PythonApi/PythonApi.h>

#include <Havoc/PythonApi/PyDemonClass.h>
#include <Havoc/PythonApi/PyAgentClass.hpp>
#include <Havoc/PythonApi/Event.h>

#include <UserInterface/Widgets/DemonInteracted.h>

#include <QCompleter>

using namespace HavocNamespace::Util;

namespace PythonAPI::Havoc
{
    PyMethodDef PyMethode_Havoc[] = {
            { "LoadScript",      PythonAPI::Havoc::Core::Load,                            METH_VARARGS,                 "load python script"       },
            { "GetDemons",       PythonAPI::Havoc::Core::GetDemons,                       METH_VARARGS,                 "get list of demon ID's"   },
            { "RegisterCommand", ( PyCFunction ) PythonAPI::Havoc::Core::RegisterCommand, METH_VARARGS | METH_KEYWORDS, "register a command/alias" },
            { "RegisterModule",  PythonAPI::Havoc::Core::RegisterModule,                  METH_VARARGS,                 "register a module"        },

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

    if ( PyType_Ready( &PyAgentClass_Type ) < 0 )
        spdlog::error( "Couldn't check if AgentClass is ready" );
    else
        PyModule_AddObject( Module, "Agent", (PyObject*) &PyAgentClass_Type );

    if ( PyType_Ready( &PyEventClass_Type ) < 0 )
        spdlog::error( "Couldn't check if Event class is ready" );
    else
        PyModule_AddObject( Module, "Event", (PyObject*) &PyEventClass_Type );

    return Module;
}

PyObject* PythonAPI::Havoc::Core::Load( PyObject *self, PyObject *args )
{
    char* FilePath = NULL;

    if ( ! PyArg_ParseTuple( args, "s", &FilePath ) )
        Py_RETURN_NONE;

    auto script = FileRead( FilePath );

    spdlog::info( "Load Script: {}", FilePath );

    PyRun_SimpleStringFlags( script.toStdString().c_str(), NULL );

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

// RegisterCommand( PyFunction: func, Module: str, Command: str, Description: str, Behavior: int, Usage: str, Example: str )
PyObject* PythonAPI::Havoc::Core::RegisterCommand( PyObject *self, PyObject *args, PyObject* kwargs )
{
    RegisteredCommand RCommand = { };

    PVOID Function      = nullptr;
    PCHAR Agent         = nullptr;
    PCHAR Module        = nullptr;
    PCHAR Command       = nullptr;
    PCHAR Description   = nullptr;
    PCHAR Usage         = nullptr;
    PCHAR Example       = nullptr;
    u32   Behavior      = 0;
    auto  CompleteText  = QString();
    auto  Path          = HavocX::Teamserver.LoadingScript;
    PCHAR KeyWords[]    = { "function", "module", "command", "description", "behavior", "usage", "example", "agent", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwargs, "Osssiss|s", KeyWords, &Function, &Module, &Command, &Description, &Behavior, &Usage, &Example, &Agent ) )
        Py_RETURN_NONE;

    if ( Agent != nullptr )
        RCommand.Agent = Agent;
    else
        RCommand.Agent = "Demon"; /* if the 'agent' keyword hasn't been specified then use the demon agent by default */

    RCommand.Function  = Function;
    RCommand.Module    = Module;
    RCommand.Command   = Command;
    RCommand.Help      = Description;
    RCommand.Behaviour = Behavior;
    RCommand.Usage     = Usage;
    RCommand.Example   = Example;
    RCommand.Path      = Path.substr( 0, Path.find_last_of( "\\/" ) );

    // Check if command already exists... if it is already existing then replace it with new one.
    for ( u32 i = 0; i < HavocX::Teamserver.RegisteredCommands.size(); i++ )
    {
        auto c = HavocX::Teamserver.RegisteredCommands[ i ];

        if ( ( c.Command == RCommand.Command ) && ( c.Module == RCommand.Module ) && ( c.Agent == RCommand.Agent ) )
        {
            spdlog::debug( "Command already exists: [Module: {}] [Command: {}]", RCommand.Module, RCommand.Command );
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

// RegisterModule( Name: str, Description: str, Behavior: str, Usage: str, Example: str, Options: str )
PyObject* PythonAPI::Havoc::Core::RegisterModule( PyObject *self, PyObject *args )
{
    spdlog::debug( "PythonAPI::Havoc::Core::RegisterModule" );
    RegisteredModule Module = {};

    PCHAR Name         = nullptr;
    PCHAR Description  = nullptr;
    PCHAR Behavior     = nullptr;
    PCHAR Usage        = nullptr;
    PCHAR Example      = nullptr;
    PCHAR Options      = nullptr;
    auto  CompleteText = QString();

    if( ! PyArg_ParseTuple( args, "ssssss", &Name, &Description, &Behavior, &Usage, &Example, &Options ) )
        Py_RETURN_NONE;

    Module.Name         = Name;
    Module.Description  = Description;
    Module.Behavior     = Behavior;
    Module.Usage        = Usage;
    Module.Example      = Example;

    // Check if module already exists... if it is already existing then replace it with new one.
    for ( u32 i = 0; i < HavocX::Teamserver.RegisteredModules.size(); i++ )
    {
        auto c = HavocX::Teamserver.RegisteredModules[ i ];

        if ( ( c.Name == Module.Name ) && ( c.Agent == Module.Agent ) )
        {
            spdlog::debug( "Module already exists: [Module: {}]", Module.Name );
            HavocX::Teamserver.RegisteredModules[ i ] = Module;

            Py_RETURN_NONE;
        }
    }

    CompleteText = QString( Module.Name.c_str() );

    // TODO: further test this. Reload or load new scripts that make use of RegisterCommand
    auto Sessions = HavocX::Teamserver.Sessions;
    for ( u32 i = 0; i < Sessions.size(); i++ )
    {
        Sessions[ i ].InteractedWidget->AutoCompleteAdd( CompleteText );
        Sessions[ i ].InteractedWidget->AutoCompleteAdd( "help " + CompleteText );
    }

    HavocX::Teamserver.AddedCommands << CompleteText;

    // Add new command
    HavocX::Teamserver.RegisteredModules.push_back( Module );

    Py_RETURN_NONE;
}
