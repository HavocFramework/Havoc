#include <global.hpp>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>
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
            { "LoadScript",       PythonAPI::Havoc::Core::Load,                            METH_VARARGS,                 "load python script"       },
            { "GetDemons",        PythonAPI::Havoc::Core::GetDemons,                       METH_VARARGS,                 "get list of demon ID's"   },
            { "GetListeners",     PythonAPI::Havoc::Core::GetListeners,                    METH_VARARGS,                 "get list of Listeners"   },
            { "GetAgents",        PythonAPI::Havoc::Core::GetAgents,                       METH_VARARGS,                 "get list of Agents"   },
            { "GeneratePayload",  ( PyCFunction ) PythonAPI::Havoc::Core::GeneratePayload, METH_VARARGS | METH_KEYWORDS, "Generate a payload and get the base64 bytestring" },
            { "RegisterCommand",  ( PyCFunction ) PythonAPI::Havoc::Core::RegisterCommand, METH_VARARGS | METH_KEYWORDS, "register a command/alias" },
            { "RegisterModule",   PythonAPI::Havoc::Core::RegisterModule,                  METH_VARARGS,                 "register a module"        },
            { "RegisterCallback", PythonAPI::Havoc::Core::RegisterCallback,                METH_VARARGS,                 "register a callback"      },

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
    int   Return   = 0;

    if ( ! PyArg_ParseTuple( args, "s", &FilePath ) )
        Py_RETURN_NONE;

    auto script = FileRead( FilePath );

    spdlog::info( "Load Script: {}", FilePath );

    Return = PyRun_SimpleStringFlags( script.toStdString().c_str(), NULL );

    if ( Return == -1 ) {
        spdlog::error( "Failed to load script" );
        Py_RETURN_FALSE;
    }

    Py_RETURN_TRUE;
}

PyObject* PythonAPI::Havoc::Core::GetListeners( PyObject *self, PyObject *args )
{
    auto      Listeners        = HavocX::Teamserver.Listeners;
    uint32_t  NumberOfSessions = Listeners.size();
    PyObject* ListenerObjects  = PyList_New( NumberOfSessions );
    PyObject* ListenerID       = NULL;

    for ( int i = 0; i < NumberOfSessions; ++i )
    {
        ListenerID = Py_BuildValue( "s", Listeners[ i ].Name.c_str() );
        PyList_SetItem( ListenerObjects, i, ListenerID );
    }

    return ListenerObjects;
}

PyObject* PythonAPI::Havoc::Core::GetAgents( PyObject *self, PyObject *args )
{
    auto      Agents           = HavocX::Teamserver.ServiceAgents;
    uint32_t  NumberOfSessions = Agents.size();
    PyObject* AgentsObjects  = PyList_New( NumberOfSessions + 1);
    PyObject* AgentsID       = NULL;

    AgentsID = Py_BuildValue( "s", "Demon" );
    PyList_SetItem( AgentsObjects, 0, AgentsID );
    for ( int i = 1; i < NumberOfSessions; ++i )
    {
        AgentsID = Py_BuildValue( "s", Agents[ i ].Name.toStdString().c_str() );
        PyList_SetItem( AgentsObjects, i, AgentsID );
    }

    return AgentsObjects;
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

PyObject* PythonAPI::Havoc::Core::GeneratePayload( PyObject *self, PyObject *args, PyObject* kwargs )
{
    PyObject*   callbackGate = nullptr;
    char*       agent = nullptr;
    char*       listener = nullptr;
    char*       arch = nullptr;
    char*       format_string = nullptr;
    char*       config = nullptr;
    const char* KeyWords[] = { "callback", "agent", "listener", "arch", "format", "config", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwargs, "Osssss", const_cast<char**>(KeyWords), &callbackGate, &agent, &listener, &arch, &format_string, &config) )
        Py_RETURN_NONE;
    if ( !PyCallable_Check(callbackGate) )
    {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    HavocX::callbackGate = callbackGate;

    auto Package = new Util::Packager::Package;

    auto Head = Util::Packager::Head_t {
            .Event   = Util::Packager::Gate::Type,
            .User    = HavocX::Teamserver.User.toStdString(),
            .Time    = CurrentTime().toStdString(),
            .OneTime = "true",
    };

    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Gate::Stageless,
            .Info = {
                { "AgentType", std::string(agent) },
                { "Listener",  std::string(listener) },
                { "Arch",      std::string(arch) },
                { "Format",    std::string(format_string) },
                { "Config",    std::string(config) },
            },
    };


    Package->Head = Head;
    Package->Body = Body;

    HavocX::Connector->SendPackage( Package );

    Py_RETURN_NONE;
}

// RegisterCommand( PyFunction: func, Module: str, Command: str, Description: str, Behavior: int, Usage: str, Example: str )
PyObject* PythonAPI::Havoc::Core::RegisterCommand( PyObject *self, PyObject *args, PyObject* kwargs )
{
    RegisteredCommand RCommand = { };

    PVOID Function         = nullptr;
    PCHAR Agent            = nullptr;
    PCHAR Module           = nullptr;
    PCHAR Command          = nullptr;
    PCHAR Description      = nullptr;
    PCHAR Usage            = nullptr;
    PCHAR Example          = nullptr;
    u32   Behavior         = 0;
    auto  CompleteText     = QString();
    auto  Path             = HavocX::Teamserver.LoadingScript;
    const char* KeyWords[] = { "function", "module", "command", "description", "behavior", "usage", "example", "agent", NULL };
    const char* format     = "Osssiss|s";

    if ( ! PyArg_ParseTupleAndKeywords( args, kwargs, format, const_cast<char**>(KeyWords), &Function, &Module, &Command, &Description, &Behavior, &Usage, &Example, &Agent ) )
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

    if ( QString( RCommand.Module.c_str() ).length() > 0 ) {
        spdlog::debug( "Registered command: {} {}", Module, Command );
    } else {
        spdlog::debug( "Registered command: {}", Command );
    }

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
    Py_XINCREF( RCommand.Function );

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

    spdlog::debug( "Registered module: {}", Module.Name );

    Py_RETURN_NONE;
}

PyObject* PythonAPI::Havoc::Core::RegisterCallback( PyObject *self, PyObject *args )
{
    spdlog::debug( "PythonAPI::Havoc::Core::RegisterCallback" );

    PyObject* Callback = nullptr;

    if ( ! PyArg_ParseTuple( args, "O", &Callback ) )
    {
        spdlog::error( "Invalid parameters on RegisterCallback" );
        return nullptr;
    }

    if ( ! PyCallable_Check( Callback ) )
    {
        spdlog::error( "The callback is not callable" );
        return nullptr;
    }

    HavocX::Teamserver.RegisteredCallbacks.push_back( Callback );
    Py_XINCREF( Callback );

    Py_RETURN_NONE;
}
