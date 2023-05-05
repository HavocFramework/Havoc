
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PythonApi.h>
#include <Havoc/PythonApi/PyDemonClass.h>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <Util/ColorText.h>

PyMemberDef PyDemonClass_members[] = {

        { "Listener",       T_STRING, offsetof( PyDemonClass, Listener ),    0, "Listener name" },
        { "DemonID",        T_STRING, offsetof( PyDemonClass, DemonID ),     0, "Listener name" },
        { "ExternalIP",     T_STRING, offsetof( PyDemonClass, ExternalIP ),  0, "External IP" },
        { "InternalIP",     T_STRING, offsetof( PyDemonClass, InternalIP ),  0, "Internal IP" },
        { "User",           T_STRING, offsetof( PyDemonClass, User ),        0, "Username" },
        { "Computer",       T_STRING, offsetof( PyDemonClass, Computer ),    0, "Computer" },
        { "Domain",         T_STRING, offsetof( PyDemonClass, Domain ),      0, "Domain" },
        { "OS",             T_STRING, offsetof( PyDemonClass, OS ),          0, "Windows Version" },
        { "OSBuild",        T_STRING, offsetof( PyDemonClass, OSBuild ),     0, "Windows OS Build" },
        { "OSArch",         T_STRING, offsetof( PyDemonClass, OSArch ),      0, "Windows Architecture" },
        { "ProcessName",    T_STRING, offsetof( PyDemonClass, ProcessName ), 0, "Process Name" },
        { "ProcessID",      T_STRING, offsetof( PyDemonClass, ProcessID ),   0, "Process ID" },
        { "ProcessArch",    T_STRING, offsetof( PyDemonClass, ProcessArch ), 0, "Process Architecture" },

        { "CONSOLE_INFO",   T_INT, offsetof( PyDemonClass, CONSOLE_INFO ),   0, "Console message type info" },
        { "CONSOLE_ERROR",  T_INT, offsetof( PyDemonClass, CONSOLE_ERROR ),  0, "Console message type error" },
        { "CONSOLE_TASK",   T_INT, offsetof( PyDemonClass, CONSOLE_TASK ),   0, "Console message type task" },

        { NULL },
};

PyMethodDef PyDemonClass_methods[] = {

        { "ConsoleWrite",           ( PyCFunction ) DemonClass_ConsoleWrite,           METH_VARARGS, "Prints messages to the demon sessions console" },
        { "ProcessCreate",          ( PyCFunction ) DemonClass_ProcessCreate,          METH_VARARGS, "Creates a Process" },
        { "InlineExecute",          ( PyCFunction ) DemonClass_InlineExecute,          METH_VARARGS, "Executes a coff file in the context of the demon sessions" },
        { "InlineExecuteGetOutput", ( PyCFunction ) DemonClass_InlineExecuteGetOutput, METH_VARARGS, "Executes a coff file in the context of the demon sessions and get the output via a callback" },
        { "DllSpawn",               ( PyCFunction ) DemonClass_DllSpawn,               METH_VARARGS, "Spawn and injects a reflective dll and get output from it" },
        { "DllInject",              ( PyCFunction ) DemonClass_DllInject,              METH_VARARGS, "Injects a reflective dll into a specified process" },
        { "DotnetInlineExecute",    ( PyCFunction ) DemonClass_DotnetInlineExecute,    METH_VARARGS, "Executes a dotnet assembly in the context of the demon sessions" },

        { NULL },
};

PyTypeObject PyDemonClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havoc.Demon",                              /* tp_name */
        sizeof( PyDemonClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) DemonClass_dealloc,          /* tp_dealloc */
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
        "Demon Session Object",                     /* tp_doc */
        0,                                          /* tp_traverse */
        0,                                          /* tp_clear */
        0,                                          /* tp_richcompare */
        0,                                          /* tp_weaklistoffset */
        0,                                          /* tp_iter */
        0,                                          /* tp_iternext */
        PyDemonClass_methods,                       /* tp_methods */
        PyDemonClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) DemonClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        DemonClass_new,                             /* tp_new */
};

#define AllocMov( des, src, size )                          \
    if ( size > 0 )                                         \
    {                                                       \
        des = ( char* ) malloc( size * sizeof( char ) );    \
        memset( des, 0, size );                             \
        std::strcpy( des, src );                            \
    }

void DemonClass_dealloc( PPyDemonClass self )
{
    Py_XDECREF( self->Listener );
    Py_XDECREF( self->DemonID );
    Py_XDECREF( self->ExternalIP );
    Py_XDECREF( self->InternalIP );
    Py_XDECREF( self->User );
    Py_XDECREF( self->Computer );
    Py_XDECREF( self->Domain );
    Py_XDECREF( self->OS );
    Py_XDECREF( self->OSBuild );
    Py_XDECREF( self->OSArch );
    Py_XDECREF( self->ProcessName );
    Py_XDECREF( self->ProcessID );
    Py_XDECREF( self->ProcessArch );

    Py_TYPE( self )->tp_free( ( PyObject* ) self );
}

PyObject* DemonClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyDemonClass self;

    self = ( PPyDemonClass ) PyType_Type.tp_alloc( type, 0 );

    return ( PyObject* ) self;
}

int DemonClass_init( PPyDemonClass self, PyObject *args, PyObject *kwds )
{
    if ( PyType_Type.tp_init( ( PyObject* ) self, args, kwds ) < 0 )
        return -1;

    char*     DemonID          = NULL;
    auto      DemonSessions    = HavocX::Teamserver.Sessions;
    uint32_t  NumberOfSessions = DemonSessions.size();
    char*     kwdlist[]        = { "DemonID", NULL };

    if ( ! PyArg_ParseTupleAndKeywords( args, kwds, "s", kwdlist, &DemonID ) )
        return -1;

    for ( int i = 0; i < NumberOfSessions; ++i )
    {
        if ( DemonSessions[ i ].Name.compare( DemonID ) == 0 )
        {
            /* seems like we are trying to use an 3rd party agent. */
            if ( DemonSessions[ i ].MagicValue != DemonMagicValue )
            {
                spdlog::error( "[PyError] specified id is not a demon agent" );
                PyErr_SetString( PyExc_TypeError, "specified id is not a demon agent" );
                return -1;
            }

            AllocMov( self->Listener, DemonSessions[ i ].Listener.toStdString().c_str(), DemonSessions[ i ].Listener.size() );
            AllocMov( self->DemonID, DemonSessions[ i ].Name.toStdString().c_str(), DemonSessions[ i ].Name.size() );
            AllocMov( self->ExternalIP, DemonSessions[ i ].External.toStdString().c_str(), DemonSessions[ i ].External.size() );
            AllocMov( self->InternalIP, DemonSessions[ i ].Internal.toStdString().c_str(), DemonSessions[ i ].Internal.size() );
            AllocMov( self->User, DemonSessions[ i ].User.toStdString().c_str(), DemonSessions[ i ].User.size() );
            AllocMov( self->Computer, DemonSessions[ i ].Computer.toStdString().c_str(), DemonSessions[ i ].Computer.size() );
            AllocMov( self->Domain, DemonSessions[ i ].Domain.toStdString().c_str(), DemonSessions[ i ].Domain.size() );
            AllocMov( self->OS, DemonSessions[ i ].OS.toStdString().c_str(), DemonSessions[ i ].OS.size() );
            AllocMov( self->OSBuild, DemonSessions[ i ].OSBuild.toStdString().c_str(), DemonSessions[ i ].OSBuild.size() );
            AllocMov( self->OSArch, DemonSessions[ i ].OSArch.toStdString().c_str(), DemonSessions[ i ].OSArch.size() );
            AllocMov( self->ProcessName, DemonSessions[ i ].Process.toStdString().c_str(), DemonSessions[ i ].Process.size() );
            AllocMov( self->ProcessID, DemonSessions[ i ].PID.toStdString().c_str(), DemonSessions[ i ].PID.size() );
            AllocMov( self->ProcessArch, DemonSessions[ i ].Arch.toStdString().c_str(), DemonSessions[ i ].Arch.size() );

            self->CONSOLE_INFO  = 1;
            self->CONSOLE_ERROR = 2;
            self->CONSOLE_TASK  = 3;
        }
    }

    return 0;
}

// Methods

// Demon.shell( TaskID: str, ShellCommands: str )
PyObject* DemonClass_Shell( PPyDemonClass self, PyObject *args )
{
    char* TaskID    = NULL;
    char* ShellArgs = NULL;

    if ( ! PyArg_ParseTuple( args, "ss", &TaskID, &ShellArgs ) )
        return NULL;

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            // Sessions.InteractedWidget->DemonCommands->Execute.Spawn( TaskID, R"(C:\Windows\System32\cmd.exe \c )" + QString( ShellArgs ) );
            break;
        }
    }

    Py_RETURN_NONE;
}

// Demon.InlineExecute( TaskID: str, EntryFunc: str, Path: str, Args: str, Threaded: bool )
PyObject* DemonClass_InlineExecute( PPyDemonClass self, PyObject *args )
{
    spdlog::debug( "[PyApi] Demon::InlineExecute" );

    char*     TaskID     = nullptr;
    char*     EntryFunc  = nullptr;
    char*     Path       = nullptr;
    PyObject* PyArgBytes = nullptr;
    auto      Flags      = QString();
    PyObject* Threaded   = nullptr;

    if ( ! PyArg_ParseTuple( args, "sssSO", &TaskID, &EntryFunc, &Path, &PyArgBytes, &Threaded ) )
        return nullptr;

    if ( PyObject_IsTrue( Threaded ) == true )
    {
        Flags = "threaded";
        spdlog::debug( "execute object file in threaded" );
    }
    else
    {
        Flags = "non-threaded";
        spdlog::debug( "execute object file in non-threaded" );
    }

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            if ( FileRead( Path ) == nullptr )
            {
                Sessions.InteractedWidget->AppendRaw();
                Sessions.InteractedWidget->TaskError( "Failed to open object file path: " + QString( Path ) );
            }
            else
            {
                auto ArgSize       = PyBytes_GET_SIZE( PyArgBytes );
                auto ObjArgs       = PyBytes_AS_STRING( PyArgBytes );
                auto ArgsByteArray = QByteArray( ObjArgs, ArgSize );

                Sessions.InteractedWidget->DemonCommands->Execute.InlineExecute( ( char* ) TaskID, ( char* ) EntryFunc, ( char* ) Path, ArgsByteArray, Flags );
            }

            break;
        }
    }

    Py_RETURN_NONE;
}

PyObject* DemonClass_InlineExecuteGetOutput( PPyDemonClass self, PyObject *args )
{
    spdlog::debug( "[PyApi] Demon::InlineExecuteGetOutput" );

    char*     TaskID     = nullptr;
    char*     EntryFunc  = nullptr;
    char*     Path       = nullptr;
    PyObject* PyArgBytes = nullptr;
    auto      Flags      = QString();
    PyObject* Callback   = nullptr;

    if ( ! PyArg_ParseTuple( args, "OssS", &Callback, &EntryFunc, &Path, &PyArgBytes ) )
        return nullptr;

    // InlineExecuteGetOutput only works in "non-threaded" mode
    // this is to avoid "RequestID" mixups
    Flags = "non-threaded";

    if ( ! PyCallable_Check( Callback ) )
    {
        spdlog::error( "The callback is not callable" );
        return nullptr;
    }

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            if ( FileRead( Path ) == nullptr )
            {
                Sessions.InteractedWidget->AppendRaw();
                Sessions.InteractedWidget->TaskError( "Failed to open object file path: " + QString( Path ) );
            }
            else
            {
                auto ArgSize       = PyBytes_GET_SIZE( PyArgBytes );
                auto ObjArgs       = PyBytes_AS_STRING( PyArgBytes );
                auto ArgsByteArray = QByteArray( ObjArgs, ArgSize );

                // create a new TaskID
                auto TaskID = QString( Util::gen_random( 8 ).c_str() );

                // save it the TaskID and the callback function
                Sessions.TaskIDToPythonCallbacks.insert(pair<QString, PyObject*>(TaskID, Callback));
                Py_XINCREF(Callback);

                Sessions.InteractedWidget->DemonCommands->Execute.InlineExecuteGetOutput( ( char* ) TaskID.toStdString().c_str(), ( char* ) EntryFunc, ( char* ) Path, ArgsByteArray, Flags );

                return PyUnicode_FromString( TaskID.toStdString().c_str() );
            }

            break;
        }
    }

    Py_RETURN_NONE;
}

// Demon.DotnetInlineExecute( TaskID: str, Path: str, Args: str )
PyObject* DemonClass_DotnetInlineExecute( PPyDemonClass self, PyObject *args )
{
    char*   TaskID    = NULL;
    char*   Path      = NULL;
    char*   Arguments = NULL;

    if ( ! PyArg_ParseTuple( args, "sss", &TaskID, &Path, &Arguments ) )
        return NULL;

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            Sessions.InteractedWidget->DemonCommands->Execute.AssemblyInlineExecute( TaskID, Path, Arguments );
            break;
        }
    }

    Py_RETURN_NONE;
}

// Demon.DllInject( TaskID: str, Pid: str, DllPath: str, DllArgs: str )
PyObject* DemonClass_DllInject( PPyDemonClass self, PyObject *args )
{
    char* TaskID  = NULL;
    char* Pid     = NULL;
    char* DllPath = NULL;
    char* DllArgs = NULL;

    if ( ! PyArg_ParseTuple( args, "ssss", &TaskID, &Pid, &DllPath, &DllArgs ) )
        return NULL;

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            Sessions.InteractedWidget->DemonCommands->Execute.DllInject( TaskID, Pid, DllPath, DllArgs );
            break;
        }
    }

    Py_RETURN_NONE;
}

// Demon.DllInject( TaskID: str, DllPath: str, DllArgs: str )
PyObject* DemonClass_DllSpawn( PPyDemonClass self, PyObject *args )
{
    char* TaskID        = NULL;
    char* DllPath       = NULL;
    char* DllArgs       = NULL;
    int   ArgSize       = 0;
    auto  ArgsByteArray = QByteArray();

    if ( ! PyArg_ParseTuple( args, "ssO", &TaskID, &DllPath, &DllArgs ) )
        return NULL;

    ArgSize       = PyBytes_GET_SIZE( DllArgs );
    DllArgs       = PyBytes_AS_STRING( DllArgs );
    ArgsByteArray = QByteArray( DllArgs, ArgSize );

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            if ( FileRead( DllPath ) == nullptr )
            {
                Sessions.InteractedWidget->AppendRaw();
                Sessions.InteractedWidget->TaskError( "Failed to open dll path: " + QString( DllPath ) );
            }
            else
            {
                Sessions.InteractedWidget->DemonCommands->Execute.DllSpawn( TaskID, DllPath, ArgsByteArray );
            }

            break;
        }
    }

    Py_RETURN_NONE;
}


// Demon.ProcessCreate( TaskID: str App: str, Cmdline: str, Suspended: bool, Piped: bool, Verbose: bool )
PyObject* DemonClass_ProcessCreate( PPyDemonClass self, PyObject *args )
{
    PCHAR     TaskID    = nullptr;
    PCHAR     App       = nullptr;
    PCHAR     CmdLine   = nullptr;
    PyObject* Suspended = nullptr;
    PyObject* Piped     = nullptr;
    PyObject* Verbose   = nullptr;
    auto      ProcArg   = QString();

    if ( ! PyArg_ParseTuple( args, "sssOOO", &TaskID, &App, &CmdLine, &Suspended, &Piped, &Verbose ) )
        Py_RETURN_NONE;

    if ( PyObject_IsTrue( Suspended ) )
        ProcArg += "4";
    else
        ProcArg += "0";

    if ( ! QString( App ).isEmpty() )
        ProcArg += ";" + QString( App );
    else
        ProcArg += ";";

    if ( PyObject_IsTrue( Verbose ) )
        ProcArg += ";TRUE";
    else
        ProcArg += ";FALSE";

    if ( PyObject_IsTrue( Piped ) )
        ProcArg += ";TRUE";
    else
        ProcArg += ";FALSE";

    ProcArg += ";" + QString( CmdLine ).toUtf8().toBase64();

    for ( auto& Sessions : HavocX::Teamserver.Sessions )
    {
        if ( Sessions.Name.compare( self->DemonID ) == 0 )
        {
            Sessions.InteractedWidget->DemonCommands->Execute.ProcModule( TaskID, 4, ProcArg );
            break;
        }
    }

    Py_RETURN_NONE;
}

// Other Methods
PyObject* DemonClass_ConsoleWrite( PPyDemonClass self, PyObject *args )
{
    u32     Type    = 0;
    char*   Message = NULL;

    if( ! PyArg_ParseTuple( args, "is", &Type, &Message ) )
        Py_RETURN_NONE;

    for ( auto& d : HavocX::Teamserver.Sessions )
    {
        if ( d.Name.compare( self->DemonID ) == 0 )
        {
            if ( Type == self->CONSOLE_INFO )
            {
                d.InteractedWidget->DemonCommands->BufferedMessages << Util::ColorText::Green( "[+]" ) + " " + QString( Message );
                break;
            }
            else if ( Type == self->CONSOLE_ERROR )
            {
                d.InteractedWidget->DemonCommands->BufferedMessages << Util::ColorText::Red( "[!]" ) + " " + QString( Message );
                break;
            }
            else if ( Type == self->CONSOLE_TASK )
            {
                auto TaskID = QString( Util::gen_random( 8 ).c_str() );

                d.InteractedWidget->DemonCommands->CommandTaskInfo[ TaskID ] = Message;

                return PyUnicode_FromString( TaskID.toStdString().c_str() );
            }
        }
    }

    Py_RETURN_NONE;
}
