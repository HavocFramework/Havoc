
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <structmember.h>

#include <Havoc/PythonApi/PyAgentClass.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <Util/ColorText.h>

PyMemberDef PyAgentClass_members[] = {

        { "CONSOLE_INFO",   T_INT, offsetof( PyAgentClass, CONSOLE_INFO ),   0, "Console message type info" },
        { "CONSOLE_ERROR",  T_INT, offsetof( PyAgentClass, CONSOLE_ERROR ),  0, "Console message type error" },
        { "CONSOLE_TASK",   T_INT, offsetof( PyAgentClass, CONSOLE_TASK ),   0, "Console message type task" },

        { NULL },
};

PyMethodDef PyAgentClass_methods[] = {

        { "ConsoleWrite", ( PyCFunction ) AgentClass_ConsoleWrite, METH_VARARGS, "Prints messages to the demon sessions console" },
        { "Command",      ( PyCFunction ) AgentClass_Command,      METH_VARARGS, "Send a command to the agent" },

        { NULL },
};

PyTypeObject PyAgentClass_Type = {
        PyVarObject_HEAD_INIT( &PyType_Type, 0 )

        "havoc.Agent",                              /* tp_name */
        sizeof( PyAgentClass ),                     /* tp_basicsize */
        0,                                          /* tp_itemsize */
        ( destructor ) AgentClass_dealloc,          /* tp_dealloc */
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
        PyAgentClass_methods,                       /* tp_methods */
        PyAgentClass_members,                       /* tp_members */
        0,                                          /* tp_getset */
        0,                                          /* tp_base */
        0,                                          /* tp_dict */
        0,                                          /* tp_descr_get */
        0,                                          /* tp_descr_set */
        0,                                          /* tp_dictoffset */
        ( initproc ) AgentClass_init,               /* tp_init */
        0,                                          /* tp_alloc */
        AgentClass_new,                             /* tp_new */
};

void AgentClass_dealloc( PPyAgentClass self )
{
    Py_XDECREF( self->AgentID );

    Py_TYPE( self )->tp_free( ( PyObject* ) self );
}

PyObject* AgentClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds )
{
    PPyAgentClass self;

    self = ( PPyAgentClass ) PyType_Type.tp_alloc( type, 0 );

    return ( PyObject* ) self;
}

int AgentClass_init( PPyAgentClass self, PyObject *args, PyObject *kwds )
{
    PCHAR AgentID = nullptr;

    if ( PyType_Type.tp_init( ( PyObject* ) self, args, kwds ) < 0 )
        return -1;

    /* TODO: add keyword "Agent" to tell it what agent it should check for
     *       just in case. */
    if ( ! PyArg_ParseTuple( args, "s", &AgentID ) )
        return -1;

    for ( auto & Agent : HavocX::Teamserver.Sessions )
    {
        if ( Agent.Name.compare( AgentID ) == 0 )
        {
            AllocMov( self->AgentID, Agent.Name.toStdString().c_str(), Agent.Name.size() );

            self->CONSOLE_INFO  = 1;
            self->CONSOLE_ERROR = 2;
            self->CONSOLE_TASK  = 3;
        }
    }

    return 0;
}

PyObject* AgentClass_ConsoleWrite( PPyAgentClass self, PyObject *args )
{
    u32     Type    = 0;
    char*   Message = NULL;

    if( ! PyArg_ParseTuple( args, "is", &Type, &Message ) )
        Py_RETURN_NONE;

    for ( auto& d : HavocX::Teamserver.Sessions )
    {
        if ( d.Name.compare( self->AgentID ) == 0 )
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

PyObject* AgentClass_Command( PPyAgentClass self, PyObject *args )
{
    PCHAR TaskID     = NULL;
    PCHAR Name       = NULL;
    PCHAR CommandArg = NULL;
    auto  CommandLen = 0;
    auto  Command    = QByteArray();

    if ( ! PyArg_ParseTuple( args, "ssO", &TaskID, &Name, &CommandArg ) )
        Py_RETURN_NONE;
        
    CommandLen = PyBytes_GET_SIZE( CommandArg );
    CommandArg = PyBytes_AS_STRING( CommandArg );
    Command    = QByteArray( CommandArg, CommandLen );

    for ( auto& d : HavocX::Teamserver.Sessions )
    {
        if ( d.Name.compare( self->AgentID ) == 0 )
        {
            /* send command to agent handler */
            d.InteractedWidget->DemonCommands->Execute.AgentCommand( QMap<string, string>{
                    { "TaskID",      TaskID                           },
                    { "CommandLine", ""                               },
                    { "DemonID",     d.Name.toStdString()             },
                    { "Command",     Name                             },
                    { "CommandArg",  Command.toBase64().toStdString() },
            } );

            break;
        }
    }

    Py_RETURN_NONE;
}