#include <Havoc/DemonCmdDispatch.h>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

#include <UserInterface/Widgets/DemonInteracted.h>

#include <Util/Base64.h>

#include <QFile>

// TODO: refactor this

auto NewPackageCommand( const QString& TeamserverName, Util::Packager::Body_t Body ) -> void
{
    auto Package = new Util::Packager::Package;
    auto Head = Util::Packager::Head_t {
        .Event   = Util::Packager::Session::Type,
        .User    = HavocX::Teamserver.User.toStdString(),
        .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
    };

    Package->Head = Head;
    Package->Body = Body;

    HavocX::Connector->SendPackage( Package );
}

auto CommandExecute::FS( const QString& TaskID, QString SubCommand, QString Arguments ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",        DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int> ( Commands::FS ) ).c_str() },
            { "SubCommand",     SubCommand.toStdString() },
            { "Arguments",      Arguments.toStdString() },
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Sleep( QString TaskID, QString seconds ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",        DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::SLEEP ) ).c_str() },
            { "Arguments",      seconds.toStdString()}
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Checkin( QString TaskID ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",        this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::CHECKIN ) ).c_str() },
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::ProcList( QString TaskID, bool FromProcessManager ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",        this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::PROC_LIST ) ).c_str() },

            { "FromProcessManager", FromProcessManager ? "true" : "false" },
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::InlineExecute( QString TaskID, QString FunctionName, QString Path, QByteArray Args, QString Flags ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[TaskID].toStdString() },
            { "DemonID",        this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::INLINE_EXECUTE ) ).c_str() },
            { "HasCallback",    "false"},

            { "FunctionName",   FunctionName.toStdString() },
            { "Binary",         Content.toBase64().toStdString() },
            { "Arguments",      Util::base64_encode( Args.toStdString().c_str(), Args.length() ) },
            { "Flags",          Flags.toStdString() },
         },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::InlineExecuteGetOutput( QString TaskID, QString FunctionName, QString Path, QByteArray Args, QString Flags ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[TaskID].toStdString() },
            { "DemonID",        this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::INLINE_EXECUTE ) ).c_str() },
            { "HasCallback",    "true"},

            { "FunctionName",   FunctionName.toStdString() },
            { "Binary",         Content.toBase64().toStdString() },
            { "Arguments",      Util::base64_encode( Args.toStdString().c_str(), Args.length() ) },
            { "Flags",          Flags.toStdString() },
         },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::AssemblyInlineExecute( QString TaskID, QString Path, QString Args ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",         TaskID.toStdString() },
            { "CommandLine",    DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",        this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",      to_string( static_cast<int>( Commands::INLINE_EXECUTE_ASSEMBLY ) ).c_str() },

            { "Binary",         Content.toBase64().toStdString() },
            { "Arguments",      Args.toStdString() },
        },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::AssemblyListVersions( QString TaskID ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",      TaskID.toStdString() },
            { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",   to_string( static_cast<int>( Commands::ASSEMBLY_LIST_VERSIONS ) ).c_str() },
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::ShellcodeInject( QString TaskID, QString InjectionTechnique, QString TargetPID, QString TargetArch, QString Path, QString Arguments = "" ) const -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",      TaskID.toStdString() },
            { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",   to_string( static_cast<int>( Commands::INJECT_SHELLCODE ) ).c_str() },
            { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

            { "Way",         "Inject" },
            { "Technique",   InjectionTechnique.toStdString() },
            { "Binary",      Content.toBase64().toStdString() },
            { "Arguments",   Arguments.toUtf8().toBase64().toStdString() },
            { "PID",         TargetPID.toStdString() },
            { "Arch",        TargetArch.toStdString() },
        },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::ShellcodeSpawn( QString TaskID, QString InjectionTechnique, QString TargetArch, QString Path, QString Arguments = "" ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",      TaskID.toStdString()},
            { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",   to_string(static_cast<int>(Commands::INJECT_SHELLCODE)).c_str() },
            { "CommandLine", DemonCommandInstance->CommandInputList[TaskID].toStdString() },

            { "Way",         "Spawn" },
            { "Technique",   InjectionTechnique.toStdString() },
            { "Binary",      Content.toBase64().toStdString() },
            { "Arguments",   Arguments.toUtf8().toBase64().toStdString() },
            { "Arch",        TargetArch.toStdString() },
        },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::ShellcodeExecute( QString TaskID, QString InjectionTechnique, QString TargetArch, QString Path, QString Arguments ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body    = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString()},
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
                { "CommandID",   to_string(static_cast<int>(Commands::INJECT_SHELLCODE)).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[TaskID].toStdString() },

                { "Way",         "Execute" },
                { "Technique",   InjectionTechnique.toStdString() },
                { "Binary",      Content.toBase64().toStdString() },
                { "Arguments",   Arguments.toUtf8().toBase64().toStdString() },
                { "Arch",        TargetArch.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::DllSpawn( QString TaskID, QString Path, QByteArray Args ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            {"TaskID",      TaskID.toStdString()},
            {"DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString()},
            {"CommandID",   to_string(static_cast<int>( Commands::INJECT_DLL_SPAWN ) ).c_str()},
            {"CommandLine", DemonCommandInstance->CommandInputList[TaskID].toStdString()},

            {"Binary",      Content.toBase64().toStdString() },
            {"Arguments",   Util::base64_encode( Args.toStdString().c_str(), Args.length() ) },
        },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Token( QString TaskID, QString SubCommand, QString Arguments ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[TaskID].toStdString() },
                    { "DemonID",     DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
                    { "CommandID",   to_string( static_cast<int>( Commands::TOKEN ) ).c_str() },

                    { "SubCommand",  SubCommand.toStdString() },
                    { "Arguments",   Arguments.toStdString() },
            }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::ProcModule( QString TaskID, int SubCommand, QString Args ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
                { "CommandID",   to_string( static_cast<int>( Commands::PROC ) ).c_str() },

                { "ProcCommand", to_string( SubCommand ).c_str() },
                { "Args",        Args.toStdString() },
            }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Exit( QString TaskID, QString Methode ) -> void
{
    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            { "TaskID",      TaskID.toStdString() },
            { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            { "CommandID",   to_string( static_cast<int>( Commands::EXIT ) ).c_str() },

            { "ExitMethod",  Methode.toStdString() },
        }
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::DllInject( QString TaskID, QString TargetPID, QString Path, QString Params ) -> void
{
    auto Content = FileRead( Path );
    if ( Content.isEmpty() ) return;

    auto Body = Util::Packager::Body_t {
        .SubEvent = Util::Packager::Session::SendCommand,
        .Info = {
            {"TaskID",      TaskID.toStdString() },
            {"DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
            {"CommandID",   to_string( static_cast<int>( Commands::INJECT_DLL ) ).c_str() },
            {"CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

            {"Binary",      Content.toBase64().toStdString() },
            {"Arguments",   Params.toStdString()},
            {"PID",         TargetPID.toStdString()},
        },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Config( const QString& TaskID, const QString& Key, const QString& Value ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( (int)Commands::CONFIG ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                { "ConfigKey",  Key.toStdString() },
                { "ConfigVal",  Value.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Screenshot( const QString &TaskID ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( ( int ) Commands::SCREENSHOT ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Net( QString TaskID, QString Command, QString Param ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( ( int ) Commands::NET ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                { "NetCommand",  Command.toStdString() },
                { "Param",       Param.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Pivot( QString TaskID, QString Command, QString Param ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( ( int ) Commands::PIVOT ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                { "Command",     Command.toStdString() },
                { "Param",       Param.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::AgentCommand( QMap<string, string> CommandData ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info     = CommandData,
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Job( QString TaskID, QString SubCommand, QString Argument ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( ( int ) Commands::JOB ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                { "Command",     SubCommand.toStdString() },
                { "Param",       Argument.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Task( const QString& TaskID, const QString& Command ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },
                { "CommandID",   "Teamserver" },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },
                { "Command",     Command.toStdString() },
            },
    };

    NewPackageCommand( this->DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Transfer( const QString &TaskID, QString SubCommand, QString Arguments ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                { "TaskID",      TaskID.toStdString() },
                { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                { "CommandID",   to_string( ( int ) Commands::TRANSFER ).c_str() },
                { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                { "Command",     SubCommand.toStdString() },
                { "FileID",      Arguments.toStdString() },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Socket( const QString &TaskID, QString SubCommand, QString Arguments ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                    { "CommandID",   to_string( ( int ) Commands::SOCKET ).c_str() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                    { "Command",     SubCommand.toStdString() },
                    { "Params",      Arguments.toStdString() },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Luid( const QString& TaskID ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                    { "CommandID",   to_string( ( int ) Commands::KERBEROS ).c_str() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                    { "Command",     "luid" },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Klist( const QString &TaskID, QString Argument1, QString Argument2 ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                    { "CommandID",   to_string( ( int ) Commands::KERBEROS ).c_str() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                    { "Command",     "klist" },

                    { "Argument1",   Argument1.toStdString() },
                    { "Argument2",   Argument2.toStdString() },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Purge( const QString &TaskID, QString Argument ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                    { "CommandID",   to_string( ( int ) Commands::KERBEROS ).c_str() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                    { "Command",     "purge" },

                    { "Argument",    Argument.toStdString() },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}

auto CommandExecute::Ptt( const QString &TaskID, QString Ticket, QString Luid ) -> void
{
    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Session::SendCommand,
            .Info = {
                    { "TaskID",      TaskID.toStdString() },
                    { "DemonID",     this->DemonCommandInstance->DemonConsole->SessionInfo.Name.toStdString() },

                    { "CommandID",   to_string( ( int ) Commands::KERBEROS ).c_str() },
                    { "CommandLine", DemonCommandInstance->CommandInputList[ TaskID ].toStdString() },

                    { "Command",     "ptt" },

                    { "Ticket",    Ticket.toStdString() },
                    { "Luid",      Luid.toStdString() },
            },
    };

    NewPackageCommand( DemonCommandInstance->Teamserver, Body );
}
