#ifndef HAVOC_DEMONCMDDISPATCH_H
#define HAVOC_DEMONCMDDISPATCH_H

#include <global.hpp>

#include <QStringList>
#include <QFile>

using namespace std;
using namespace HavocNamespace;

#define SEND( f ) \
    if ( Send ) f; return true;

#define CONSOLE_ERROR( x )                          \
    DemonConsole->Console->append( "" );            \
    DemonConsole->Console->append( this->Prompt );  \
    DemonConsole->TaskError( x );

#define CONSOLE_INFO( x ) \
    DemonConsole->TaskInfo( Send, TaskID, x );

enum class Commands {
    CHECKIN                 = 100,
    CALLBACK                = 10,
    CONSOLE_MESSAGE         = 0x80,
    BOF_CALLBACK            = 0x81,
    SLEEP                   = 11,
    PROC_LIST               = 12,
    FS                      = 15,
    INLINE_EXECUTE          = 20,
    JOB                     = 21,
    INJECT_DLL              = 22,
    INJECT_SHELLCODE        = 24,
    INJECT_DLL_SPAWN        = 26,
    TOKEN                   = 40,
    PROC                    = 0x1010,
    INLINE_EXECUTE_ASSEMBLY = 0x2001,
    ASSEMBLY_LIST_VERSIONS 	= 0x2003,
    NET                     = 2100,
    CONFIG                  = 2500,
    SCREENSHOT              = 2510,
    PIVOT                   = 2520,
    TRANSFER                = 2530,
    SOCKET                  = 2540,
    KERBEROS                = 2550,

    OUTPUT  = 90,
    ERROR   = 91,
    EXIT    = 92,
};

class DispatchOutput
{
public:
    HavocSpace::DemonCommands* DemonCommandInstance;

    auto MessageOutput( QString JsonString, const QString& Date ) const -> void;
};

class CommandExecute
{
public:
    HavocSpace::DemonCommands* DemonCommandInstance;

    auto Exit( QString TaskID, QString Methode ) -> void;
    auto Sleep( QString TaskID, QString seconds ) -> void;
    auto Checkin( QString TaskID ) -> void;
    auto Job( QString TaskID, QString SubCommand, QString Argument ) -> void;
    auto FS( const QString& TaskID, QString SubCommand, QString Arguments ) -> void;
    auto Transfer( const QString& TaskID, QString SubCommand, QString FileID ) -> void;
    auto Socket( const QString& TaskID, QString SubCommand, QString Params ) -> void;
    auto Luid( const QString& TaskID ) -> void;
    auto Klist( const QString &TaskID, QString Argument1, QString Argument2 ) -> void;
    auto Purge( const QString &TaskID, QString Argument ) -> void;
    auto Ptt( const QString &TaskID, QString Ticket, QString Luid ) -> void;

    auto ProcModule( QString TaskID, int SubCommand, QString Args ) -> void;
    auto ProcList( QString TaskID, bool FromProcessManager ) -> void;

    auto ShellcodeInject( QString TaskID, QString InjectionTechnique, QString TargetPID, QString TargetArch, QString Path, QString Arguments ) const -> void;
    auto ShellcodeSpawn( QString TaskID, QString InjectionTechnique, QString TargetArch, QString Path, QString Arguments ) -> void;
    auto ShellcodeExecute( QString TaskID, QString InjectionTechnique, QString TargetArch, QString Path, QString Arguments ) -> void;

    auto DllInject( QString TaskID, QString TargetPID, QString Path, QString Params ) -> void;
    auto DllSpawn( QString TaskID, QString FilePath, QByteArray Args ) -> void;

    auto InlineExecute( QString TaskID, QString FunctionName, QString Path, QByteArray Args, QString Flags ) -> void;
    auto InlineExecuteGetOutput( QString TaskID, QString FunctionName, QString Path, QByteArray Args, QString Flags ) -> void;
    auto AssemblyInlineExecute( QString TaskID, QString Path, QString Args ) -> void;
    auto AssemblyListVersions( QString TaskID ) -> void;
    auto Net( QString TaskID, QString Command, QString Param ) -> void;
    auto Pivot( QString TaskID, QString Command, QString Param ) -> void;
    auto Token( QString TaskID, QString SubCommand, QString Arguments ) -> void;
    auto Config( const QString& TaskID, const QString& Key, const QString& Value ) -> void;
    auto Screenshot( const QString& TaskID ) -> void;
    auto Task( const QString& TaskID, const QString& Command ) -> void;

    auto AgentCommand( QMap<string, string> CommandData ) -> void;
};

class HavocSpace::DemonCommands
{

public:
    UserInterface::Widgets::DemonInteracted* DemonConsole = nullptr;

    QString         Teamserver;
    QString         DemonID;
    u64             MagicValue;
    QString         AgentTypeName;
    DispatchOutput  OutputDispatch;
    CommandExecute  Execute;
    QString         Prompt;
    /* Something the command scripts can write to */
    QStringList     BufferedMessages;

    typedef struct SubCommand
    {
        QString     CommandString;
        QString     Description;
        QString     Behavior;
        QString     NeedElevated;
        QStringList MitreTechniques; // TODO: finish this for all commands
        QString     Usage;
        QString     Example;
        QStringList Options;
    } SubCommand_t;

    typedef struct Command
    {
        QString     CommandString;
        QString     Description;
        QString     Behavior;
        QString     NeedElevated;
        QStringList MitreTechniques;
        QString     Usage;
        QString     Example;
        bool        Module;

        std::vector<SubCommand_t> SubCommands;
    } Command_t;

    static std::vector<Command_t>   DemonCommandList;
    QMap<QString, QString>          CommandInputList;
    QMap<QString, QString>          CommandTaskInfo;

    explicit DemonCommands();

    auto SetDemonConsole( UserInterface::Widgets::DemonInteracted* pInteracted ) -> void;
    auto DispatchCommand( bool Send, QString TaskID, const QString& commandline ) -> bool;
    auto PrintModuleCachedMessages() -> void;
};

#endif
