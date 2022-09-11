#if !defined(HAVOC_GLOBAL_HPP)
#define HAVOC_GLOBAL_HPP

#include <QApplication>
#include <QMainWindow>
#include <QtNetwork/QTcpSocket>
#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QAction>
#include <QFormLayout>
#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QPushButton>
#include <QSpacerItem>
#include <QTabWidget>
#include <QWidget>
#include <QDialog>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QTcpServer>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QTextEdit>
#include <QTableWidget>

#include <string>
#include <map>
#include <iostream>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/bin_to_hex.h>

#include <Havoc/Service.hpp>
#include <Util/Base.hpp>

#include <UserInterface/Widgets/FileBrowser.hpp>

#pragma push_macro("slots")
#undef slots
#include <Python.h>
#pragma pop_macro("slots")

typedef uint32_t            u32;
typedef uint64_t            u64;

typedef char*               PCHAR;
typedef char                BYTE;
typedef void*               PVOID;
typedef void*               LPVOID;
typedef unsigned long int   UINT_PTR;

namespace HavocNamespace
{
    extern std::string Version;
    extern std::string CodeName;

    namespace Util
    {
        class ColorText;
        class StructPack;

        std::string base64_encode( const char* buf, unsigned int bufLen );
        std::string gen_random( const int len );

        typedef struct CredentialsItem
        {
            typedef struct PasswordTypes
            {
                static std::string Cleartext;
                static std::string Hashed;
            } PasswordTypes;

            typedef struct SourceTypes
            {
                static std::string Mimikatz;
                static std::string Hashdump;
                static std::string Manuel;
            } SourceTypes;

            int CredentialsID;
            std::string User;
            std::string Password;
            std::string Type;
            std::string Domain;
            std::string Source;
            std::string Added;

        } CredentialsItem;

        typedef struct RegisteredCommand
        {
            std::string     Module;
            std::string     Command;
            std::string     Help;
            u32             Behaviour;
            std::string     Usage;
            std::string     Example;
            void*           Function;
            // PyThreadState*  PythonState;
        } RegisteredCommand ;

        typedef struct ListenerItem
        {
            typedef struct ListenerProtocols
            {
                static std::string HTTPS;
                static std::string HTTP;
                static std::string SMB;
                static std::string External;
            } ListenerProtocols;

            typedef struct PayloadOptions
            {
                typedef struct DemonHTTP
                {
                    std::vector<std::string>    Hosts;
                    std::string                 HostStager;
                    std::string                 Port;
                    std::string                 HostHeader;
                    std::string                 HostRotation;
                } DemonHTTP;

                typedef struct DemonHTTPS {} DemonHTTPS;
                typedef struct DemonDNS {} DemonDNS;

            } PayloadOptions;

            std::string TeamserverID;
            std::string Name;
            std::string Protocol;
            std::string Host;
            std::string Port;
            std::string Connected;
            std::string Status;
            std::map<std::string, std::string> Options;
        } ListenerItem ;
    };

    namespace UserInterface
    {
        class HavocUI;
        class Themer;

        // Dialogs
        namespace Dialogs
        {
            namespace Gates
            {
                class MSOffice;
                class Dropper;
                class Stageless;
                class Staged;
            }

            class About;
            class Connect;
            class NewListener;
            class Preferences;
        }

        // Widgets
        namespace Widgets {
            class Chat;
            class SessionTable;
            class ListenersTable;
            class CredentialsTable;
            class TeamserverTabSession;
            class ProcessList;
            class PythonScriptInterpreter;
            class ScriptManager;
        }

        namespace SmallWidgets {
            class EventViewer;
            class Dashboard;
        }

    };
    namespace HavocSpace
    {
        struct Listener
        {
            static QString PayloadHTTPS;
            static QString PayloadHTTP;
            static QString PayloadSMB;
            static QString PayloadExternal;
        };

        class Packager;
        class DBManager;
        class Havoc;
    }

    extern HavocNamespace::HavocSpace::Havoc* HavocApplication;
};

namespace HavocNamespace
{
    class Connector;

    namespace UserInterface::Widgets
    {
        class DemonInteracted;
    }

    namespace HavocSpace
    {
        class DemonCommands;
    };

    namespace Util
    {
        typedef struct
        {
            QString  TeamserverID;

            QString  Name;
            uint64_t MagicValue;
            QString  External;
            QString  Internal;
            QString  Listener;
            QString  User;
            QString  Computer;
            QString  Domain;
            QString  OS;
            QString  OSBuild;
            QString  OSArch;
            QString  Process;
            QString  PID;
            QString  Arch;
            QString  First;
            QString  Last;
            QString  Elevated;
            QString  PivotParent;

            UserInterface::Widgets::DemonInteracted* InteractedWidget;
            UserInterface::Widgets::ProcessList*     ProcessList;
            FileBrowser*                             FileBrowser;

            void Export();
        } SessionItem;

        typedef struct
        {
            QString Name;
            QString Host;
            QString Port;
            QString User;
            QString Password;

            std::vector<ListenerItem>       Listeners;
            std::vector<SessionItem>        Sessions;
            std::vector<CredentialsItem>    Credentials;
            std::vector<RegisteredCommand>  RegisteredCommands;
            std::vector<ServiceAgent>       ServiceAgents;
            PyThreadState*                  PythonState;
            QStringList                     AddedCommands;
            QJsonDocument                   DemonConfig;

            UserInterface::Widgets::TeamserverTabSession* TabSession;
        } ConnectionInfo;
    };
}

// Global Instance
namespace HavocX
{
    extern HavocNamespace::Util::ConnectionInfo Teamserver;
    extern HavocNamespace::Connector*           Connector;
}

#endif