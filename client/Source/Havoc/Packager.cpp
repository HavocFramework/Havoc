#include <global.hpp>

#include <Havoc/Havoc.hpp>
#include <Havoc/Packager.hpp>
#include <Havoc/DemonCmdDispatch.h>
#include <Havoc/Connector.hpp>

#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/ScriptManager.h>

#include <Util/ColorText.h>
#include <Util/Base.hpp>

#include <sstream>

#include <QScrollBar>
#include <QByteArray>
#include <QJsonArray>
#include <QDir>

const int Util::Packager::InitConnection::Type      = 0x1;
const int Util::Packager::InitConnection::Success   = 0x1;
const int Util::Packager::InitConnection::Error     = 0x2;
const int Util::Packager::InitConnection::Login     = 0x3;

const int Util::Packager::Listener::Type            = 0x2;
const int Util::Packager::Listener::Add             = 0x1;
const int Util::Packager::Listener::Edit            = 0x2;
const int Util::Packager::Listener::Remove          = 0x3;
const int Util::Packager::Listener::Mark            = 0x4;
const int Util::Packager::Listener::Error           = 0x5;

const int Util::Packager::Chat::Type                = 0x4;
const int Util::Packager::Chat::NewMessage          = 0x1;
const int Util::Packager::Chat::NewListener         = 0x2;
const int Util::Packager::Chat::NewSession          = 0x3;
const int Util::Packager::Chat::NewUser             = 0x4;
const int Util::Packager::Chat::UserDisconnect      = 0x5;

const int Util::Packager::Gate::Type                = 0x5;
const int Util::Packager::Gate::Staged              = 0x1;
const int Util::Packager::Gate::Stageless           = 0x2;

const int Util::Packager::Session::Type             = 0x7;
const int Util::Packager::Session::NewSession       = 0x1;
const int Util::Packager::Session::Remove           = 0x2;
const int Util::Packager::Session::SendCommand      = 0x3;
const int Util::Packager::Session::ReceiveCommand   = 0x4;

const int Util::Packager::Service::Type             = 0x9;
const int Util::Packager::Service::AgentRegister    = 0x1;
const int Util::Packager::Service::ListenerRegister = 0x2;

const int Util::Packager::Teamserver::Type          = 0x10;
const int Util::Packager::Teamserver::Logger        = 0x1;
const int Util::Packager::Teamserver::Profile       = 0x2;

using HavocNamespace::UserInterface::Widgets::ScriptManager;

Util::Packager::PPackage Packager::DecodePackage( const QString& Package )
{
    auto FullPackage    = new Util::Packager::Package;
    auto PackageObject  = QJsonObject();
    auto JsonData       = QJsonDocument::fromJson( Package.toUtf8() );

    if ( JsonData.isEmpty() )
    {
        spdlog::critical( "Invalid json" );
        return nullptr;
    }

    if ( JsonData.isObject() )
    {
        PackageObject = JsonData.object();

        auto HeadObject = PackageObject[ "Head" ].toObject();
        auto BodyObject = PackageObject[ "Body" ].toObject();

        FullPackage->Head.Event = HeadObject[ "Event" ].toInt();
        FullPackage->Head.Time = HeadObject[ "Time" ].toString().toStdString();
        FullPackage->Head.User = HeadObject[ "User" ].toString().toStdString();

        FullPackage->Body.SubEvent = BodyObject[ "SubEvent" ].toInt();

        if ( BodyObject[ "Info" ].isObject() )
        {
            foreach( const QString& key, BodyObject[ "Info" ].toObject().keys() )
            {
                FullPackage->Body.Info[ key.toStdString() ] = BodyObject[ "Info" ].toObject().value( key ).toString().toStdString();
            }
        }

    }
    else
    {
        spdlog::critical("Is not an Object: {}", QJsonDocument(JsonData).toJson().toStdString());
    }

    return FullPackage;
}

QJsonDocument Packager::EncodePackage( Util::Packager::Package Package )
{
    auto JsonPackage = QJsonObject();
    auto Head        = QJsonObject();
    auto Body        = QJsonObject();
    auto Map         = QVariantMap();
    auto Iterator    = QMapIterator<string, string>( Package.Body.Info );

    while ( Iterator.hasNext() )
    {
        Iterator.next();
        Map.insert( Iterator.key().c_str(), Iterator.value().c_str() );
    }

    Head.insert( "Event", QJsonValue::fromVariant( Package.Head.Event ) );
    Head.insert( "User", QJsonValue::fromVariant( Package.Head.User.c_str() ) );
    Head.insert( "Time", QJsonValue::fromVariant( Package.Head.Time.c_str() ) );
    Head.insert( "OneTime", QJsonValue::fromVariant( Package.Head.OneTime.c_str() ) );

    Body.insert( "SubEvent", QJsonValue::fromVariant( Package.Body.SubEvent ) );
    Body.insert( "Info", QJsonValue::fromVariant( Map ) );

    JsonPackage.insert( "Body", Body );
    JsonPackage.insert( "Head", Head );

    return QJsonDocument( JsonPackage );
}


auto Packager::DispatchPackage( Util::Packager::PPackage Package ) -> bool
{
    switch ( Package->Head.Event )
    {
        case Util::Packager::InitConnection::Type:
            return DispatchInitConnection( Package );

        case Util::Packager::Listener::Type:
            return DispatchListener( Package );

        case Util::Packager::Chat::Type:
            return DispatchChat( Package );

        case Util::Packager::Gate::Type:
            return DispatchGate( Package );

        case Util::Packager::Session::Type:
            return DispatchSession( Package );

        case Util::Packager::Service::Type:
            return DispatchService( Package );

        case Util::Packager::Teamserver::Type:
            return DispatchTeamserver( Package );

        default:
            spdlog::info( "[PACKAGE] Event Id not found" );
            return false;
    }
}

bool Packager::DispatchInitConnection( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::InitConnection::Success:
        {
            if ( HavocApplication->ClientInitConnect )
            {
                if ( ! HavocApplication->HavocAppUI.isVisible() )
                {
                    HavocApplication->HavocAppUI.setupUi( HavocApplication->HavocMainWindow );
                    HavocApplication->HavocAppUI.setDBManager( HavocApplication->dbManager );
                }

                // add some "default" scripts
                if ( QDir( "client/Modules" ).exists( ) )
                {
                    ScriptManager::AddScript( "client/Modules/InvokeAssembly/invokeassembly.py" );
                    ScriptManager::AddScript( "client/Modules/PowerPick/powerpick.py" );
                    ScriptManager::AddScript( "client/Modules/SituationalAwareness/SituationalAwareness.py" );
                    ScriptManager::AddScript( "client/Modules/Domaininfo/Domaininfo.py" );
                    ScriptManager::AddScript( "client/Modules/Jump-exec/ScShell/scshell.py" );
                    ScriptManager::AddScript( "client/Modules/Jump-exec/Psexec/psexec.py" );
                }
                else
                {
                    spdlog::debug( "Modules folder does not exists" );
                }

                HavocApplication->Start();
            }
            else
            {
                HavocApplication->HavocAppUI.NewTeamserverTab( this->TeamserverName );
            }

            return true;
        }

        case Util::Packager::InitConnection::Error:
        {
            if ( Package->Body.Info[ "Message" ] == "" )
                MessageBox( "Teamserver Error", QString( "Couldn't connect to Teamserver:" + QString( Package->Body.Info[ "Message" ].c_str() ) ), QMessageBox::Critical );
            else
                MessageBox( "Teamserver Error", "Couldn't connect to Teamserver", QMessageBox::Critical );

            return true;
        }

        case 0x5:
        {
            auto TeamserverIPs = QString( Package->Body.Info[ "TeamserverIPs" ].c_str() );
            for ( auto& Ip : TeamserverIPs.split( ", " ) )
                HavocX::Teamserver.IpAddresses << Ip;

            HavocX::Teamserver.DemonConfig = QJsonDocument::fromJson( Package->Body.Info[ "Demon" ].c_str() );
        }

        default:
            return false;
    }
}

bool Packager::DispatchListener( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Listener::Add:
        {
            auto TeamserverTab = HavocX::Teamserver.TabSession;

            // check if this comes from the Teamserver or operator. if from operator then ignore it
            if ( ! Package->Head.User.empty() )
                return false;

            auto ListenerInfo = Util::ListenerItem {
                .Name     = Package->Body.Info[ "Name" ],
                .Protocol = Package->Body.Info[ "Protocol" ],
                .Status   = Package->Body.Info[ "Status" ],
            };

            if ( ListenerInfo.Protocol == Listener::PayloadHTTP.toStdString() )
            {
                auto Headers = QStringList();
                for ( auto& header : QString( Package->Body.Info[ "Headers" ].c_str() ).split( ", " ) )
                    Headers << header;

                auto Uris = QStringList();
                for ( auto& uri : QString( Package->Body.Info[ "Uris" ].c_str() ).split( ", " ) )
                    Uris << uri;

                auto Hosts = QStringList();
                for ( auto& host : QString( Package->Body.Info[ "Hosts" ].c_str() ).split( ", " ) )
                    Hosts << host;

                ListenerInfo.Info = Listener::HTTP {
                        .Hosts          = Hosts,
                        .HostBind       = Package->Body.Info[ "HostBind" ].c_str(),
                        .HostRotation   = Package->Body.Info[ "HostRotation" ].c_str(),
                        .Port           = Package->Body.Info[ "Port" ].c_str(),
                        .UserAgent      = Package->Body.Info[ "UserAgent" ].c_str(),
                        .Headers        = Headers,
                        .Uris           = Uris,
                        .HostHeader     = Package->Body.Info[ "HostHeader" ].c_str(),
                        .Secure         = Package->Body.Info[ "Secure" ].c_str(),

                        // proxy configuration
                        .ProxyEnabled   = Package->Body.Info[ "Proxy Enabled" ].c_str(),
                        .ProxyType      = Package->Body.Info[ "Proxy Type" ].c_str(),
                        .ProxyHost      = Package->Body.Info[ "Proxy Host" ].c_str(),
                        .ProxyPort      = Package->Body.Info[ "Proxy Port" ].c_str(),
                        .ProxyUsername  = Package->Body.Info[ "Proxy Username" ].c_str(),
                        .ProxyPassword  = Package->Body.Info[ "Proxy Password" ].c_str(),
                };

                if ( Package->Body.Info[ "Secure" ] == "true" )
                {
                    ListenerInfo.Protocol = Listener::PayloadHTTPS.toStdString();
                }
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadSMB.toStdString() )
            {
                ListenerInfo.Info = Listener::SMB {
                    .PipeName = Package->Body.Info[ "PipeName" ].c_str(),
                };
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadExternal.toStdString() )
            {
                ListenerInfo.Info = Listener::External {
                        .Endpoint = Package->Body.Info[ "Endpoint" ].c_str(),
                };
            }
            else
            {
                // We assume it's a service listener.
                auto found = false;

                for ( const auto& listener : HavocX::Teamserver.RegisteredListeners )
                {
                    if ( ListenerInfo.Protocol == listener[ "Name" ] )
                    {
                        found = true;

                        ListenerInfo.Info = Listener::Service {
                                { "Host", Package->Body.Info[ "Host" ].c_str() },
                                { "Port", Package->Body.Info[ "Port" ].c_str() },
                                { "Info", Package->Body.Info[ "Info" ].c_str() } // NOTE: this is json string.
                        };

                        break;
                    }
                }

                if ( ! found  )
                {
                    spdlog::error( "Listener protocol type not found: {} ", ListenerInfo.Protocol );

                    MessageBox(
                        "Listener Error",
                        QString( ( "Listener protocol type not found: {} " + ListenerInfo.Protocol ).c_str() ),
                        QMessageBox::Critical
                    );

                    return false;
                }
            }

            if ( TeamserverTab->ListenerTableWidget == nullptr )
            {
                TeamserverTab->ListenerTableWidget = new UserInterface::Widgets::ListenersTable;
                TeamserverTab->ListenerTableWidget->setupUi( new QWidget );
                TeamserverTab->ListenerTableWidget->TeamserverName = this->TeamserverName;
            }

            TeamserverTab->ListenerTableWidget->ListenerAdd( ListenerInfo );

            if ( ListenerInfo.Status.compare( "Online" ) == 0 )
            {
                auto MsgStr = "[" + Util::ColorText::Cyan( "*" ) + "]" + " Started " + Util::ColorText::Green( "\"" + QString( ListenerInfo.Name.c_str() ) + "\"" ) + " listener";
                auto Time   = QString( Package->Head.Time.c_str() );

                HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );

                spdlog::info( "Started \"{}\" listener", ListenerInfo.Name );
            }
            else if ( ListenerInfo.Status.compare( "Offline" ) == 0 )
            {
                if ( ! Package->Body.Info[ "Error" ].empty() )
                {
                    auto Error = QString( Package->Body.Info[ "Error" ].c_str() );
                    auto Name  = QString( ListenerInfo.Name.c_str() );

                    TeamserverTab->ListenerTableWidget->ListenerError( Name, Error );
                }
            }

            break;
        }

        case Util::Packager::Listener::Remove:
        {

            HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerRemove( Package->Body.Info[ "Name" ].c_str() );

            break;
        }

        case Util::Packager::Listener::Edit:
        {
            auto ListenerInfo = Util::ListenerItem {
                    .Name     = Package->Body.Info[ "Name" ],
                    .Protocol = Package->Body.Info[ "Protocol" ],
                    .Status   = Package->Body.Info[ "Status" ],
            };

            if ( ListenerInfo.Protocol == Listener::PayloadHTTP.toStdString() )
            {
                auto Headers = QStringList();
                for ( auto& header : QString( Package->Body.Info[ "Headers" ].c_str() ).split( ", " ) )
                    Headers << header;

                auto Uris = QStringList();
                for ( auto& uri : QString( Package->Body.Info[ "Uris" ].c_str() ).split( ", " ) )
                    Uris << uri;

                auto Hosts = QStringList();
                for ( auto& host : QString( Package->Body.Info[ "Hosts" ].c_str() ).split( ", " ) )
                    Hosts << host;


                ListenerInfo.Info = Listener::HTTP {
                        .Hosts          = Hosts,
                        .HostBind       = Package->Body.Info[ "HostBind" ].c_str(),
                        .HostRotation   = Package->Body.Info[ "HostRotation" ].c_str(),
                        .Port           = Package->Body.Info[ "Port" ].c_str(),
                        .UserAgent      = Package->Body.Info[ "UserAgent" ].c_str(),
                        .Headers        = Headers,
                        .Uris           = Uris,
                        .HostHeader     = Package->Body.Info[ "HostHeader" ].c_str(),
                        .Secure         = Package->Body.Info[ "Secure" ].c_str(),

                        .ProxyEnabled   = Package->Body.Info[ "Proxy Enabled" ].c_str(),
                        .ProxyType      = Package->Body.Info[ "Proxy Type" ].c_str(),
                        .ProxyHost      = Package->Body.Info[ "Proxy Host" ].c_str(),
                        .ProxyPort      = Package->Body.Info[ "Proxy Port" ].c_str(),
                        .ProxyUsername  = Package->Body.Info[ "Proxy Username" ].c_str(),
                        .ProxyPassword  = Package->Body.Info[ "Proxy Password" ].c_str(),
                };

                if ( Package->Body.Info[ "Secure" ] == "true" )
                {
                    ListenerInfo.Protocol = Listener::PayloadHTTPS.toStdString();
                }

            }
            else if ( ListenerInfo.Protocol == Listener::PayloadSMB.toStdString() )
            {
                ListenerInfo.Info = Listener::SMB {
                        .PipeName = Package->Body.Info[ "PipeName" ].c_str(),
                };
            }
            else if ( ListenerInfo.Protocol == Listener::PayloadExternal.toStdString() )
            {
                ListenerInfo.Info = Listener::External {
                        .Endpoint = Package->Body.Info[ "Endpoint" ].c_str(),
                };
            }

            HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerEdit( ListenerInfo );

            break;
        }

        case Util::Packager::Listener::Mark:
        {
            break;
        }

        case Util::Packager::Listener::Error:
        {
            auto Error = Package->Body.Info[ "Error" ];
            auto Name  = Package->Body.Info[ "Name" ];

            if ( Package->Head.User.compare( HavocX::Teamserver.User.toStdString() ) == 0 )
            {
                if ( ! Name.empty() )
                {
                    if ( ! Error.empty() )
                    {
                        MessageBox( "Listener Error", QString( Error.c_str() ), QMessageBox::Critical );
                        HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerError( QString( Name.c_str() ), QString( Error.c_str() ) );

                        auto MsgStr = "[" + Util::ColorText::Red( "-" ) + "]" + " Failed to start " + Util::ColorText::Green( "\"" + QString( Name.c_str() ) + "\"" ) + " listener: " + Util::ColorText::Red( Error.c_str() );
                        auto Time   = QString( Package->Head.Time.c_str() );

                        HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );
                    }
                }
            }
            else if ( Package->Head.User.empty() )
            {
                if ( ! Name.empty() )
                {
                    if ( ! Error.empty() )
                    {
                        HavocX::Teamserver.TabSession->ListenerTableWidget->ListenerError( QString( Name.c_str() ), QString( Error.c_str() ) );

                        auto MsgStr = "[" + Util::ColorText::Red( "-" ) + "]" + " Failed to start " + Util::ColorText::Green( "\"" + QString( Name.c_str() ) + "\"" ) + " listener: " + Util::ColorText::Red( Error.c_str() );
                        auto Time   = QString( Package->Head.Time.c_str() );

                        HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );
                    }
                }
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchChat( Util::Packager::PPackage Package)
{
    switch (Package->Body.SubEvent) {
        case Util::Packager::Chat::NewMessage:
        {
            auto TeamserverUser = HavocX::Teamserver.User;

            for ( const auto& e : Package->Body.Info.toStdMap() )
            {
                auto Time = QString( Package->Head.Time.c_str() );

                HavocX::Teamserver.TabSession->TeamserverChat->AddUserMessage( Time, string( e.first ).c_str(), QByteArray::fromBase64( string( e.second ).c_str() ) );
            }
            break;
        }

        case Util::Packager::Chat::NewListener:
        {
            break;
        }

        case Util::Packager::Chat::NewSession:
        {
            break;
        }

        case Util::Packager::Chat::NewUser:
        {
            auto user = QString( Package->Body.Info.toStdMap()[ "User" ].c_str() );
            auto Time = QString( Package->Head.Time.c_str() );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time,  "[" + Util::ColorText::Green( "+" ) + "] " + Util::ColorText::Green( user + " connected to teamserver" ) );

            break;
        }

        case Util::Packager::Chat::UserDisconnect:
        {
            auto user = QString( Package->Body.Info.toStdMap()[ "User" ].c_str() );
            auto Time = QString( Package->Head.Time.c_str() );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, "[" + Util::ColorText::Red( "-" ) + "] " + Util::ColorText::Red( user + " disconnected from teamserver" ) );

            break;
        }
    }
    return true;
}

bool Packager::DispatchGate( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Gate::Staged:
        {
            break;
        }

        case Util::Packager::Gate::Stageless:
        {

            if ( Package->Body.Info[ "PayloadArray" ].size() > 0 )
            {
                auto PayloadArray = QString( Package->Body.Info[ "PayloadArray" ].c_str() ).toLocal8Bit();
                auto FileName     = QString( Package->Body.Info[ "FileName" ].c_str() );

                HavocX::Teamserver.TabSession->PayloadDialog->ReceivedImplantAndSave( FileName, QByteArray::fromBase64( PayloadArray ) );
            }
            else if ( Package->Body.Info[ "MessageType" ].size() > 0 )
            {
                auto MessageType = QString( Package->Body.Info[ "MessageType" ].c_str() );
                auto Message     = QString( Package->Body.Info[ "Message" ].c_str() );

                HavocX::Teamserver.TabSession->PayloadDialog->addConsoleLog( MessageType, Message );
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchSession( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Session::NewSession:
        {
            auto TeamserverTab = HavocX::Teamserver.TabSession;
            auto MagicValue    = uint64_t( 0 );
            auto StringStream  = std::stringstream();

            StringStream << std::hex << Package->Body.Info[ "MagicValue" ].c_str();
            StringStream >> MagicValue;

            auto Agent = Util::SessionItem {
                    .Name        = Package->Body.Info[ "NameID" ].c_str(),
                    .MagicValue  = MagicValue,
                    .External    = Package->Body.Info[ "ExternalIP" ].c_str(),
                    .Internal    = Package->Body.Info[ "InternalIP" ].c_str(),
                    .Listener    = Package->Body.Info[ "Listener" ].c_str(),
                    .User        = Package->Body.Info[ "Username" ].c_str(),
                    .Computer    = Package->Body.Info[ "Hostname" ].c_str(),
                    .Domain      = Package->Body.Info[ "DomainName" ].c_str(),
                    .OS          = Package->Body.Info[ "OSVersion" ].c_str(),
                    .OSBuild     = Package->Body.Info[ "OSBuild" ].c_str(),
                    .OSArch      = Package->Body.Info[ "OSArch" ].c_str(),
                    .Process     = Package->Body.Info[ "ProcessName" ].c_str(),
                    .PID         = Package->Body.Info[ "ProcessPID" ].c_str(),
                    .Arch        = Package->Body.Info[ "ProcessArch" ].c_str(),
                    .First       = Package->Body.Info[ "FirstCallIn" ].c_str(),
                    .Last        = QString( Package->Body.Info[ "LastCallIn" ].c_str() ).split(" ")[ 1 ],
                    .Elevated    = Package->Body.Info[ "Elevated" ].c_str(),
                    .PivotParent = Package->Body.Info[ "PivotParent" ].c_str(),
                    .Marked      = Package->Body.Info[ "Active" ].c_str(),
            };

            if ( Agent.Marked == "true" )
            {
                Agent.Marked = "Alive";
            }
            else if ( Agent.Marked == "false" )
            {
                Agent.Marked = "Dead";
            }

            for ( auto& session : HavocX::Teamserver.Sessions )
                if ( session.Name.compare( Agent.Name ) == 0 )
                    return false;

            TeamserverTab->SessionTableWidget->NewSessionItem( Agent );
            TeamserverTab->LootWidget->AddSessionSection( Agent.Name );

            auto Time    = QString( Package->Head.Time.c_str() );
            auto Message = "[" + Util::ColorText::Cyan( "*" ) + "]" + " Initialized " + Util::ColorText::Cyan( Agent.Name ) + " :: " + Util::ColorText::Yellow( Agent.User + "@" + Agent.Internal ) + Util::ColorText::Cyan( " (" ) + Util::ColorText::Red( Agent.Computer ) + Util::ColorText::Cyan( ")" );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, Message );

            break;
        }

        case Util::Packager::Session::SendCommand:
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name.compare( Package->Body.Info[ "DemonID" ].c_str() ) == 0 )
                {
                    auto AgentType = QString( Package->Body.Info[ "AgentType" ].c_str() );

                    if ( ! Package->Body.Info[ "CommandLine" ].empty() )
                    {
                        auto TaskID = QString( Package->Body.Info[ "TaskID" ].c_str() );

                        if ( AgentType.isEmpty() )
                            AgentType = "Demon";

                        Session.InteractedWidget->DemonCommands->Prompt = QString (
                                Util::ColorText::Comment( QString( Package->Head.Time.c_str() ) + " [" + QString( Package->Head.User.c_str() ) + "]" ) +
                                " " + Util::ColorText::UnderlinePink( AgentType ) +
                                Util::ColorText::Cyan(" » ") + QString( Package->Body.Info[ "CommandLine" ].c_str() )
                        );

                        if ( ! Package->Body.Info[ "TaskMessage" ].empty() )
                        {
                            Session.InteractedWidget->DemonCommands->CommandTaskInfo[ TaskID ] = Package->Body.Info[ "TaskMessage" ].c_str();
                        }
                        else
                        {
                            Session.InteractedWidget->AppendRaw();
                            Session.InteractedWidget->AppendRaw( Session.InteractedWidget->DemonCommands->Prompt );
                        }

                        Session.InteractedWidget->lineEdit->AddCommand( QString( Package->Body.Info[ "CommandLine" ].c_str() ) );
                        Session.InteractedWidget->DemonCommands->DispatchCommand( false, TaskID, Package->Body.Info[ "CommandLine" ].c_str() );
                    }
                }
            }
            break;
        }

        case Util::Packager::Session::ReceiveCommand:
        {
            for ( auto & Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name.compare( Package->Body.Info[ "DemonID" ].c_str() ) == 0 )
                {
                    if ( Session.Marked.compare( "Dead" ) == 0 )
                    {
                        auto Package = new Util::Packager::Package;

                        Package->Head = Util::Packager::Head_t {
                                .Event= Util::Packager::Session::Type,
                                .User = HavocX::Teamserver.User.toStdString(),
                                .Time = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
                        };

                        for ( int i = 0; i < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
                        {
                            auto Row = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                            if ( Row.compare( Session.Name ) == 0 )
                            {
                                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( WinVersionIcon( Session.OS, true ) );

                                for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                                {
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Foreground ) );
                                }
                            }
                        }

                        Package->Body = Util::Packager::Body_t {
                                .SubEvent = 0x5,
                                .Info = {
                                    { "AgentID", Session.Name.toStdString() },
                                    { "Marked",  "Alive" },
                                }
                        };

                        Session.Marked = "Alive";

                        HavocX::Connector->SendPackage( Package );
                    }

                    Session.InteractedWidget->DemonCommands->OutputDispatch.DemonCommandInstance = Session.InteractedWidget->DemonCommands;

                    int CommandID = QString( Package->Body.Info[ "CommandID" ].c_str() ).toInt();
                    auto Output   = QString( Package->Body.Info[ "Output" ].c_str() );

                    switch ( CommandID )
                    {
                        case 0x80:

                            if ( QByteArray::fromBase64( Output.toLocal8Bit() ).length() > 5 )
                            {
                                Session.InteractedWidget->DemonCommands->OutputDispatch.MessageOutput(
                                        Output,
                                        QString( Package->Head.Time.c_str() )
                                );
                                Session.InteractedWidget->Console->verticalScrollBar()->setValue(
                                        Session.InteractedWidget->Console->verticalScrollBar()->maximum()
                                );
                            }

                            break;

                        case ( int ) Commands::CALLBACK:
                        {
                            auto LastTime     = QString( QByteArray::fromBase64( Output.toLocal8Bit() ) );
                            auto LastTimeJson = QJsonDocument::fromJson( LastTime.toLocal8Bit() );

                            HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue(
                                Package->Body.Info["DemonID"].c_str(), 8, LastTimeJson["Output"].toString()
                            );
                            break;
                        }

                        default:
                            spdlog::error( "[PACKAGE] Command not found" );
                            break;
                    }

                    break;
                }
            }

            break;
        }

        case Util::Packager::Session::Remove:
        {
            break;
        }

        case 0x5:
        {
            auto AgentID = Package->Body.Info[ "AgentID" ];
            auto Marked  = Package->Body.Info[ "Marked" ];

            for ( int i = 0; i < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
            {
                auto Row = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                if ( Row.compare( QString( AgentID.c_str() ) ) == 0 )
                {
                    if ( Marked.compare( "Alive" ) == 0 )
                    {
                        for ( auto& session : HavocX::Teamserver.Sessions )
                        {
                            if ( session.Name.toStdString() == AgentID )
                            {
                                auto Icon = ( session.Elevated.compare( "true" ) == 0 ) ?
                                        WinVersionIcon( session.OS, true ) :
                                        WinVersionIcon( session.OS, false );

                                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( Icon );
                            }
                        }

                        for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                        {
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Foreground ) );
                        }
                    }
                    else if ( Marked.compare( "Dead" ) == 0 )
                    {
                        HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );

                        for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                        {
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
                            HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
                        }
                    }
                }
            }

            break;
        }
    }
    return true;
}

bool Packager::DispatchService( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Service::AgentRegister:
        {
            auto JsonObject     = QJsonDocument::fromJson( Package->Body.Info[ "Agent" ].c_str() ).object();
            auto OSArray        = QStringList();
            auto Arch           = QStringList();
            auto Formats        = std::vector<AgentFormat>();
            auto Commands       = std::vector<AgentCommands>();
            auto MagicValue     = uint64_t( 0 );
            auto StringStream   = std::stringstream();

            for ( const auto& item : JsonObject[ "Arch" ].toArray() )
                Arch << item.toString();

            for ( const auto& item : JsonObject[ "Formats" ].toArray() )
            {
                Formats.push_back( AgentFormat {
                        .Name = item.toObject()[ "Name" ].toString(),
                        .Extension = item.toObject()[ "Extension" ].toString(),
                } );
            }

            for ( const auto& item : JsonObject[ "SupportedOS" ].toArray() )
                OSArray << item.toString();

            for ( const auto& command : JsonObject[ "Commands" ].toArray() )
            {
                auto Mitr   = QStringList();
                auto Params = std::vector<CommandParam>();

                for ( const auto& param : command.toObject()[ "Params" ].toArray() )
                {
                    Params.push_back( CommandParam {
                        .Name       = param.toObject()[ "Name" ].toString(),
                        .IsFilePath = param.toObject()[ "IsFilePath" ].toBool(),
                        .IsOptional = param.toObject()[ "IsOptional" ].toBool(),
                    } );
                }

                for ( const auto& i : command.toObject()[ "Mitr" ].toArray() )
                    Mitr << i.toString();

                Commands.push_back( AgentCommands{
                    .Name        = command.toObject()[ "Name" ].toString(),
                    .Description = command.toObject()[ "Description" ].toString(),
                    .Help        = command.toObject()[ "Help" ].toString(),
                    .NeedAdmin   = command.toObject()[ "NeedAdmin" ].toBool(),
                    .Mitr        = Mitr,
                    .Params      = Params,
                    .Anonymous   = command.toObject()[ "Anonymous" ].toBool(),
                } );
            }

            StringStream << std::hex << JsonObject[ "MagicValue" ].toString().toStdString();
            StringStream >> MagicValue;

            HavocX::Teamserver.ServiceAgents.push_back( ServiceAgent{
                .Name           = JsonObject[ "Name" ].toString(),
                .Description    = JsonObject[ "Description" ].toString(),
                .Version        = JsonObject[ "Version" ].toString(),
                .MagicValue     = MagicValue,
                .Arch           = Arch,
                .Formats        = Formats,
                .SupportedOS    = OSArray,
                .Commands       = Commands,
                .BuildingConfig = QJsonDocument( JsonObject[ "BuildingConfig" ].toObject() ),
            } );

            spdlog::info( "Added service agent to client: {}", JsonObject[ "Name" ].toString().toStdString() );

            return true;
        }

        case Util::Packager::Service::ListenerRegister:
        {
            auto listener = json::parse( Package->Body.Info[ "Listener" ].c_str() );

            HavocX::Teamserver.RegisteredListeners.push_back( listener );

            spdlog::info( "Added service listener to client: {}", listener[ "Name" ].get<std::string>() );

            return true;
        }

        default: break;
    }
    return false;
}

bool Packager::DispatchTeamserver( Util::Packager::PPackage Package )
{
    switch ( Package->Body.SubEvent )
    {
        case Util::Packager::Teamserver::Logger:
        {
            auto Text = QString( Package->Body.Info[ "Text" ].c_str() );

            if ( HavocX::Teamserver.TabSession->Teamserver == nullptr )
            {
                HavocX::Teamserver.TabSession->Teamserver = new Teamserver;
                HavocX::Teamserver.TabSession->Teamserver->setupUi( new QDialog );
            }

            HavocX::Teamserver.TabSession->Teamserver->AddLoggerText( Text );
        }

        case Util::Packager::Teamserver::Profile:
        {

        }
    }
}


void Packager::setTeamserver( QString Name )
{
    this->TeamserverName = Name;
}
