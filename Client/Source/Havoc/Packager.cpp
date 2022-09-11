#include "Include/Havoc/Havoc.hpp"
#include "Include/Havoc/Packager.hpp"
#include "Include/Havoc/DemonCmdDispatch.h"

#include "Include/UserInterface/Widgets/TeamserverTabSession.h"
#include "Include/UserInterface/SmallWidgets/EventViewer.hpp"
#include "Include/UserInterface/Widgets/DemonInteracted.h"

#include "Include/Util/ColorText.h"

#include <QScrollBar>
#include "Include/global.hpp"
#include <QByteArray>
#include <sstream>
#include <QJsonArray>

const int Util::Packager::InitConnection::Type      = 0x1;
const int Util::Packager::InitConnection::Success   = 0x1;
const int Util::Packager::InitConnection::Error     = 0x2;
const int Util::Packager::InitConnection::Login     = 0x3;

const int Util::Packager::Listener::Type            = 0x2;
const int Util::Packager::Listener::Add             = 0x1;
const int Util::Packager::Listener::Edit            = 0x2;
const int Util::Packager::Listener::Remove          = 0x3;
const int Util::Packager::Listener::SetOffline      = 0x4;
const int Util::Packager::Listener::SetOnline       = 0x5;

const int Util::Packager::Credentials::Type         = 0x3;
const int Util::Packager::Credentials::Add          = 0x1;
const int Util::Packager::Credentials::Edit         = 0x2;
const int Util::Packager::Credentials::Remove       = 0x3;

const int Util::Packager::Chat::Type                = 0x4;
const int Util::Packager::Chat::NewMessage          = 0x1;
const int Util::Packager::Chat::NewListener         = 0x2;
const int Util::Packager::Chat::NewSession          = 0x3;
const int Util::Packager::Chat::NewUser             = 0x4;
const int Util::Packager::Chat::UserDisconnect      = 0x5;

const int Util::Packager::Gate::Type                = 0x5;
const int Util::Packager::Gate::Staged              = 0x1;
const int Util::Packager::Gate::Stageless           = 0x2;

const int Util::Packager::HostFile::Type            = 0x6;
const int Util::Packager::HostFile::Add             = 0x1;
const int Util::Packager::HostFile::Remove          = 0x2;
const int Util::Packager::HostFile::SetOffline      = 0x3;
const int Util::Packager::HostFile::SetOnline       = 0x4;

const int Util::Packager::Session::Type             = 0x7;
const int Util::Packager::Session::NewSession       = 0x1;
const int Util::Packager::Session::Remove           = 0x2;
const int Util::Packager::Session::SendCommand      = 0x3;
const int Util::Packager::Session::ReceiveCommand   = 0x4;

const int Util::Packager::Service::Type             = 0x9;
const int Util::Packager::Service::AgentRegister    = 0x1;

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

        case Util::Packager::Credentials::Type:
            return DispatchCredentials( Package );

        case Util::Packager::Chat::Type:
            return DispatchChat( Package );

        case Util::Packager::Gate::Type:
            return DispatchGate( Package );

        case Util::Packager::HostFile::Type:
            return DispatchHostFile( Package );

        case Util::Packager::Session::Type:
            return DispatchSession( Package );

        case Util::Packager::Service::Type:
            return DispatchService( Package );

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
                QMessageBox::critical( nullptr, "Teamserver Error", string( "Couldn't connect to Teamserver: " + Package->Body.Info[ "Message" ] ).c_str() );
            else
                QMessageBox::critical( nullptr, "Teamserver Error", "Couldn't connect to Teamserver" );

            return true;
        }

        case 0x5:
        {
            spdlog::info( "Received demon profile" );
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

            if ( ! Package->Body.Info[ "Error" ].empty() )
            {
                spdlog::warn( "Listener \"{}\" error: {}", Package->Body.Info[ "Name" ], Package->Body.Info[ "Error" ] );

                auto ErrorMessage = QMessageBox();

                ErrorMessage.setWindowTitle( "Listener Error" );
                ErrorMessage.setIcon( QMessageBox::Critical );
                ErrorMessage.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );

                ErrorMessage.setText( "Failed to create " + QString( Package->Body.Info[ "Name" ].c_str() ) + ":" + QString( Package->Body.Info[ "Error" ].c_str() ) );
                ErrorMessage.exec();

                break;
            }

            auto ListenerInfo = Util::ListenerItem {
                .Name       = Package->Body.Info[ "Name" ],
                .Protocol   = Package->Body.Info[ "Protocol" ],
                .Host       = Package->Body.Info[ "Host" ],
                .Port       = Package->Body.Info[ "Port" ],
                .Connected  = Package->Body.Info[ "Connected" ],
                .Status     = "online",
            };

            if ( Package->Body.Info[ "Secure" ] == "true" )
            {
                ListenerInfo.Protocol = "Https";
            }

            if ( TeamserverTab->ListenerTableWidget == nullptr )
            {
                TeamserverTab->ListenerTableWidget = new UserInterface::Widgets::ListenersTable;
                TeamserverTab->ListenerTableWidget->setupUi( new QWidget );
                TeamserverTab->ListenerTableWidget->TeamserverName = this->TeamserverName;
            }

            TeamserverTab->ListenerTableWidget->NewListenerItem( ListenerInfo );

            auto MsgStr = "[" + Util::ColorText::Cyan( "*" ) + "]" + " Started " + Util::ColorText::Green( "\"" + QString( ListenerInfo.Name.c_str() ) + "\"" ) + " listener";
            auto Time   = QString( Package->Head.Time.c_str() );

            HavocX::Teamserver.TabSession->SmallAppWidgets->EventViewer->AppendText( Time, MsgStr );

            spdlog::info( "Started \"{}\" listener", ListenerInfo.Name );

            break;
        }

        case Util::Packager::Listener::Remove:
        {
            break;
        }

        case Util::Packager::Listener::Edit:
        {
            break;
        }

        case Util::Packager::Listener::SetOffline:
        {
            break;
        }

        case Util::Packager::Listener::SetOnline:
        {
            break;
        }
    }
    return true;
}

bool Packager::DispatchCredentials(Util::Packager::PPackage Package)
{
    switch (Package->Body.SubEvent) {
        case Util::Packager::Credentials::Add: {
            break;
        }
        case Util::Packager::Credentials::Remove: {
            break;
        }
        case Util::Packager::Credentials::Edit: {
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

bool Packager::DispatchHostFile( Util::Packager::PPackage Package)
{
    switch (Package->Body.SubEvent) {
        case Util::Packager::HostFile::Add: {
            break;
        }

        case Util::Packager::HostFile::Remove: {
            break;
        }

        case Util::Packager::HostFile::SetOnline: {
            break;
        }

        case Util::Packager::HostFile::SetOffline: {
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
            };

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
                    auto AgentType  = QString( Package->Body.Info[ "AgentType" ].c_str() );
                    auto message    = QString (
                            Util::ColorText::Comment( QString( Package->Head.Time.c_str() ) + " [" + QString( Package->Head.User.c_str() ) + "]" ) +
                            " " + Util::ColorText::UnderlinePink( AgentType ) +
                            Util::ColorText::Cyan(" » ") + QString( Package->Body.Info[ "CommandLine" ].c_str() )
                    );

                    if ( ! Package->Body.Info[ "CommandLine" ].empty() )
                    {
                        Session.InteractedWidget->AppendRaw();
                        Session.InteractedWidget->AppendRaw( message );
                    }

                    Session.InteractedWidget->DemonCommands->DispatchCommand( false, Package->Body.Info[ "TaskID" ].c_str(), Package->Body.Info[ "CommandLine" ].c_str() );
                }
            }
            break;
        }

        case Util::Packager::Session::ReceiveCommand:
        {
            bool scrollmouse = true;

            for ( auto & Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name.compare( Package->Body.Info[ "DemonID" ].c_str() ) == 0 )
                {
                    Session.InteractedWidget->DemonCommands->OutputDispatch.DemonCommandInstance = Session.InteractedWidget->DemonCommands;

                    int CommandID = QString( Package->Body.Info[ "CommandID" ].c_str() ).toInt();
                    auto Output   = QString( Package->Body.Info[ "Output" ].c_str() );

                    switch ( CommandID )
                    {
                        case 0x80:
                            Session.InteractedWidget->DemonCommands->OutputDispatch.MessageOutput( Output, QString( Package->Head.Time.c_str() ) );
                            break;

                        case ( int ) Commands::CALLBACK:
                        {
                            auto LastTime     = QString( QByteArray::fromBase64( Output.toLocal8Bit() ) );
                            auto LastTimeJson = QJsonDocument::fromJson( LastTime.toLocal8Bit() );

                            HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue(
                                    Package->Body.Info["DemonID"].c_str(), 8, LastTimeJson["Output"].toString().split(" ")[1]
                            );

                            scrollmouse = false;
                            break;
                        }

                        default:
                            spdlog::error( "[PACKAGE] Command not found" );
                            break;
                    }

                    if ( scrollmouse )
                        Session.InteractedWidget->Console->verticalScrollBar()->setValue( Session.InteractedWidget->Console->verticalScrollBar()->maximum() );

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
            spdlog::info( "Mark As Dead" );

            auto AgentID = Package->Body.Info[ "AgentID" ];

            for ( int i = 0; i < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
            {
                auto Row = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

                if ( Row.compare( QString( AgentID.c_str() ) ) == 0 )
                {
                    for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                    {
                        HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
                        HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
                    }

                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );
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
            auto Formats        = std::vector<AgentFormat>();
            auto Commands       = std::vector<AgentCommands>();
            auto MagicValue     = uint64_t( 0 );
            auto StringStream   = std::stringstream();

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
                } );
            }

            StringStream << std::hex << JsonObject[ "MagicValue" ].toString().toStdString();
            StringStream >> MagicValue;

            HavocX::Teamserver.ServiceAgents.push_back( ServiceAgent{
                .Name           = JsonObject[ "Name" ].toString(),
                .Description    = JsonObject[ "Description" ].toString(),
                .Version        = JsonObject[ "Version" ].toString(),
                .MagicValue     = MagicValue,
                .Formats        = Formats,
                .SupportedOS    = OSArray,
                .Commands       = Commands,
                .BuildingConfig = QJsonDocument( JsonObject[ "BuildingConfig" ].toObject() ),
            } );

            spdlog::info( "Added service agent to client" );

            return true;
        }
    }
    return false;
}

void Packager::setTeamserver(QString Name) {
    this->TeamserverName = Name;
}
