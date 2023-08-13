#include <global.hpp>
#include <random>

#include <Havoc/Connector.hpp>

#include <QFileDialog>

using namespace std;
using namespace HavocNamespace;
using namespace HavocNamespace::HavocSpace;

string HavocNamespace::Version  = "0.6";
string HavocNamespace::CodeName = "Hierophant Green";

// Global Variables in the Havoc Namespace
HavocSpace::Havoc* HavocNamespace::HavocApplication;

Util::ConnectionInfo       HavocX::Teamserver;
HavocNamespace::Connector* HavocX::Connector;
bool                       HavocX::DebugMode = false;

QString HavocSpace::Listener::PayloadHTTPS    = "Https";
QString HavocSpace::Listener::PayloadHTTP     = "Http";
QString HavocSpace::Listener::PayloadSMB      = "Smb";
QString HavocSpace::Listener::PayloadExternal = "External";

std::string Util::gen_random( const int len )
{
    auto str = std::string( "0123456789ABCDEF" );
    auto rd  = std::random_device();
    auto gen = std::mt19937( rd() );

    std::shuffle( str.begin(), str.end(), gen );

    return str.substr( 0, len );
}

void Util::SessionItem::Export()
{
    auto FileDialog = QFileDialog();
    auto Filename   = QUrl();
    auto Style      = FileRead( ":/stylesheets/Dialogs/FileDialog" ).toStdString();

    Style.erase( std::remove( Style.begin(), Style.end(), '\n' ), Style.end() );

    FileDialog.setStyleSheet( Style.c_str() );
    FileDialog.setAcceptMode( QFileDialog::AcceptSave );
    FileDialog.setDirectory( QDir::homePath() );
    FileDialog.selectFile( "Session_data_" + Name + ".json" );

    if ( FileDialog.exec() == QFileDialog::Accepted )
    {
        Filename = FileDialog.selectedUrls().value( 0 ).toLocalFile();

        if ( ! Filename.toString().isNull() )
        {
            // Save to file
            auto file       = QFile( Filename.toString() );
            auto messageBox = QMessageBox(  );

            if ( file.open( QIODevice::ReadWrite ) )
            {
                auto SessionData = QJsonObject();

                SessionData.insert( "AgentID",          QJsonValue::fromVariant( Name ) );
                SessionData.insert( "MagicValue",       QJsonValue::fromVariant( (int) MagicValue ) );
                SessionData.insert( "ExternalIP",       QJsonValue::fromVariant( External ) );
                SessionData.insert( "InternalIP",       QJsonValue::fromVariant( Internal ) );
                SessionData.insert( "Listener",         QJsonValue::fromVariant( Listener ) );
                SessionData.insert( "User",             QJsonValue::fromVariant( User ) );
                SessionData.insert( "Computer",         QJsonValue::fromVariant( Computer ) );
                SessionData.insert( "Domain",           QJsonValue::fromVariant( Domain ) );
                SessionData.insert( "OS",               QJsonValue::fromVariant( OS ) );
                SessionData.insert( "OSBuild",          QJsonValue::fromVariant( OSBuild ) );
                SessionData.insert( "OSArch",           QJsonValue::fromVariant( OSArch ) );
                SessionData.insert( "ProcessName",      QJsonValue::fromVariant( Process ) );
                SessionData.insert( "ProcessID",        QJsonValue::fromVariant( PID ) );
                SessionData.insert( "ProcessArch",      QJsonValue::fromVariant( Arch ) );
                SessionData.insert( "ProcessElevated",  QJsonValue::fromVariant( Elevated ) );
                SessionData.insert( "PivotParent",      QJsonValue::fromVariant( PivotParent ) );
                SessionData.insert( "First Callback",   QJsonValue::fromVariant( First ) );
                SessionData.insert( "Last Callback",    QJsonValue::fromVariant( Last ) );

                file.write( QJsonDocument( SessionData ).toJson( QJsonDocument::Indented ) );
            }
            else
                spdlog::error("Couldn't write to file {}", Filename.toString().toStdString());

            file.close();

            messageBox.setWindowTitle( "Session Exported" );
            messageBox.setText( "Path: " + Filename.toString() );
            messageBox.setIcon( QMessageBox::Information );
            messageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
            // messageBox.setMaximumSize( QSize( 500, 500 ) );
            messageBox.exec();
        }
    }
}
