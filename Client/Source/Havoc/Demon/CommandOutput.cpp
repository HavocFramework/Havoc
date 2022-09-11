#include <QJsonDocument>
#include <QJsonArray>

#include "Include/Havoc/DemonCmdDispatch.h"

#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/ProcessList.hpp>

#include <Util/ColorText.h>
#include <QFile>

using namespace HavocNamespace::HavocSpace;

void DispatchOutput::MessageOutput( QString JsonString, const QString& Date = "" )
{
    auto JsonDocument = QJsonDocument::fromJson( QByteArray::fromBase64( JsonString.toLocal8Bit( ) ) );
    auto MessageType  = JsonDocument[ "Type" ].toString();
    auto Message      = JsonDocument[ "Message" ].toString();
    auto Output       = JsonDocument[ "Output" ].toString();

    if ( Message.length() > 0 )
    {
        if ( MessageType == "Error" )
            this->DemonCommandInstance->DemonConsole->TaskError( Message );
        else if ( MessageType == "Good" )
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Green( "[+]" ) + " " + Message.toHtmlEscaped() );
        else if ( MessageType == "Info" )
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Cyan( "[*]" ) + " " + Message.toHtmlEscaped() );
        else
            this->DemonCommandInstance->DemonConsole->AppendRaw( Util::ColorText::Purple( "[^]" ) + " " + Message.toHtmlEscaped() );
    }

    if ( ! Output.isEmpty() )
    {
        this->DemonCommandInstance->DemonConsole->AppendRaw( Output );
    }

    if ( JsonDocument[ "MiscType" ].toString().compare( "" ) != 0 )
    {
        auto Type = JsonDocument[ "MiscType" ].toString();
        auto Data = JsonDocument[ "MiscData" ].toString();

        if ( Type.compare( "screenshot" ) == 0 )
        {
            auto DecodedData = QByteArray::fromBase64( Data.toLocal8Bit() );
            auto Name        = JsonDocument[ "MiscData2" ].toString();

            HavocX::Teamserver.TabSession->LootWidget->AddScreenshot( DemonCommandInstance->DemonID, Name, Date, DecodedData );
        }
        else if ( Type.compare( "download" ) == 0 )
        {
            auto DecodedData  = QByteArray::fromBase64( Data.toLocal8Bit() );
            auto MiscDataInfo = JsonDocument[ "MiscData2" ].toString().split(";");

            auto Name = QByteArray::fromBase64( MiscDataInfo[ 0 ].toLocal8Bit() );
            auto Size = ( MiscDataInfo[ 1 ] );

            HavocX::Teamserver.TabSession->LootWidget->AddDownload( DemonCommandInstance->DemonID, Name, Size, Date, DecodedData );
        }
        else if ( Type.compare( "ProcessUI" ) == 0 )
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name == DemonCommandInstance->DemonID )
                {
                    if ( Session.ProcessList )
                    {
                        auto Decoded = QByteArray::fromBase64( Data.toLocal8Bit() );
                        Session.ProcessList->UpdateProcessListJson( QJsonDocument::fromJson( Decoded ) );
                    }
                }
            }
        }
        else if ( Type.compare( "FileExplorer" ) == 0 )
        {
            for ( auto& Session : HavocX::Teamserver.Sessions )
            {
                if ( Session.Name == DemonCommandInstance->DemonID )
                {
                    if ( Session.FileBrowser )
                    {
                        auto Decoded = QByteArray::fromBase64( Data.toLocal8Bit() );
                        Session.FileBrowser->AddData( QJsonDocument::fromJson( Decoded ) );
                    }
                }
            }
        }
    }
}
