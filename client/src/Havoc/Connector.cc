#include <Havoc/Connector.hpp>
#include <Havoc/Havoc.hpp>
#include <QCryptographicHash>
#include <QMap>
#include <QBuffer>

Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
{
    Teamserver   = ConnectionInfo;
    Socket       = new QWebSocket();
    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
    auto SslConf = Socket->sslConfiguration();

    /* ignore annoying SSL errors */
    SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
    Socket->setSslConfiguration( SslConf );
    Socket->ignoreSslErrors();

    QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
    {
        auto Package = HavocSpace::Packager::DecodePackage( Message );

        if ( Package != nullptr )
        {
            if ( ! Packager )
                return;

            Packager->DispatchPackage( Package );

            return;
        }

        spdlog::critical( "Got Invalid json" );
    } );

    QObject::connect( Socket, &QWebSocket::connected, this, [&]()
    {
        this->Packager = new HavocSpace::Packager;
        this->Packager->setTeamserver( this->Teamserver->Name );

        SendLogin();
    } );

    QObject::connect( Socket, &QWebSocket::disconnected, this, [&]()
    {
        MessageBox( "Teamserver error", Socket->errorString(), QMessageBox::Critical );

        Socket->close();

        Havoc::Exit();
    } );

    Socket->open( QUrl( Server ) );
}

bool Connector::Disconnect()
{
    if ( this->Socket != nullptr )
    {
        this->Socket->disconnect();
        return true;
    }

    return false;
}

Connector::~Connector() noexcept
{
    delete this->Socket;
}

void Connector::SendLogin()
{
    Util::Packager::Package Package;

    Util::Packager::Head_t Head;
    Util::Packager::Body_t Body;

    Head.Event              = Util::Packager::InitConnection::Type;
    Head.User               = this->Teamserver->User.toStdString();
    Head.Time               = QTime::currentTime().toString( "hh:mm:ss" ).toStdString();

    Body.SubEvent           = Util::Packager::InitConnection::Login;
    Body.Info[ "User" ]     = this->Teamserver->User.toStdString();
    Body.Info[ "Password" ] = QCryptographicHash::hash( this->Teamserver->Password.toLocal8Bit(), QCryptographicHash::Sha3_256 ).toHex().toStdString();

    Package.Head = Head;
    Package.Body = Body;

    SendPackage( &Package );
}

void Connector::SendPackage( Util::Packager::PPackage Package )
{
    Socket->sendBinaryMessage( Packager->EncodePackage( *Package ).toJson( QJsonDocument::Compact ) );
}
