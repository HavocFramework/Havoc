#include <Havoc/Connector.hpp>
#include <Havoc/Havoc.hpp>
#include <QCryptographicHash>
#include <QMap>
#include <QBuffer>

Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
{
    Teamserver              = ConnectionInfo;
    Socket                  = new QWebSocket();
    const QString& Server   = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";

    QObject::connect( Socket, &QWebSocket::connected,     this, &Connector::OnConnect );
    QObject::connect( Socket, &QWebSocket::disconnected,  this, &Connector::OnClosed );

    // QObject::connect( Socket, &QWebSocket::errorOccurred, this, &Connector::socketError );

    Socket->open( QUrl( Server ) );

    /*this->ConnectionSocket->connectToHost( this->Teamserver->Host, this->Teamserver->Port.toInt() );

    if ( !this->ConnectionSocket->waitForConnected(5000) && this->ErrorString == nullptr )
    {
        spdlog::critical("Teamserver Error: {}", this->ConnectionSocket->errorString().toStdString());

        QFile messageBoxStyleSheets(":/stylesheets/MessageBox");
        QMessageBox messageBox;

        messageBoxStyleSheets.open(QIODevice::ReadOnly);

        messageBox.setWindowTitle("Teamserver Error");
        messageBox.setText(this->ConnectionSocket->errorString());
        messageBox.setIcon(QMessageBox::Critical);
        messageBox.setStyleSheet(messageBoxStyleSheets.readAll());

        messageBox.exec();

        Havoc::Exit();
    }*/
}

bool Connector::Connect()
{
    this->Packager = new HavocSpace::Packager;
    this->Packager->setTeamserver( this->Teamserver->Name );

    SendLogin();

    return true;
}

void Connector::OnConnect()
{
    QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, &Connector::OnReceive );

    Connect();
}

auto Connector::OnClosed() -> void
{
    auto MessageBox = QMessageBox();

    spdlog::error( "Server disconnected => {}", Socket->errorString().toStdString() );

    MessageBox.setWindowTitle("Teamserver Error");
    MessageBox.setText( Socket->errorString() );
    MessageBox.setIcon( QMessageBox::Critical );
    MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );

    MessageBox.exec();

    Socket->close();

    Havoc::Exit();
}

void Connector::OnReceive( const QByteArray& Message )
{
    auto Package = HavocSpace::Packager::DecodePackage( Message );

    if ( Package != nullptr )
        Packager->DispatchPackage( Package );
    else
        spdlog::critical( "Got Invalid json" );
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
