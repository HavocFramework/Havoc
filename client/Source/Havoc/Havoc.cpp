#include <Havoc/Havoc.hpp>
#include <QApplication>
#include <Havoc/Connector.hpp>
// #include <QQuickView>

HavocSpace::Havoc::Havoc( QMainWindow* w )
{
    w->setVisible( false );

    this->HavocMainWindow = w;
    this->dbManager = new HavocSpace::DBManager( "data/client.db", DBManager::CreateSqlFile );
}

void HavocSpace::Havoc::Init( int argc, char** argv )
{
    auto List    = this->dbManager->listTeamservers();
    auto Connect = new HavocNamespace::UserInterface::Dialogs::Connect;

    this->HavocMainWindow->setVisible( false );

    Connect->TeamserverList = List;
    Connect->passDB( this->dbManager );
    Connect->setupUi( new QDialog );

    HavocX::Teamserver = Connect->StartDialog( false );
}

void HavocSpace::Havoc::Start()
{
    this->ClientInitConnect = false;
    this->HavocMainWindow->setVisible( true );
    this->HavocMainWindow->setCentralWidget( this->HavocAppUI.centralwidget );
    this->HavocMainWindow->show();
}

void HavocSpace::Havoc::Exit()
{
    spdlog::critical( "Exit Program" );
    HavocApplication->HavocMainWindow->close();

    exit( 0 );
}

Havoc::~Havoc()
{
    delete this->dbManager;
    delete this->HavocMainWindow;
}
