#include <global.hpp>

// Headers for UserInterface
#include <Havoc/Havoc.hpp>
#include <Havoc/PythonApi/PythonApi.h>

#include <UserInterface/HavocUI.hpp>
#include "Include/Havoc/Connector.hpp"
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <UserInterface/Widgets/PythonScript.hpp>
#include <UserInterface/Widgets/ScriptManager.h>
#include <UserInterface/Widgets/LootWidget.h>

#include <QPixmap>
#include <QProcess>
#include <QFile>
#include <QToolButton>
#include <QShortcut>
#include <QStackedWidget>

using namespace HavocNamespace::HavocSpace;

void HavocNamespace::UserInterface::HavocUI::setupUi(QMainWindow *Havoc)
{
    HavocWindow = Havoc;

    if ( HavocWindow->objectName().isEmpty() )
        HavocWindow->setObjectName( QString::fromUtf8( "HavocWindow " ) );
    this->HavocWindow->resize( 1399, 821 );

    HavocWindow->setStyleSheet( FileRead( ":/stylesheets/Havoc" ) );

    actionNew_Client = new QAction( HavocWindow );
    actionNew_Client->setObjectName( QString::fromUtf8( "NewClient" ) );

    actionChat = new QAction( HavocWindow );
    actionChat->setObjectName( QString::fromUtf8( "actionChat" ) );

    actionPreferences = new QAction( this->HavocWindow );
    actionPreferences->setObjectName( QString::fromUtf8( "actionPreferences" ) );
    actionPreferences->setIcon( QIcon( ":/icons/settings" ) );
    actionPreferences->setShortcut( QKeySequence( "Ctrl+Alt+s" ) );

    actionDisconnect = new QAction( this->HavocWindow );
    actionDisconnect->setObjectName( QString::fromUtf8( "actionDisconnect" ) );

    actionExit = new QAction( this->HavocWindow );
    actionExit->setObjectName( QString::fromUtf8( "actionExit" ) );

    actionTeamserver = new QAction( this->HavocWindow );
    actionTeamserver->setObjectName( QString::fromUtf8( "actionTeamserver" ) );

    // actionHostFile = new QAction( this->HavocWindow );
    // actionHostFile->setObjectName( QString::fromUtf8( "actionHostFile" ) );
    // actionHostFile->setIcon( QIcon( ":/icons/hostfile" ) );

    actionGeneratePayload = new QAction( this->HavocWindow );
    actionGeneratePayload->setObjectName( QString::fromUtf8( "actionGeneratePayload" ) );

    actionGeneratePayload = new QAction( this->HavocWindow );
    actionGeneratePayload->setObjectName( QString::fromUtf8( "actionGeneratePayload" ) );

    actionLoad_Script = new QAction( this->HavocWindow );
    actionLoad_Script->setObjectName( QString::fromUtf8( "actionLoad_Script" ) );

    actionPythonConsole = new QAction( this->HavocWindow );
    actionPythonConsole->setObjectName( QString::fromUtf8( "actionPythonConsole" ) );

    actionAbout = new QAction( this->HavocWindow );
    actionAbout->setObjectName( QString::fromUtf8( "actionAbout" ) );

    actionOpen_Help_Documentation = new QAction( this->HavocWindow );
    actionOpen_Help_Documentation->setObjectName( QString::fromUtf8( "actionOpen_Help_Documentation" ) );

    actionOpen_API_Reference = new QAction( this->HavocWindow );
    actionOpen_API_Reference->setObjectName( QString::fromUtf8( "actionOpen_API_Reference" ) );

    actionGithub_Repository = new QAction( this->HavocWindow );
    actionGithub_Repository->setObjectName( QString::fromUtf8( "actionGithub_Repository" ) );

    actionListeners = new QAction( this->HavocWindow );
    actionListeners->setObjectName( QString::fromUtf8( "actionListeners" ) );

    actionSessionsTable = new QAction( this->HavocWindow );
    actionSessionsTable->setObjectName( QString::fromUtf8( "actionSessionsTable" ) );

    actionSessionsGraph = new QAction( this->HavocWindow );
    actionSessionsGraph->setObjectName( QString::fromUtf8( "actionSessionsGraph" ) );

    // actionCredentials = new QAction( this->HavocWindow );//
    // actionCredentials->setObjectName( QString::fromUtf8( "actionCredentials" ) );
    // actionCredentials->setIcon( QIcon( ":/icons/lock" ) );

    actionLogs = new QAction( this->HavocWindow );
    actionLogs->setObjectName( QString::fromUtf8( "actionLogs" ) );

    // actionOperator = new QAction( this->HavocWindow );
    // actionOperator->setObjectName( QString::fromUtf8( "actionOperator" ) );

    actionLoot = new QAction( this->HavocWindow );
    actionLoot->setObjectName( QString::fromUtf8( "actionLoot" ) );

    centralwidget = new QWidget( this->HavocWindow );
    centralwidget->setObjectName( QString::fromUtf8( "centralwidget" ) );
    gridLayout_3 = new QGridLayout( centralwidget );
    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );
    gridLayout_3->setContentsMargins( 0, 0, 0, 0 );

    TeamserverTabWidget = new QTabWidget( centralwidget );
    TeamserverTabWidget->setObjectName( QString::fromUtf8( "TeamserverTabWidget" ) );
    TeamserverTabWidget->setStyleSheet( FileRead( ":/stylesheets/teamserverTab" ) );
    TeamserverTabWidget->setTabBarAutoHide( true );
    TeamserverTabWidget->setTabsClosable( true );

    // TODO: remove it.
    NewTeamserverTab( &HavocX::Teamserver );

    gridLayout_3->addWidget( TeamserverTabWidget, 0, 0, 1, 1 );

    menubar = new QMenuBar( this->HavocWindow );
    menubar->setObjectName( QString::fromUtf8( "menubar" ) );
    menubar->setGeometry( QRect( 0, 0, 1143, 20 ) );

    menubar->setStyleSheet( FileRead( ":/stylesheets/menubar" ) );

    menuHavoc   = new QMenu( menubar );
    menuView    = new QMenu( menubar );
    menuAttack  = new QMenu( menubar );
    MenuSession = new QMenu( menubar );
    menuScripts = new QMenu( menubar );
    menuHelp    = new QMenu( menubar );

    menuHavoc->setObjectName( QString::fromUtf8( "menuHavoc" ) );
    menuView->setObjectName( QString::fromUtf8( "menuView" ) );
    menuAttack->setObjectName( QString::fromUtf8( "menuAttack" ) );

    HavocWindow->setMenuBar( menubar );

    menuScripts->setObjectName( QString::fromUtf8( "menuScripts" ) );
    menuHelp->setObjectName( QString::fromUtf8( "menuHelp" ) );

    statusbar = new QStatusBar( HavocWindow );
    statusbar->setObjectName( QString::fromUtf8( "statusbar" ) );
    statusbar->setLayoutDirection( Qt::LayoutDirection::RightToLeft );
    statusbar->setSizeGripEnabled( false );
    statusbar->setVisible( false ); // change that by setting
    HavocWindow->setStatusBar( statusbar );

    menubar->addAction( menuHavoc->menuAction() );
    menubar->addAction( menuView->menuAction() );
    menubar->addAction( menuAttack->menuAction() );
    menubar->addAction( menuScripts->menuAction() );
    menubar->addAction( menuHelp->menuAction() );

    menuHavoc->addAction( actionNew_Client );
    // menuHavoc->addSeparator();
    // menuHavoc->addAction( actionPreferences ); // TODO: finish later.
    menuHavoc->addSeparator();
    menuHavoc->addAction( actionDisconnect );
    menuHavoc->addAction( actionExit );

    MenuSession->addAction( actionSessionsTable );
    MenuSession->addAction( actionSessionsGraph );

    menuView->addAction( actionListeners );
    menuView->addSeparator();
    menuView->addAction( MenuSession->menuAction() );
    menuView->addSeparator();
    menuView->addAction( actionChat );
    //menuView->addAction( actionCredentials );
    menuView->addAction( actionLoot );
    menuView->addSeparator();
    menuView->addAction( actionLogs );
    menuView->addAction( actionTeamserver );

    menuAttack->addAction( actionGeneratePayload );
    // menuAttack->addAction( actionHostFile );

    menuScripts->addAction( actionLoad_Script );
    menuScripts->addAction( actionPythonConsole );

    menuHelp->addAction( actionAbout );
    menuHelp->addSeparator();
    menuHelp->addAction( actionOpen_Help_Documentation );
    menuHelp->addAction( actionOpen_API_Reference );
    menuHelp->addSeparator();
    menuHelp->addAction( actionGithub_Repository );

    // Init Python Interpreter
    {
        PyImport_AppendInittab( "emb", emb::PyInit_emb );

        PyImport_AppendInittab( "havocui", PythonAPI::HavocUI::PyInit_HavocUI );
        PyImport_AppendInittab( "havoc", PythonAPI::Havoc::PyInit_Havoc );

        Py_Initialize();

        PyImport_ImportModule( "emb" );

        for ( auto& ScriptPath : dbManager->GetScripts() )
        {
            Widgets::ScriptManager::AddScript( ScriptPath );
        }
    }

    InitializeButtons();
    InitShortCuts();

    retranslateUi( this->HavocWindow );
    QMetaObject::connectSlotsByName( this->HavocWindow );
}

void HavocNamespace::UserInterface::HavocUI::retranslateUi( QMainWindow* Havoc ) const
{
    Havoc->setWindowTitle(QCoreApplication::translate("Havoc", "Havoc", nullptr));

    actionNew_Client->setText( QCoreApplication::translate( "Havoc", "New Client", nullptr ) );
    actionChat->setText( QCoreApplication::translate( "Havoc", "Teamserver Chat", nullptr ) );
    actionChat->setIcon( QIcon( ":/icons/users" ) );
    // actionPreferences->setText( QCoreApplication::translate( "Havoc", "Preferences", nullptr ) );
    actionDisconnect->setText( QCoreApplication::translate( "Havoc", "Disconnect", nullptr ) );
    actionExit->setText( QCoreApplication::translate( "Havoc", "Exit", nullptr ) );
    actionTeamserver->setText( QCoreApplication::translate( "Havoc", "Teamserver", nullptr ) );
    actionGeneratePayload->setText( QCoreApplication::translate( "Havoc", "Payload", nullptr ) );
    actionLoad_Script->setText(QCoreApplication::translate("Havoc", "Scripts Manager", nullptr));
    actionPythonConsole->setText(QCoreApplication::translate("Havoc", "Script Console", nullptr));
    actionAbout->setText(QCoreApplication::translate("Havoc", "About", nullptr));
    actionOpen_Help_Documentation->setText(QCoreApplication::translate("Havoc", "Open Documentation", nullptr));
    actionOpen_API_Reference->setText(QCoreApplication::translate("Havoc", "Open API Reference", nullptr));
    actionGithub_Repository->setText(QCoreApplication::translate("Havoc", "Github Repository", nullptr));
    actionListeners->setText(QCoreApplication::translate("Havoc", "Listeners", nullptr));
    actionListeners->setIcon(QIcon(":/icons/listener"));
    actionListeners->setIconVisibleInMenu(true);

    actionSessionsTable->setText(QCoreApplication::translate("Havoc", "Table", nullptr));
    // actionSessions->setIcon(QIcon(":/icons/demon-shell"));
    actionSessionsTable->setIconVisibleInMenu( true );

    actionSessionsGraph->setText(QCoreApplication::translate("Havoc", "Graph", nullptr));
    // actionSessions->setIcon(QIcon(":/icons/demon-shell"));
    actionSessionsGraph->setIconVisibleInMenu( true );

    // actionCredentials->setText( QCoreApplication::translate( "Havoc", "Credentials", nullptr ) );
    actionLogs->setText( QCoreApplication::translate( "Havoc", "Event Viewer", nullptr ) );
    // actionOperator->setText( QCoreApplication::translate( "Havoc", "Operator", nullptr ) );
    actionLoot->setText( QCoreApplication::translate( "Havoc", "Loot", nullptr ) );

    menuHavoc->setTitle(QCoreApplication::translate("Havoc", "Havoc", nullptr));
    menuView->setTitle(QCoreApplication::translate("Havoc", "View", nullptr));
    menuAttack->setTitle(QCoreApplication::translate("Havoc", "Attack", nullptr));
    menuScripts->setTitle(QCoreApplication::translate("Havoc", "Scripts", nullptr));
    menuHelp->setTitle(QCoreApplication::translate("Havoc", "Help", nullptr));

    MenuSession->setTitle( "Session View" );

    this->HavocWindow->setFocus();
    this->HavocWindow->showMaximized();

}

void HavocNamespace::UserInterface::HavocUI::InitializeButtons() const
{
    // create shortcut
    // Havoc
    QMainWindow::connect( actionNew_Client, &QAction::triggered, this, &HavocUI::onButton_Havoc_Client );
    QMainWindow::connect( actionChat, &QAction::triggered, this, &HavocUI::onButton_Havoc_Chat );
    // QMainWindow::connect(actionPreferences, &QAction::triggered, this, &HavocUI::onButton_Havoc_Preferences);
    QMainWindow::connect( actionDisconnect, &QAction::triggered, this, &HavocUI::onButton_Havoc_Disconnect );
    QMainWindow::connect( actionExit, &QAction::triggered, this, &HavocUI::onButton_Havoc_Exit );

    // View
    QMainWindow::connect( actionSessionsTable, &QAction::triggered, this, &HavocUI::onButton_View_SessionsTable );
    QMainWindow::connect( actionListeners, &QAction::triggered, this, &HavocUI::onButton_View_Listeners );
    QMainWindow::connect( actionTeamserver, &QAction::triggered, this, &HavocUI::onButton_View_Teamserver );

    // QMainWindow::connect(actionCredentials, &QAction::triggered, this, &HavocUI::onButton_View_Credentials);
    QMainWindow::connect( actionSessionsGraph, &QAction::triggered, this, &HavocUI::onButton_View_SessionsGraph );
    QMainWindow::connect( actionLogs, &QAction::triggered, this, &HavocUI::onButton_View_Logs );
    QMainWindow::connect( actionLoot, &QAction::triggered, this, &HavocUI::onButtonViewLoot );

    // Attack
    QMainWindow::connect( actionGeneratePayload, &QAction::triggered, this, &HavocUI::onButton_Attack_Payload );

    // Scripts
    QMainWindow::connect( actionPythonConsole, &QAction::triggered, this, &HavocUI::onButton_Scripts_Interpreter );
    QMainWindow::connect( actionLoad_Script, &QAction::triggered, this, &HavocUI::onButtonScriptsManager );

    // Help
    QMainWindow::connect( actionAbout, &QAction::triggered, this, &HavocUI::onButton_Help_About );
    QMainWindow::connect( actionGithub_Repository, &QAction::triggered, this, &HavocUI::onButton_Help_Github );
    QMainWindow::connect( actionOpen_Help_Documentation, &QAction::triggered, this, &HavocUI::onButton_Help_Documentation );

    QMainWindow::connect( TeamserverTabWidget, &QTabWidget::currentChanged, this, &HavocUI::tabSelected );
    QMainWindow::connect( TeamserverTabWidget, &QTabWidget::tabCloseRequested, this, &HavocUI::removeTab );
}

void HavocNamespace::UserInterface::HavocUI::InitShortCuts()
{


}

void HavocNamespace::UserInterface::HavocUI::NewBottomTab( QWidget* TabWidget, const std::string& TitleName, const QString IconPath ) const
{
    HavocX::Teamserver.TabSession->NewBottomTab( TabWidget, TitleName );
}

void HavocNamespace::UserInterface::HavocUI::setDBManager(HavocSpace::DBManager* dbManager)
{
    this->dbManager = dbManager;
}

// ------------
// SLOT BUTTONS
// ------------

/*void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Connect()
{
    if ( this->ConnectDialog == nullptr )
    {
        this->ConnectDialog = new Dialogs::Connect;
        this->ConnectDialog->setupUi( new QDialog );
    }
    this->ConnectDialog->FromAction = true;

    auto ConnectionInfo = this->ConnectDialog->StartDialog(true);
}*/

void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Client()
{
    QProcess::startDetached( QCoreApplication::applicationFilePath(), QStringList{""} );
}

void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Chat()
{
    auto Teamserver = HavocX::Teamserver.TabSession;
    if ( Teamserver->TeamserverChat == nullptr )
    {
        Teamserver->TeamserverChat = new Widgets::Chat;
        Teamserver->TeamserverChat->setupUi(new QWidget);
        Teamserver->TeamserverName = HavocX::Teamserver.Name;
    }

    NewBottomTab( Teamserver->TeamserverChat->ChatWidget, "Teamserver Chat", ":/icons/users" );
}

void HavocNamespace::UserInterface::HavocUI::onButton_Help_About()
{
    if ( AboutDialog == nullptr )
    {
        AboutDialog = new About( new QDialog );
        AboutDialog->setupUi();
    }
    this->AboutDialog->AboutDialog->exec();
}

void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Exit()
{
    Havoc::Exit();
}

void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Disconnect()
{
    if ( HavocX::Connector != nullptr )
    {
        HavocX::Connector->Disconnect();
        MessageBox( "Disconnected", "Disconnected from " + HavocX::Teamserver.Name, QMessageBox::Information );
    }
    else
    {
        MessageBox( "Error", "Couldn't disconnect from " + HavocX::Teamserver.Name, QMessageBox::Critical );
    }
}

void HavocNamespace::UserInterface::HavocUI::onButton_Help_Github()
{
    QDesktopServices::openUrl( QUrl( "https://github.com/HavocFramework/Havoc" ) );
}

void HavocNamespace::UserInterface::HavocUI::onButton_Help_Documentation()
{
    QDesktopServices::openUrl( QUrl( "https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD" ) );
}

void HavocNamespace::UserInterface::HavocUI::onButton_Scripts_Interpreter()
{
    auto Teamserver = HavocX::Teamserver.TabSession;

    if ( Teamserver->PythonScriptWidget == nullptr )
    {
        Teamserver->PythonScriptWidget = new Widgets::PythonScriptInterpreter;
        Teamserver->PythonScriptWidget->setupUi( new QWidget );
    }

    NewBottomTab( Teamserver->PythonScriptWidget->PythonScriptInterpreterWidget, "Scripting Console" );
}

void HavocNamespace::UserInterface::HavocUI::onButtonScriptsManager()
{
    auto Teamserver = HavocX::Teamserver.TabSession;

    if ( Teamserver->PythonScriptWidget == nullptr )
    {
        Teamserver->PythonScriptWidget = new Widgets::PythonScriptInterpreter;
        Teamserver->PythonScriptWidget->setupUi( new QWidget );
    }


    if ( Teamserver->ScriptManagerWidget == nullptr )
    {
        Teamserver->ScriptManagerWidget = new Widgets::ScriptManager;
        Teamserver->ScriptManagerWidget->SetupUi( new QWidget );
    }

    NewBottomTab( Teamserver->ScriptManagerWidget->ScriptManagerWidget, "Script Manager" );
}

void HavocNamespace::UserInterface::HavocUI::onButton_View_SessionsTable()
{
    HavocX::Teamserver.TabSession->MainViewWidget->setCurrentIndex( 0 );
}

void HavocNamespace::UserInterface::HavocUI::onButton_View_SessionsGraph()
{
    HavocX::Teamserver.TabSession->MainViewWidget->setCurrentIndex( 1 );
}

/*void HavocNamespace::UserInterface::HavocUI::onButton_View_Credentials()
{
    auto Teamserver = HavocX::Teamserver.TabSession;
    if ( Teamserver->CredentialsTableWidget == nullptr )
    {
        Teamserver->CredentialsTableWidget = new Widgets::CredentialsTable;
        Teamserver->CredentialsTableWidget->setupUi( new QWidget );
    }
    NewBottomTab( Teamserver->CredentialsTableWidget->CredentialsTable, "Credentials", ":/icons/lock" );
}*/

void HavocNamespace::UserInterface::HavocUI::onButton_View_Listeners()
{
    auto Teamserver = HavocX::Teamserver.TabSession;

    if ( Teamserver->ListenerTableWidget == nullptr )
    {
        Teamserver->ListenerTableWidget = new Widgets::ListenersTable;
        Teamserver->ListenerTableWidget->setupUi(new QWidget);
        Teamserver->ListenerTableWidget->setDBManager(this->dbManager);
        Teamserver->ListenerTableWidget->TeamserverName = HavocX::Teamserver.Name;
    }

    NewBottomTab( Teamserver->ListenerTableWidget->ListenerWidget, "Listeners", ":/icons/listener" );
}

void HavocNamespace::UserInterface::HavocUI::onButton_View_Logs()
{
    auto Teamserver = HavocX::Teamserver.TabSession;

    if ( Teamserver->SmallAppWidgets->EventViewer == nullptr )
    {
        Teamserver->SmallAppWidgets->EventViewer = new SmallWidgets::EventViewer;
        Teamserver->SmallAppWidgets->EventViewer->setupUi( new QWidget );
    }

    NewSmallTab( Teamserver->SmallAppWidgets->EventViewer->EventViewer, "Event Viewer" );
}

void HavocNamespace::UserInterface::HavocUI::onButton_Attack_Payload()
{
    if ( HavocX::Teamserver.TabSession->PayloadDialog == nullptr )
    {
        HavocX::Teamserver.TabSession->PayloadDialog = new Payload;
        HavocX::Teamserver.TabSession->PayloadDialog->setupUi( new QDialog );
        HavocX::Teamserver.TabSession->PayloadDialog->TeamserverName = HavocX::Teamserver.Name;
    }

    HavocX::Teamserver.TabSession->PayloadDialog->Start();
}

void HavocNamespace::UserInterface::HavocUI::onButton_Havoc_Preferences()
{
    if (this->PreferencesDialogs == nullptr) {
        this->PreferencesDialogs = new Dialogs::Preferences;
        this->PreferencesDialogs->setupUi();
    }
    this->PreferencesDialogs->StartDialog();
}

// TODO: change that for Teamserver
void HavocNamespace::UserInterface::HavocUI::removeTab(int index) const
{
    if ( index == -1 )
        return;

    auto TeamserverName = TeamserverTabWidget->tabText( index );

    if ( HavocX::Connector != nullptr )
    {
        HavocX::Connector->Disconnect();
        MessageBox( "Disconnected", "Disconnected from " + HavocX::Teamserver.Name, QMessageBox::Information );
    }
    else
    {
        MessageBox( "Error", "Couldn't disconnect from " + HavocX::Teamserver.Name, QMessageBox::Critical );
    }

    TeamserverTabWidget->removeTab( index );
    for ( int i = 0 ; i < TeamserverTabWidget->count(); i++ )
    {
        TeamserverTabWidget->setCurrentIndex( i );
    }
}

void UserInterface::HavocUI::tabSelected() const
{
    // Global::CurrentTeamserverConnection = this->TeamserverTabWidget->tabText(this->TeamserverTabWidget->currentIndex() );
}

void UserInterface::HavocUI::NewTeamserverTab( HavocNamespace::Util::ConnectionInfo* Connection )
{
    Connection->TabSession = new UserInterface::Widgets::TeamserverTabSession;
    Connection->TabSession->setupUi( new QWidget, Connection->Name );

    int id = TeamserverTabWidget->addTab( Connection->TabSession->PageWidget, Connection->Name );
    TeamserverTabWidget->setCurrentIndex( id );
    HavocX::Teamserver = *Connection;
}

void UserInterface::HavocUI::NewTeamserverTab( QString Name )
{
    HavocX::Teamserver.TabSession = new UserInterface::Widgets::TeamserverTabSession;
    HavocX::Teamserver.TabSession->setupUi( new QWidget, HavocX::Teamserver.Name );

    int id = TeamserverTabWidget->addTab( HavocX::Teamserver.TabSession->PageWidget, HavocX::Teamserver.Name );
    TeamserverTabWidget->setCurrentIndex( id );
}

void UserInterface::HavocUI::NewSmallTab( QWidget *TabWidget, const string &TitleName ) const
{
    auto Teamserver = HavocX::Teamserver.TabSession;
    Teamserver->NewWidgetTab( TabWidget, TitleName );
}

void UserInterface::HavocUI::ApplicationScreenshot()
{
    /*
    cout << "Pressed !!!!!!!!!" << endl;
    QMessageBox::information(nullptr, "test", "test");
    */
}

bool UserInterface::HavocUI::event(QEvent* e)
{
    return true;
}

void UserInterface::HavocUI::onButtonViewLoot()
{
    auto Teamserver = HavocX::Teamserver.TabSession;

    if ( Teamserver->LootWidget == nullptr )
        Teamserver->LootWidget = new LootWidget;

    NewBottomTab( Teamserver->LootWidget, "Loot Collection" );
}

void UserInterface::HavocUI::onButton_View_Teamserver()
{
    if ( HavocX::Teamserver.TabSession->Teamserver == nullptr )
    {
        HavocX::Teamserver.TabSession->Teamserver = new Teamserver;
        HavocX::Teamserver.TabSession->Teamserver->setupUi( new QDialog );
    }

    NewBottomTab( HavocX::Teamserver.TabSession->Teamserver->TeamserverWidget, "Teamserver" );
}
