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

#include <Util/ColorText.h>

#include <Havoc/Packager.hpp>

#include <QPixmap>
#include <QProcess>
#include <QFile>
#include <QToolButton>
#include <QShortcut>
#include <QStackedWidget>
#include <QTimer>

using namespace HavocNamespace::HavocSpace;

void HavocNamespace::UserInterface::HavocUI::setupUi(QMainWindow *Havoc)
{
    HavocWindow = Havoc;

    if ( HavocWindow->objectName().isEmpty() ) {
        HavocWindow->setObjectName( QString::fromUtf8( "HavocWindow " ) );
    }

    HavocWindow->resize( 1399, 821 );
    HavocWindow->setStyleSheet( FileRead( ":/stylesheets/Havoc" ) );

    actionNew_Client = new QAction( HavocWindow );
    actionNew_Client->setObjectName( QString::fromUtf8( "NewClient" ) );

    actionChat = new QAction( HavocWindow );
    actionChat->setObjectName( QString::fromUtf8( "actionChat" ) );

    actionPreferences = new QAction( HavocWindow );
    actionPreferences->setObjectName( QString::fromUtf8( "actionPreferences" ) );
    actionPreferences->setIcon( QIcon( ":/icons/settings" ) );
    actionPreferences->setShortcut( QKeySequence( "Ctrl+Alt+s" ) );

    actionDisconnect = new QAction( HavocWindow );
    actionDisconnect->setObjectName( QString::fromUtf8( "actionDisconnect" ) );

    actionExit = new QAction( HavocWindow );
    actionExit->setObjectName( QString::fromUtf8( "actionExit" ) );

    actionTeamserver = new QAction( HavocWindow );
    actionTeamserver->setObjectName( QString::fromUtf8( "actionTeamserver" ) );

    actionGeneratePayload = new QAction( HavocWindow );
    actionGeneratePayload->setObjectName( QString::fromUtf8( "actionGeneratePayload" ) );

    actionGeneratePayload = new QAction( HavocWindow );
    actionGeneratePayload->setObjectName( QString::fromUtf8( "actionGeneratePayload" ) );

    actionLoad_Script = new QAction( HavocWindow );
    actionLoad_Script->setObjectName( QString::fromUtf8( "actionLoad_Script" ) );

    actionPythonConsole = new QAction( HavocWindow );
    actionPythonConsole->setObjectName( QString::fromUtf8( "actionPythonConsole" ) );

    actionAbout = new QAction( HavocWindow );
    actionAbout->setObjectName( QString::fromUtf8( "actionAbout" ) );

    actionOpen_Help_Documentation = new QAction( HavocWindow );
    actionOpen_Help_Documentation->setObjectName( QString::fromUtf8( "actionOpen_Help_Documentation" ) );

    actionOpen_API_Reference = new QAction( HavocWindow );
    actionOpen_API_Reference->setObjectName( QString::fromUtf8( "actionOpen_API_Reference" ) );

    actionGithub_Repository = new QAction( HavocWindow );
    actionGithub_Repository->setObjectName( QString::fromUtf8( "actionGithub_Repository" ) );

    actionListeners = new QAction( HavocWindow );
    actionListeners->setObjectName( QString::fromUtf8( "actionListeners" ) );

    actionSessionsTable = new QAction( HavocWindow );
    actionSessionsTable->setObjectName( QString::fromUtf8( "actionSessionsTable" ) );

    actionSessionsGraph = new QAction( HavocWindow );
    actionSessionsGraph->setObjectName( QString::fromUtf8( "actionSessionsGraph" ) );

    actionLogs = new QAction( HavocWindow );
    actionLogs->setObjectName( QString::fromUtf8( "actionLogs" ) );

    actionLoot = new QAction( HavocWindow );
    actionLoot->setObjectName( QString::fromUtf8( "actionLoot" ) );

    centralwidget = new QWidget( HavocWindow );
    centralwidget->setObjectName( QString::fromUtf8( "centralwidget" ) );
    gridLayout_3 = new QGridLayout( centralwidget );
    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );
    gridLayout_3->setContentsMargins( 0, 0, 0, 0 );

    TeamserverTabWidget = new QTabWidget( centralwidget );
    TeamserverTabWidget->setObjectName( QString::fromUtf8( "TeamserverTabWidget" ) );
    TeamserverTabWidget->setStyleSheet( FileRead( ":/stylesheets/teamserverTab" ) );
    TeamserverTabWidget->setTabBarAutoHide( true );
    TeamserverTabWidget->setTabsClosable( true );

    /* TODO: refactor this. */
    HavocX::Teamserver.TabSession = new UserInterface::Widgets::TeamserverTabSession;
    HavocX::Teamserver.TabSession->setupUi( new QWidget, HavocX::Teamserver.Name );
    TeamserverTabWidget->setCurrentIndex(
        TeamserverTabWidget->addTab(
            HavocX::Teamserver.TabSession->PageWidget,
            HavocX::Teamserver.Name
        )
    );

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
    menuView->addAction( actionLoot );
    menuView->addSeparator();
    menuView->addAction( actionLogs );
    menuView->addAction( actionTeamserver );
    menuAttack->addAction( actionGeneratePayload );

    menuScripts->addAction( actionLoad_Script );
    menuScripts->addAction( actionPythonConsole );

    menuHelp->addAction( actionAbout );
    menuHelp->addSeparator();
    menuHelp->addAction( actionOpen_Help_Documentation );
    menuHelp->addAction( actionOpen_API_Reference );
    menuHelp->addSeparator();
    menuHelp->addAction( actionGithub_Repository );

    /* prepare python interpreter */
    PythonPrepare();

    /* connect events & buttons */
    ConnectEvents();

    /* set text for each action, button and widget */
    retranslateUi( HavocWindow );

    QMetaObject::connectSlotsByName( HavocWindow );
}

void HavocNamespace::UserInterface::HavocUI::OneSecondTick()
{

}

void HavocNamespace::UserInterface::HavocUI::MarkSessionAs(HavocNamespace::Util::SessionItem Session, QString Mark)
{
    for ( int i = 0; i <  HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->rowCount(); i++ )
    {
        auto AgentID = HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->text();

        if ( Session.Name.compare( AgentID ) == 0 )
        {
            auto Package = new Util::Packager::Package;
            QString Marked;

            if ( Mark.compare( "Alive" ) == 0 )
            {
                Marked = "Alive";
                Session.Marked = Marked;

                auto Icon = ( Session.Elevated.compare( "true" ) == 0 ) ?
                            WinVersionIcon( Session.OS, true ) :
                            WinVersionIcon( Session.OS, false );

                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( Icon );

                for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                {
                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Foreground ) );
                }
            }
            else if ( Mark.compare( "Dead" ) == 0 )
            {
                Marked = "Dead";
                Session.Marked = Marked;

                HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );

                for ( int j = 0; j < HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->columnCount(); j++ )
                {
                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
                    HavocX::Teamserver.TabSession->SessionTableWidget->SessionTableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
                }
            }

            spdlog::debug( "- Marked.toStdString(): {}", Marked.toStdString() );
            Package->Body = Util::Packager::Body_t {
                .SubEvent = Util::Packager::Session::MarkAs,
                .Info = {
                        { "AgentID", AgentID.toStdString() },
                        { "Marked",  Marked.toStdString() },
                }
            };

            HavocX::Connector->SendPackage( Package );

            break;
        }
    }
}


void HavocNamespace::UserInterface::HavocUI::UpdateSessionsHealth()
{
    for ( auto& session : HavocX::Teamserver.Sessions )
    {
        if ( session.Marked.compare( "Dead" ) == 0 )
            continue;

        auto Now  = QDateTime::currentDateTimeUtc();
        auto Last = QDateTime::fromString( session.Last.toStdString().c_str(), "dd-MM-yyyy hh:mm:ss" );
        auto diff = Last.secsTo( Now );

        // it is very normal for agents to delay one second due to network latency
        auto AllowedDiff = 1;

        if ( session.KillDate > 0 )
        {
            auto UNIX_TIME_START  = 0x019DB1DED53E8000; //January 1, 1970 (start of Unix epoch) in "ticks"
            auto TICKS_PER_SECOND = 10000000; //a tick is 100ns
            auto KillDateInEpoch  = ( session.KillDate - UNIX_TIME_START ) / TICKS_PER_SECOND;

            if ( Now.secsTo( QDateTime::fromSecsSinceEpoch( KillDateInEpoch, Qt::UTC ) ) <= 0 )
            {
                // agent reached its killdate
                session.Health = "killdate";
                session.Marked = "Dead";
                HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue( session.Name, 9, session.Health );
                MarkSessionAs( session, QString( "Dead") );
                continue;
            }
        }

        if ( ( ( session.WorkingHours >> 22 ) & 1 ) == 1 )
        {
            uint32_t StartHour   = ( session.WorkingHours >> 17 ) & 0b011111;
            uint32_t StartMinute = ( session.WorkingHours >> 11 ) & 0b111111;
            uint32_t EndHour     = ( session.WorkingHours >>  6 ) & 0b011111;
            uint32_t EndMinute   = ( session.WorkingHours >>  0 ) & 0b111111;
            bool isOffHours = false;

            if ( StartHour < Now.time().hour() || EndHour > Now.time().hour() ) {
                isOffHours = true;
            }

            if ( StartHour == Now.time().hour() && StartMinute < Now.time().minute() ) {
                isOffHours = true;
            }

            if ( EndHour == Now.time().hour() && EndMinute > Now.time().minute() ) {
                isOffHours = true;
            }

            if ( isOffHours ) {
                // agent is offhours
                session.Health = "offhours";
                HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue(session.Name, 9, session.Health);
                continue;
            }
        }

        if ( diff - AllowedDiff < session.SleepDelay + ( session.SleepDelay * 0.01 * session.SleepJitter ) ) {
            // agent has ping back in time
            session.Health = "healthy";
            HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue( session.Name, 9, session.Health );
            continue;
        } else {
            // agent has not pinged back in time
            session.Health = "unresponsive";
            HavocX::Teamserver.TabSession->SessionTableWidget->ChangeSessionValue( session.Name, 9, session.Health );
            continue;
        }
    }
}

void HavocNamespace::UserInterface::HavocUI::retranslateUi( QMainWindow* Havoc ) const
{
    Havoc->setWindowTitle( "Havoc" );

    actionNew_Client->setText( "New Client" );
    actionChat->setText( "Teamserver Chat" );
    actionDisconnect->setText( "Disconnect" );
    actionExit->setText( "Exit" );
    actionTeamserver->setText( "Teamserver" );
    actionGeneratePayload->setText( "Payload" );
    actionLoad_Script->setText(  "Scripts Manager" );
    actionPythonConsole->setText( "Script Console" );
    actionAbout->setText( "About" );
    actionOpen_Help_Documentation->setText( "Open Documentation" );
    actionOpen_API_Reference->setText( "Open API Reference" );
    actionGithub_Repository->setText( "Github Repository" );
    actionListeners->setText( "Listeners" );
    actionSessionsTable->setText( "Table" );
    actionSessionsGraph->setText( "Graph" );
    actionLogs->setText( "Event Viewer" );
    actionLoot->setText( "Loot" );
    menuHavoc->setTitle( "Havoc" );
    menuView->setTitle( "View" );
    menuAttack->setTitle( "Attack" );
    menuScripts->setTitle( "Scripts" );
    menuHelp->setTitle( "Help" );
    MenuSession->setTitle( "Session View" );

    HavocWindow->setFocus();
    HavocWindow->showMaximized();

}

void HavocNamespace::UserInterface::HavocUI::ConnectEvents()
{
    auto OneSecondTimer = new QTimer( this );

    QMainWindow::connect( OneSecondTimer, &QTimer::timeout, this, [&]() {
        UpdateSessionsHealth();
    } );
    OneSecondTimer->start(1000);

    QMainWindow::connect( actionNew_Client, &QAction::triggered, this, []() {
        QProcess::startDetached( QCoreApplication::applicationFilePath(), QStringList{""} );
    } );

    QMainWindow::connect( actionChat, &QAction::triggered, this, [&](){
        auto Teamserver = HavocX::Teamserver.TabSession;
        if ( Teamserver->TeamserverChat == nullptr ) {
            Teamserver->TeamserverChat = new Widgets::Chat;
            Teamserver->TeamserverChat->setupUi(new QWidget);
            Teamserver->TeamserverName = HavocX::Teamserver.Name;
        }

        NewBottomTab(
            Teamserver->TeamserverChat->ChatWidget,
            "Teamserver Chat"
        );
    } );

    QMainWindow::connect( actionDisconnect, &QAction::triggered, this, []() {
        if ( HavocX::Connector != nullptr ) {
            HavocX::Connector->Disconnect();
            MessageBox( "Disconnected", "Disconnected from " + HavocX::Teamserver.Name, QMessageBox::Information );
        } else {
            MessageBox( "Error", "Couldn't disconnect from " + HavocX::Teamserver.Name, QMessageBox::Critical );
        }
    } );

    QMainWindow::connect( actionExit, &QAction::triggered, this, []() {
        Havoc::Exit();
    } );

    QMainWindow::connect( actionSessionsTable, &QAction::triggered, this, []() {
        HavocX::Teamserver.TabSession->MainViewWidget->setCurrentIndex( 0 );
    } );

    QMainWindow::connect( actionListeners, &QAction::triggered, this, [&](){
        auto Teamserver = HavocX::Teamserver.TabSession;

        if ( Teamserver->ListenerTableWidget == nullptr ) {
            Teamserver->ListenerTableWidget = new Widgets::ListenersTable;
            Teamserver->ListenerTableWidget->setupUi(new QWidget);
            Teamserver->ListenerTableWidget->setDBManager(this->dbManager);
            Teamserver->ListenerTableWidget->TeamserverName = HavocX::Teamserver.Name;
        }

        NewBottomTab(
            Teamserver->ListenerTableWidget->ListenerWidget,
            "Listeners"
        );
    } );

    QMainWindow::connect( actionTeamserver, &QAction::triggered, this, [&](){
        if ( HavocX::Teamserver.TabSession->Teamserver == nullptr ) {
            HavocX::Teamserver.TabSession->Teamserver = new Teamserver;
            HavocX::Teamserver.TabSession->Teamserver->setupUi( new QDialog );
        }

        NewBottomTab(
            HavocX::Teamserver.TabSession->Teamserver->TeamserverWidget,
            "Teamserver"
        );
    } );

    QMainWindow::connect( actionSessionsGraph, &QAction::triggered, this, [&]() {
        HavocX::Teamserver.TabSession->MainViewWidget->setCurrentIndex( 1 );
    } );

    QMainWindow::connect( actionLogs, &QAction::triggered, this, [&]() {
        auto Teamserver = HavocX::Teamserver.TabSession;

        if ( Teamserver->SmallAppWidgets->EventViewer == nullptr )
        {
            Teamserver->SmallAppWidgets->EventViewer = new SmallWidgets::EventViewer;
            Teamserver->SmallAppWidgets->EventViewer->setupUi( new QWidget );
        }

        NewSmallTab(
            Teamserver->SmallAppWidgets->EventViewer->EventViewer,
            "Event Viewer"
        );
    } );

    QMainWindow::connect( actionLoot, &QAction::triggered, this, [&]() {
        if ( HavocX::Teamserver.TabSession->LootWidget == nullptr ) {
            HavocX::Teamserver.TabSession->LootWidget = new LootWidget;
        }

        NewBottomTab( HavocX::Teamserver.TabSession->LootWidget, "Loot Collection" );
    } );

    QMainWindow::connect( actionGeneratePayload, &QAction::triggered, this, []() {
        if ( HavocX::Teamserver.TabSession->PayloadDialog == nullptr ) {
            HavocX::Teamserver.TabSession->PayloadDialog = new Payload;
            HavocX::Teamserver.TabSession->PayloadDialog->setupUi( new QDialog );
            HavocX::Teamserver.TabSession->PayloadDialog->TeamserverName = HavocX::Teamserver.Name;
        }

        HavocX::Teamserver.TabSession->PayloadDialog->Start();
    } );

    QMainWindow::connect( actionPythonConsole, &QAction::triggered, this, [&]() {
        auto Teamserver = HavocX::Teamserver.TabSession;

        if ( Teamserver->PythonScriptWidget == nullptr ) {
            Teamserver->PythonScriptWidget = new Widgets::PythonScriptInterpreter;
            Teamserver->PythonScriptWidget->setupUi( new QWidget );
        }

        NewBottomTab(
            Teamserver->PythonScriptWidget->PythonScriptInterpreterWidget,
            "Scripting Console"
        );
    } );

    QMainWindow::connect( actionLoad_Script, &QAction::triggered, this, [&]() {
        auto Teamserver = HavocX::Teamserver.TabSession;

        if ( Teamserver->PythonScriptWidget == nullptr ) {
            Teamserver->PythonScriptWidget = new Widgets::PythonScriptInterpreter;
            Teamserver->PythonScriptWidget->setupUi( new QWidget );
        }

        if ( Teamserver->ScriptManagerWidget == nullptr ) {
            Teamserver->ScriptManagerWidget = new Widgets::ScriptManager;
            Teamserver->ScriptManagerWidget->SetupUi( new QWidget );
        }

        NewBottomTab(
            Teamserver->ScriptManagerWidget->ScriptManagerWidget,
            "Script Manager"
        );
    } );

    QMainWindow::connect( actionAbout, &QAction::triggered, this, [&]() {
        if ( AboutDialog == nullptr ) {
            AboutDialog = new About( new QDialog );
            AboutDialog->setupUi();
        }

        this->AboutDialog->AboutDialog->exec();
    } );

    QMainWindow::connect( actionGithub_Repository, &QAction::triggered, this, []() {
        QDesktopServices::openUrl( QUrl( "https://github.com/HavocFramework/Havoc" ) );
    } );

    QMainWindow::connect( actionOpen_Help_Documentation, &QAction::triggered, this, []() {
        QDesktopServices::openUrl( QUrl( "https://havocframework.com/docs/welcome" ) );
    } );
}

void HavocNamespace::UserInterface::HavocUI::NewBottomTab( QWidget* TabWidget, const std::string& TitleName, const QString IconPath ) const
{
    HavocX::Teamserver.TabSession->NewBottomTab( TabWidget, TitleName );
}

void HavocNamespace::UserInterface::HavocUI::setDBManager(HavocSpace::DBManager* dbManager)
{
    this->dbManager = dbManager;
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

void UserInterface::HavocUI::PythonPrepare()
{
    PyImport_AppendInittab( "emb", emb::PyInit_emb );
    PyImport_AppendInittab( "havocui", PythonAPI::HavocUI::PyInit_HavocUI );
    PyImport_AppendInittab( "havoc", PythonAPI::Havoc::PyInit_Havoc );

    Py_Initialize();

    PyImport_ImportModule( "emb" );

    for ( auto& ScriptPath : dbManager->GetScripts() ) {
        Widgets::ScriptManager::AddScript( ScriptPath );
    }
}

