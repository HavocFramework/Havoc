#include <global.hpp>

#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/SessionGraph.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <UserInterface/Widgets/ProcessList.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <UserInterface/Widgets/LootWidget.h>
#include <UserInterface/Widgets/FileBrowser.hpp>

#include <UserInterface/SmallWidgets/EventViewer.hpp>

#include <Util/ColorText.h>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

#include <QFile>
#include <QToolButton>
#include <QHeaderView>
#include <QByteArray>
#include <QKeyEvent>
#include <QShortcut>

using namespace UserInterface::Widgets;

void HavocNamespace::UserInterface::Widgets::TeamserverTabSession::setupUi(QWidget *Page, QString TeamserverName)
{
    this->TeamserverName = TeamserverName;
    this->PageWidget = Page;

    auto MenuStyle = QString(
        "QMenu {"
         "    background-color: #282a36;"
         "    color: #f8f8f2;"
         "    border: 1px solid #44475a;"
         "}"
         "QMenu::separator {"
         "    background: #44475a;"
         "}"
         "QMenu::item:selected {"
         "    background: #44475a;"
         "}"
         "QAction {"
         "    background-color: #282a36;"
         "    color: #f8f8f2;"
         "}"
    );

    this->SmallAppWidgets = new SmallAppWidgets_t;
    this->SmallAppWidgets->EventViewer = new UserInterface::SmallWidgets::EventViewer;
    this->SmallAppWidgets->EventViewer->setupUi(new QWidget);

    gridLayout = new QGridLayout(PageWidget);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setContentsMargins(0, 0, 0, 0);

    splitter_TopBot = new QSplitter(PageWidget);
    splitter_TopBot->setOrientation(Qt::Vertical);
    splitter_TopBot->setContentsMargins(0, 0, 0, 0);

    layoutWidget    = new QWidget( splitter_TopBot );

    verticalLayout  = new QVBoxLayout( layoutWidget );
    verticalLayout->setContentsMargins( 3, 3, 3, 3 );

    MainViewWidget   = new QStackedWidget(  );
    SessionTablePage = new QWidget( );

    gridLayout_2 = new QGridLayout( SessionTablePage );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );
    gridLayout_2->setContentsMargins( 0, 0, 0, 0 );

    splitter_SessionAndTabs = new QSplitter( layoutWidget );
    splitter_SessionAndTabs->setOrientation( Qt::Horizontal );

    SessionTableWidget = new HavocNamespace::UserInterface::Widgets::SessionTable;
    SessionTableWidget->setupUi( new QTableWidget(), this->TeamserverName );
    SessionTableWidget->setFocusPolicy( Qt::NoFocus );

    SessionGraphWidget = new GraphWidget( MainViewWidget );

    // Session Table
    MainViewWidget->addWidget( SessionTableWidget->SessionTableWidget );
    MainViewWidget->addWidget( SessionGraphWidget );
    MainViewWidget->setCurrentIndex( 0 );

    splitter_SessionAndTabs->addWidget( MainViewWidget );

    tabWidgetSmall = new QTabWidget( splitter_SessionAndTabs );
    tabWidgetSmall->setObjectName( QString::fromUtf8( "tabWidgetSmall" ) );
    tabWidgetSmall->setMovable( false );

    splitter_SessionAndTabs->addWidget( tabWidgetSmall );

    gridLayout_2->addWidget( splitter_SessionAndTabs, 0, 0, 1, 1 );

    verticalLayout->addWidget( SessionTablePage );

    splitter_TopBot->addWidget( layoutWidget );
    tabWidget = new QTabWidget( splitter_TopBot );
    tabWidget->setObjectName( QString::fromUtf8( "tabWidget" ) );
    splitter_TopBot->addWidget( tabWidget );

    gridLayout->addWidget(splitter_TopBot, 0, 0, 1, 1);

    TeamserverChat = new UserInterface::Widgets::Chat;
    TeamserverChat->TeamserverName = HavocX::Teamserver.Name;
    TeamserverChat->setupUi( new QWidget );

    NewBottomTab( TeamserverChat->ChatWidget, "Teamserver Chat", ":/icons/users" );
    tabWidget->setCurrentIndex( 0 );
    tabWidget->setMovable( false );

    SessionTableMenu_Interact = new QAction( "Interact" );
    SessionTableMenu_Explore  = new QMenu( "Explore" );

    SessionTableMenu_Explore_ProcessList  = new QAction( "Process List" );
    SessionTableMenu_Explore_FileExplorer = new QAction( "File Explorer" );
    SessionTableMenu_Explore->setStyleSheet( MenuStyle );

    SessionTableMenu_MarkAsDead = new QAction( "Mark as Dead" );
    SessionTableMenu_Export     = new QAction( "Export" );
    SessionTableMenu_Remove     = new QAction( "Remove" );
    SessionTableMenu_Exit       = new QAction( "Exit" );
    // SessionTableMenu_Info       = new QAction( "Info" );

    actionSeperator = new QAction(),
    actionSeperator1 = new QAction(),
    actionSeperator2 = new QAction(),
    actionSeperator3 = new QAction();

    actionSeperator->setSeparator ( true );
    actionSeperator1->setSeparator( true );
    actionSeperator2->setSeparator( true );
    actionSeperator3->setSeparator( true );

    SessionTableMenu_Explore->addAction( SessionTableMenu_Explore_ProcessList );
    SessionTableMenu_Explore->addAction( SessionTableMenu_Explore_FileExplorer );

    DemonContextMenu = new QMenu( this );
    DemonContextMenu->setStyleSheet( MenuStyle );
    DemonContextMenu->addAction( SessionTableMenu_Interact );
    DemonContextMenu->addAction( actionSeperator );
    DemonContextMenu->addAction( SessionTableMenu_Explore->menuAction() );
    DemonContextMenu->addAction( actionSeperator1 );
    DemonContextMenu->addAction( SessionTableMenu_MarkAsDead );
    DemonContextMenu->addAction( SessionTableMenu_Export );
    DemonContextMenu->addAction( actionSeperator2 );
    DemonContextMenu->addAction( SessionTableMenu_Remove );
    DemonContextMenu->addAction( SessionTableMenu_Exit );
    DemonContextMenu->addAction( actionSeperator3 );
    // DemonContextMenu->addAction( SessionTableMenu_Info );

    this->LootWidget = new ::LootWidget;

    NewWidgetTab( this->SmallAppWidgets->EventViewer->EventViewer, "Event Viewer" );

    connect( SessionTableWidget->SessionTableWidget, &QTableWidget::customContextMenuRequested, this, &TeamserverTabSession::handleDemonContextMenu );
    connect( tabWidget->tabBar(), &QTabBar::tabCloseRequested, this, &TeamserverTabSession::removeTab );
    connect( tabWidgetSmall->tabBar(), &QTabBar::tabCloseRequested, this, &TeamserverTabSession::removeTabSmall );

    connect( SessionTableMenu_Interact, &QAction::triggered, this, &TeamserverTabSession::Action_Menu_Interact );
    connect( SessionTableMenu_Explore_ProcessList, &QAction::triggered, this, &TeamserverTabSession::Action_Menu_Explore_ProcessList );
    connect( SessionTableMenu_Explore_FileExplorer, &QAction::triggered, this, &TeamserverTabSession::ActionMenuExploreFileBrowser );
    connect( SessionTableMenu_Remove, &QAction::triggered, this, &TeamserverTabSession::ActionMenuRemove );
    connect( SessionTableMenu_MarkAsDead, &QAction::triggered, this, &TeamserverTabSession::ActionMenuMarkAsDead );
    connect( SessionTableMenu_Exit, &QAction::triggered, this, [&](){
        auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();

        for ( auto & Session : HavocX::Teamserver.Sessions )
        {
            if ( SessionID.compare( Session.Name ) == 0 )
            {
                Session.InteractedWidget->DemonCommands->Execute.Exit( Util::gen_random( 8 ).c_str(), "process" );
                break;
            }
        }
    } );

    connect( SessionTableMenu_Export, &QAction::triggered, this, [&](){
        auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();

        for ( auto & Session : HavocX::Teamserver.Sessions )
        {
            if ( SessionID.compare( Session.Name ) == 0 )
            {
                Session.Export();
                break;
            }
        }
    } );

}

void UserInterface::Widgets::TeamserverTabSession::removeTab(int index) const {
    if (index == -1)
        return;

    tabWidget->removeTab(index);

    if (tabWidget->count() == 0) {
        this->splitter_TopBot->setSizes(QList<int>() << 0);
        splitter_TopBot->setStyleSheet("QSplitter::handle {  image: url(images/notExists.png); }");
    }
    else if (tabWidget->count() == 1)
        this->tabWidget->setMovable(false);
}

void UserInterface::Widgets::TeamserverTabSession::handleDemonContextMenu( const QPoint &pos )
{
    if ( ! SessionTableWidget->SessionTableWidget->itemAt( pos ) )
        return;

    this->DemonContextMenu->popup( SessionTableWidget->SessionTableWidget->horizontalHeader()->viewport()->mapToGlobal( pos ) );
}

void UserInterface::Widgets::TeamserverTabSession::Action_Menu_Interact() const
{
    auto SessionID = SessionTableWidget->SessionTableWidget->item(SessionTableWidget->SessionTableWidget->currentRow(), 0)->text();
    auto User = SessionTableWidget->SessionTableWidget->item(SessionTableWidget->SessionTableWidget->currentRow(), 2)->text();
    auto ComputerName = SessionTableWidget->SessionTableWidget->item(SessionTableWidget->SessionTableWidget->currentRow(), 3)->text();

    QString tabName =  "["+SessionID+"] " + User + "/" + ComputerName;

    for (auto & Session : HavocX::Teamserver.Sessions)
    {
        // TODO: make that on Session receive
        if ( Session.InteractedWidget == nullptr )
        {
            Session.InteractedWidget                 = new UserInterface::Widgets::DemonInteracted;
            Session.InteractedWidget->SessionInfo    = Session;
            Session.InteractedWidget->TeamserverName = this->TeamserverName;
            Session.InteractedWidget->setupUi( new QWidget );
        }

        if ( tabName.split( " " )[ 0 ] == "[" + Session.Name + "]"  )
        {
            for ( int i = 0 ; i < this->tabWidget->count(); i++ )
            {
                if ( this->tabWidget->tabText( i ) == tabName )
                {
                    this->tabWidget->setCurrentIndex( i );
                    return;
                }
            }

            NewBottomTab( Session.InteractedWidget->DemonInteractedWidget, tabName.toStdString(), ":/icons/demon-shell" );
            Session.InteractedWidget->lineEdit->setFocus();

        }
    }
}

void UserInterface::Widgets::TeamserverTabSession::Action_Menu_Explore_ProcessList() const
{
    auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();
    auto TabName = QString( "[" + SessionID + "] Process List" );

    for ( auto & Session : HavocX::Teamserver.Sessions )
    {
        if ( TabName.split(" ")[ 0 ] == "[" + Session.Name + "]" )
        {
            if ( Session.InteractedWidget == nullptr )
            {
                Session.InteractedWidget = new UserInterface::Widgets::DemonInteracted;
                Session.InteractedWidget->setupUi( new QWidget );
                Session.InteractedWidget->SessionInfo = Session;
            }

            if ( Session.ProcessList == nullptr )
            {
                Session.ProcessList = new UserInterface::Widgets::ProcessList;
                Session.ProcessList->setupUi( new QWidget );
                Session.ProcessList->Session = Session;
                Session.ProcessList->Teamserver = this->TeamserverName;
                NewBottomTab( Session.ProcessList->ProcessListWidget, TabName.toStdString(), "" );
            }

            Session.InteractedWidget->DemonCommands->Execute.ProcList( Util::gen_random( 8 ).c_str(), true );
        }
    }
}

void UserInterface::Widgets::TeamserverTabSession::ActionMenuRemove() const
{
    auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();

    for ( auto & Session : HavocX::Teamserver.Sessions )
    {
        if ( SessionID.compare( Session.Name ) == 0 )
        {
            auto indexes = SessionTableWidget->SessionTableWidget->selectionModel()->selectedRows();

            for ( int i = indexes.count(); i > 0; i-- )
            {
                SessionTableWidget->SessionTableWidget->removeRow( indexes.at( i - 1 ).row() );
            }
        }
    }
}

void UserInterface::Widgets::TeamserverTabSession::ActionMenuMarkAsDead() const
{
    auto selection = SessionTableWidget->SessionTableWidget->selectionModel()->selectedRows();

    spdlog::info( "selection count: {}", selection.count() );

    for ( int i = 0; i< selection.count(); i++ )
    {
        auto Package = new Util::Packager::Package;
        auto AgentID = SessionTableWidget->SessionTableWidget->item( selection.at( i ).row(), 0 )->text().toStdString();

        SessionTableWidget->SessionTableWidget->item( selection.at( i ).row(), 0 )->setIcon( QIcon( ":/icons/DeadWhite" ) );

        for ( int j = 0; j < SessionTableWidget->SessionTableWidget->columnCount(); j++ )
        {
            SessionTableWidget->SessionTableWidget->item( selection.at( i ).row(), j )->setBackground( QColor( Util::ColorText::Colors::Hex::CurrentLine ) );
            SessionTableWidget->SessionTableWidget->item( selection.at( i ).row(), j )->setForeground( QColor( Util::ColorText::Colors::Hex::Comment ) );
        }

        Package->Head = Util::Packager::Head_t {
                .Event= Util::Packager::Session::Type,
                .User = HavocX::Teamserver.User.toStdString(),
                .Time = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
        };

        Package->Body = Util::Packager::Body_t {
                .SubEvent = 0x5,
                .Info = {
                        { "AgentID", AgentID },
                }
        };

        HavocX::Connector->SendPackage( Package );
    }
}

void UserInterface::Widgets::TeamserverTabSession::NewBottomTab( QWidget* TabWidget, const string& TitleName, const QString IconPath ) const
{
    int id = 0;
    if ( tabWidget->count() == 0 )
    {
        this->splitter_TopBot->setSizes( QList<int>() << 100 << 200 );
        this->splitter_TopBot->setStyleSheet( "" );
    }
    else if ( tabWidget->count() == 1 )
        this->tabWidget->setMovable( true );

    this->tabWidget->setTabsClosable( true );

    id = tabWidget->addTab( TabWidget, TitleName.c_str() );

    tabWidget->setIconSize( QSize( 15, 15 ) );
    tabWidget->setCurrentIndex( id );
}

void UserInterface::Widgets::TeamserverTabSession::NewWidgetTab( QWidget *TabWidget, const std::string &TitleName ) const
{
    if ( tabWidgetSmall->count() == 0 )
    {
        splitter_SessionAndTabs->setSizes( QList<int>() << 200 << 10 );
        this->splitter_SessionAndTabs->setStyleSheet( "" );

        splitter_SessionAndTabs->handle( 1 )->setEnabled( true );
        splitter_SessionAndTabs->handle( 1 )->setCursor( Qt::SplitHCursor );
    }
    else if ( tabWidgetSmall->count() == 1)
        this->tabWidgetSmall->setMovable(true);

    this->tabWidgetSmall->setTabsClosable(true);

    int id = tabWidgetSmall->addTab(TabWidget, TitleName.c_str());
    tabWidget->setCurrentIndex(id);
}

void UserInterface::Widgets::TeamserverTabSession::removeTabSmall( int index ) const
{
    if ( index == -1 )
        return;

    tabWidgetSmall->removeTab( index );

    if ( tabWidgetSmall->count() == 0 )
    {
        splitter_SessionAndTabs->setSizes( QList<int>() << 0 );
        splitter_SessionAndTabs->setStyleSheet( "QSplitter::handle { image: url(images/notExists.png); }" );
        splitter_SessionAndTabs->handle( 1 )->setEnabled( false );
        splitter_SessionAndTabs->handle( 1 )->setCursor( Qt::ArrowCursor );
    }
    else if ( tabWidgetSmall->count() == 1 )
        this->tabWidgetSmall->setMovable( false );
}

bool TeamserverTabSession::event( QEvent* e )
{

}

void TeamserverTabSession::ActionMenuExploreFileBrowser() const
{
    auto SessionID = SessionTableWidget->SessionTableWidget->item( SessionTableWidget->SessionTableWidget->currentRow(), 0 )->text();
    auto TabName = QString( "[" + SessionID + "] File Explorer" );

    for ( auto & Session : HavocX::Teamserver.Sessions )
    {
        if ( TabName.split( " " )[ 0 ] == "[" + Session.Name + "]" )
        {
            if ( Session.InteractedWidget == nullptr )
            {
                Session.InteractedWidget = new UserInterface::Widgets::DemonInteracted;
                Session.InteractedWidget->setupUi( new QWidget );
                Session.InteractedWidget->SessionInfo = Session;
            }

            if ( Session.FileBrowser == nullptr )
            {
                Session.FileBrowser = new FileBrowser;
                Session.FileBrowser->setupUi( new QWidget );
                Session.FileBrowser->SessionID = Session.Name;

                NewBottomTab( Session.FileBrowser->FileBrowserWidget, TabName.toStdString(), "" );
            }

            Session.InteractedWidget->DemonCommands->Execute.FS( Util::gen_random( 8 ).c_str(), "dir;ui", "." );
        }
    }
}
