#include <global.hpp>
#include <QHeaderView>

#include <UserInterface/Widgets/ListenerTable.hpp>
#include <UserInterface/Dialogs/Listener.hpp>
#include "Include/Havoc/Packager.hpp"
#include "Include/Havoc/Connector.hpp"
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/Widgets/Chat.hpp>
#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <Util/ColorText.h>

#include <QMap>

void HavocNamespace::UserInterface::Widgets::ListenersTable::setupUi( QWidget* Form )
{
    this->ListenerWidget = Form;

    if ( Form->objectName().isEmpty() )
        Form->setObjectName( QString::fromUtf8( "ListenerTable" ) );

    gridLayout = new QGridLayout( Form );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    gridLayout->setContentsMargins( 0, 0, 0, 3 );

    buttonAdd = new QPushButton( Form );
    buttonAdd->setObjectName( QString::fromUtf8( "pushButton_New_Profile" ) );
    gridLayout->addWidget( buttonAdd, 1, 1, 1, 1 );

    buttonRemove = new QPushButton( Form );
    buttonRemove->setObjectName( QString::fromUtf8( "pushButton_Close" ) );
    gridLayout->addWidget( buttonRemove, 1, 2, 1, 1 );

    buttonEdit = new QPushButton( Form );
    buttonEdit->setObjectName( QString::fromUtf8( "pushButton_4" ) );
    gridLayout->addWidget( buttonEdit, 1, 3, 1, 1 );

    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    gridLayout->addItem( horizontalSpacer_2, 1, 4, 1, 1 );

    horizontalSpacer = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    gridLayout->addItem( horizontalSpacer, 1, 0, 1, 1 );

    tableWidget = new QTableWidget( Form );
    if ( tableWidget->columnCount() < 5 )
        tableWidget->setColumnCount( 5 );

    tableWidget->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" )     );
    tableWidget->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Protocol" ) );
    tableWidget->setHorizontalHeaderItem( 2, new QTableWidgetItem( "Host" )     );
    tableWidget->setHorizontalHeaderItem( 3, new QTableWidgetItem( "Port" )     );
    tableWidget->setHorizontalHeaderItem( 4, new QTableWidgetItem( "Status" )   );

    tableWidget->setObjectName( QString::fromUtf8( "tableWidget" ) );
    tableWidget->setMouseTracking( false );
    tableWidget->setContextMenuPolicy( Qt::ActionsContextMenu );
    tableWidget->setAutoFillBackground( false );
    tableWidget->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    tableWidget->setShowGrid( false );
    tableWidget->setSortingEnabled( false );
    tableWidget->setWordWrap( true );
    tableWidget->setCornerButtonEnabled( true );
    tableWidget->horizontalHeader()->setVisible( true );
    tableWidget->horizontalHeader()->setCascadingSectionResizes( false );
    tableWidget->horizontalHeader()->setHighlightSections( false );
    tableWidget->verticalHeader()->setVisible( false );
    tableWidget->setSelectionBehavior( QAbstractItemView::SelectRows );
    tableWidget->setSelectionMode( QAbstractItemView::SingleSelection );
    tableWidget->verticalHeader()->setDefaultSectionSize( 12 );
    tableWidget->setFocusPolicy( Qt::NoFocus );

    gridLayout->addWidget( tableWidget, 0, 0, 1, 6 );

    Form->setWindowTitle( QCoreApplication::translate( "Form", "Listener", nullptr ) );

    buttonAdd->setText( QCoreApplication::translate(" Form", "Add", nullptr ) );
    buttonEdit->setText( QCoreApplication::translate( "Form", "Edit", nullptr ) );
    buttonRemove->setText( QCoreApplication::translate( "Form", "Remove", nullptr ) );

    ButtonsInit();
    QMetaObject::connectSlotsByName( Form );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::ButtonsInit()
{
    QObject::connect( buttonAdd, &QPushButton::clicked, this, [&]()
    {
        auto ListenerDialog = new UserInterface::Dialogs::NewListener( new QDialog );
        auto ListenerInfo   = MapStrStr();

        /* add custom listeners to it. */
        for ( const auto& listenerService : HavocX::Teamserver.RegisteredListeners )
            ListenerDialog->ListenerCustomAdd( listenerService.dump().c_str() );

        ListenerInfo = ListenerDialog->Start( {}, false );

        if ( ListenerDialog->DialogSaved )
        {
            if ( ! ListenerInfo.empty() )
            {
                auto Package = CreateNewPackage( Util::Packager::Listener::Add, ListenerInfo );
                HavocX::Connector->SendPackage( &Package );
            }
        }
    } );

    QObject::connect( buttonEdit, &QPushButton::clicked, this, [&]()
    {
        if ( tableWidget->selectionModel()->selectedRows().empty() )
        {
            MessageBox( "Listener Error", "Select one listener to edit", QMessageBox::Icon::Critical );
            return;
        }

        auto ListenerName   = QString();
        auto ListenerItem   = Util::ListenerItem{};
        auto ListenerDialog = ( UserInterface::Dialogs::NewListener* ) nullptr;
        auto ListenerInfo   = MapStrStr();

        ListenerName = tableWidget->item( tableWidget->currentRow(), 0 )->text();

        for ( auto& listener : HavocX::Teamserver.Listeners )
        {
            if ( listener.Name == ListenerName.toStdString() )
            {
                ListenerItem = listener;
                break;
            }
        }

        ListenerDialog = new UserInterface::Dialogs::NewListener( new QDialog );

        /* add custom listeners to it. */
        for ( const auto& listenerService : HavocX::Teamserver.RegisteredListeners )
            ListenerDialog->ListenerCustomAdd( listenerService.dump().c_str() );

        ListenerInfo = ListenerDialog->Start( ListenerItem, true );

        if ( ListenerDialog->DialogSaved )
        {
            if ( ! ListenerInfo.empty() )
            {
                auto Package = CreateNewPackage( Util::Packager::Listener::Edit, ListenerInfo );
                HavocX::Connector->SendPackage( &Package );
            }
        }

        delete ListenerDialog;
    } );

    QObject::connect( buttonRemove,  &QPushButton::clicked, this, [&]()
    {
        if ( tableWidget->selectionModel()->selectedRows().empty() )
        {
            MessageBox( "Listener Error", "Select one listener to remove", QMessageBox::Icon::Critical );
            return;
        }
        auto Name = tableWidget->item( tableWidget->currentRow(), 0 )->text().toStdString();

        tableWidget->removeRow( tableWidget->currentRow() );
        for ( int i = 0; i < HavocX::Teamserver.Listeners.size(); i++ )
        {
            if ( HavocX::Teamserver.Listeners[ i ].Name == Name )
            {
                HavocX::Teamserver.Listeners.erase( HavocX::Teamserver.Listeners.begin() + i );
            }
        }

        auto Info = map<string, string>();
        Info.insert( { "Name", Name } );

        auto Package = CreateNewPackage( Util::Packager::Listener::Remove, Info );
        HavocX::Connector->SendPackage( &Package );
    } );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::ListenerAdd( Util::ListenerItem item ) const
{
    for ( auto& listener : HavocX::Teamserver.Listeners )
    {
        if ( listener.Name.compare( item.Name ) == 0 )
        {
            return;
        }
    }

    if ( tableWidget->rowCount() < 1 )
        tableWidget->setRowCount( 1 );
    else
        tableWidget->setRowCount( tableWidget->rowCount() + 1 );

    const bool isSortingEnabled = tableWidget->isSortingEnabled();
    tableWidget->setSortingEnabled( false );

    auto item_Name     = new QTableWidgetItem();
    auto item_Protocol = new QTableWidgetItem();
    auto item_Host     = new QTableWidgetItem();
    auto item_Port     = new QTableWidgetItem();
    auto item_Status   = new QTableWidgetItem();

    item_Name->setText( item.Name.c_str() );
    item_Name->setFlags( item_Name->flags() ^ Qt::ItemIsEditable );
    item_Name->setTextAlignment( Qt::AlignLeft );

    item_Protocol->setText( item.Protocol.c_str() );
    item_Protocol->setFlags( item_Protocol->flags() ^ Qt::ItemIsEditable );
    item_Protocol->setTextAlignment( Qt::AlignLeft );

    if ( item.Protocol == Listener::PayloadSMB.toStdString() )
    {
        item_Host->setText( R"(\\.\pipe\)" + any_cast<Listener::SMB>(item.Info).PipeName );
    }
    else if ( item.Protocol == Listener::PayloadHTTP.toStdString() || item.Protocol == Listener::PayloadHTTPS.toStdString() )
    {
        item_Host->setText( any_cast<Listener::HTTP>( item.Info ).HostBind );
        item_Port->setText( any_cast<Listener::HTTP>( item.Info ).Port );
    }
    else if ( item.Protocol == Listener::PayloadExternal.toStdString() )
    {
        item_Host->setText( any_cast<Listener::External>( item.Info ).Endpoint );
    }
    else
    {
        auto Host = QString();
        auto Port = QString();

        Host = QString( any_cast<MapStrStr>( any_cast<Listener::Service>( item.Info ) )[ "Host" ].c_str() );
        Port = QString( any_cast<MapStrStr>( any_cast<Listener::Service>( item.Info ) )[ "Port" ].c_str() );

        item_Host->setText( Host );
        item_Port->setText( Port );
    }

    item_Host->setFlags( item_Host->flags() ^ Qt::ItemIsEditable );
    item_Host->setTextAlignment( Qt::AlignLeft );

    item_Port->setFlags( item_Port->flags() ^ Qt::ItemIsEditable );
    item_Port->setTextAlignment( Qt::AlignLeft );

    item_Status->setText( item.Status.c_str() );
    item_Status->setFlags( item_Status->flags() ^ Qt::ItemIsEditable );
    item_Status->setTextAlignment( Qt::AlignLeft );

    if ( item.Status.compare( "Online" ) == 0 )
    {
        item_Status->setForeground( QColor( Util::ColorText::Colors::Hex::Green ) );
    }
    else if ( item.Status.compare( "Offline" ) == 0 )
    {
        item_Status->setForeground( QColor( Util::ColorText::Colors::Hex::Red ) );
    }

    tableWidget->setItem( tableWidget->rowCount() - 1, 0, item_Name );
    tableWidget->setItem( tableWidget->rowCount() - 1, 1, item_Protocol );
    tableWidget->setItem( tableWidget->rowCount() - 1, 2, item_Host );
    tableWidget->setItem( tableWidget->rowCount() - 1, 3, item_Port );
    tableWidget->setItem( tableWidget->rowCount() - 1, 4, item_Status );

    tableWidget->setSortingEnabled( isSortingEnabled );

    std::string Protocol = item.Protocol;
    std::transform( Protocol.begin(), Protocol.end(), Protocol.begin(), ::tolower );

    auto Time = QTime::currentTime().toString( "hh:mm:ss" );

    HavocX::Teamserver.Listeners.push_back( item );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::setDBManager( HavocSpace::DBManager* dbManager )
{
    this->dbManager = dbManager;
}

Util::Packager::Package UserInterface::Widgets::ListenersTable::CreateNewPackage( int EventID, map<string, string> Listener ) const
{
    Util::Packager::Package ListenerPackage;

    auto Head = Util::Packager::Head_t {
            .Event = Util::Packager::Listener::Type,
            .User  = HavocX::Teamserver.User.toStdString(),
            .Time  = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
    };

    Util::Packager::Body_t Body;

    auto BodyInfo = QMap<string, string>( Listener );

    Body.SubEvent = EventID;
    Body.Info     = BodyInfo;

    ListenerPackage.Head = Head;
    ListenerPackage.Body = Body;

    return ListenerPackage;
}

void UserInterface::Widgets::ListenersTable::ListenerEdit( Util::ListenerItem item ) const
{
    for ( int i = 0; i < HavocX::Teamserver.Listeners.size(); i++ )
    {
        if ( HavocX::Teamserver.Listeners[ i ].Name == item.Name )
        {
            HavocX::Teamserver.Listeners[ i ].Info = item.Info;
        }
    }
}

void UserInterface::Widgets::ListenersTable::ListenerRemove( QString ListenerName ) const
{
    auto Name = QString();

    if ( ! ListenerName.isEmpty() )
    {
        if ( tableWidget->rowCount() > 0 )
        {
            for ( int i = 0; i < tableWidget->rowCount(); i++ )
            {
                Name = tableWidget->item( i, 0 )->text();

                if ( Name.compare( ListenerName ) == 0 )
                {
                    spdlog::debug( "Remove listener from table" );
                    tableWidget->removeRow( i );
                }
            }
        }

        if ( ! HavocX::Teamserver.Listeners.empty() )
        {
            for ( int i = 0; i < HavocX::Teamserver.Listeners.size(); i++ )
            {
                if ( HavocX::Teamserver.Listeners[ i ].Name == ListenerName.toStdString() )
                {
                    spdlog::debug( "Remove listener from list" );
                    HavocX::Teamserver.Listeners.erase( HavocX::Teamserver.Listeners.begin() + i );
                }
            }
        }
    }
}

void UserInterface::Widgets::ListenersTable::ListenerError( QString ListenerName, QString Error ) const
{
    for ( int i = 0; i < tableWidget->rowCount(); i++ )
    {
        auto Row = tableWidget->item( i, 0 )->text();

        if ( Row.compare( ListenerName ) == 0 )
        {
            for ( int j = 0; j < tableWidget->columnCount(); j++ )
            {
                tableWidget->item( i, j )->setBackground( QColor( Util::ColorText::Colors::Hex::Background ) );
                tableWidget->item( i, j )->setForeground( QColor( Util::ColorText::Colors::Hex::Red ) );
                tableWidget->item( i, j )->setToolTip( Error );
            }

            tableWidget->item( i, 4 )->setText( "Offline [" + Error + " ]" );
        }
    }

}
