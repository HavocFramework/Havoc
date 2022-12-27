#include <Havoc/Havoc.hpp>
#include <global.hpp>

#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/TeamserverTabSession.h>
#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>

#include <QHeaderView>
#include <QItemSelectionModel>
#include <Util/ColorText.h>

using namespace HavocNamespace::UserInterface::Widgets;
using namespace HavocNamespace::Util;

void HavocNamespace::UserInterface::Widgets::SessionTable::setupUi(QWidget *Form, QString TeamserverName)
{
    this->TeamserverName = TeamserverName;

    if ( Form->objectName().isEmpty() )
        Form->setObjectName( QString::fromUtf8( "Form" ) );

    gridLayout = new QGridLayout( Form );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    SessionTableWidget = new QTableWidget( Form );

    if ( SessionTableWidget->columnCount() < 9 )
        SessionTableWidget->setColumnCount( 9 );

    SessionTableWidget->setStyleSheet(
        "QTableWidget { "
        "   background-color: #282a36;"
        "   color: #f8f8f2; "
        "}"
    );

    TitleAgentID     = new QTableWidgetItem( "ID" );
    TitleInternal    = new QTableWidgetItem( "Internal" );
    TitleUser        = new QTableWidgetItem( "User" );
    TitleComputer    = new QTableWidgetItem( "Computer" );
    TitleOperating   = new QTableWidgetItem( "OS" );
    TitleProcess     = new QTableWidgetItem( "Process" );
    TitleProcessId   = new QTableWidgetItem( "PID" );
    TitleArch        = new QTableWidgetItem( "Arch" );
    TitleLast        = new QTableWidgetItem( "Last" );

    SessionTableWidget->setHorizontalHeaderItem( 0, TitleAgentID );
    SessionTableWidget->setHorizontalHeaderItem( 1, TitleInternal );
    SessionTableWidget->setHorizontalHeaderItem( 2, TitleUser );
    SessionTableWidget->setHorizontalHeaderItem( 3, TitleComputer );
    SessionTableWidget->setHorizontalHeaderItem( 4, TitleOperating );
    SessionTableWidget->setHorizontalHeaderItem( 5, TitleProcess );
    SessionTableWidget->setHorizontalHeaderItem( 6, TitleProcessId );
    SessionTableWidget->setHorizontalHeaderItem( 7, TitleArch );
    SessionTableWidget->setHorizontalHeaderItem( 8, TitleLast );
    SessionTableWidget->horizontalHeader()->resizeSection( 5, 150 );

    SessionTableWidget->setObjectName( QString::fromUtf8( "tableWidget" ) );
    SessionTableWidget->setEnabled( true );
    SessionTableWidget->setShowGrid( false );
    SessionTableWidget->setSortingEnabled( false );
    SessionTableWidget->setWordWrap( true );
    SessionTableWidget->setCornerButtonEnabled( true );
    SessionTableWidget->horizontalHeader()->setVisible( true );
    SessionTableWidget->setSelectionBehavior( QAbstractItemView::SelectRows );
    SessionTableWidget->setContextMenuPolicy( Qt::CustomContextMenu );
    SessionTableWidget->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    SessionTableWidget->verticalHeader()->setVisible(false);
    SessionTableWidget->verticalHeader()->setStretchLastSection( false );
    SessionTableWidget->verticalHeader()->setDefaultSectionSize( 12 );
    SessionTableWidget->setFocusPolicy( Qt::NoFocus );

    SessionTableWidget->horizontalHeaderItem( 0 )->setSizeHint( QSize( 0, 0 ) );

    connect( SessionTableWidget, &QTableWidget::itemSelectionChanged, this, &HavocNamespace::UserInterface::Widgets::SessionTable::updateRow );

    gridLayout->addWidget( SessionTableWidget, 0, 0, 1, 1 );

    QMetaObject::connectSlotsByName( Form );
}

void HavocNamespace::UserInterface::Widgets::SessionTable::NewSessionItem( Util::SessionItem item ) const
{
    for ( auto& session : HavocX::Teamserver.Sessions )
    {
        if ( session.Name.compare( item.Name ) == 0 )
        {
            // it seems that a session with that name already exists. do not add
            return;
        }
    }

    HavocX::Teamserver.Sessions.push_back( item );

    if ( SessionTableWidget->rowCount() < 1 )
        SessionTableWidget->setRowCount( 1 );
    else
        SessionTableWidget->setRowCount( SessionTableWidget->rowCount() + 1 );

    const bool isSortingEnabled = SessionTableWidget->isSortingEnabled();
    SessionTableWidget->setSortingEnabled( false );

    auto *item_ID        = new QTableWidgetItem();
    auto *item_Internal  = new QTableWidgetItem();
    auto *item_User      = new QTableWidgetItem();
    auto *item_Computer  = new QTableWidgetItem();
    auto *item_OS        = new QTableWidgetItem();
    auto *item_Process   = new QTableWidgetItem();
    auto *item_ProcessID = new QTableWidgetItem();
    auto *item_Arch      = new QTableWidgetItem();
    auto *item_Last      = new QTableWidgetItem();
    auto Icon            = QIcon();

    if ( item.Elevated.compare( "true" ) == 0 )
    {
        item_ID->setForeground( QColor( 255, 85, 85 ) );
        Icon = WinVersionIcon( item.OS, true );
    } else Icon = WinVersionIcon( item.OS, false );

    item_ID->setText( item.Name );
    item_ID->setIcon( Icon );
    item_ID->setTextAlignment( Qt::AlignCenter );
    item_ID->setFlags( item_ID->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount() - 1, 0, item_ID );

    item_Internal->setText( item.Internal );
    item_Internal->setTextAlignment( Qt::AlignCenter );
    item_Internal->setFlags( item_Internal->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 1, item_Internal );

    item_User->setText( item.User );
    item_User->setTextAlignment( Qt::AlignCenter );
    item_User->setFlags( item_User->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 2, item_User );

    item_Computer->setText( item.Computer );
    item_Computer->setTextAlignment( Qt::AlignCenter );
    item_Computer->setFlags( item_Computer->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 3, item_Computer );

    item_OS->setText( item.OS );
    item_OS->setTextAlignment( Qt::AlignCenter );
    item_OS->setFlags( item_OS->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 4, item_OS );

    item_Process->setText( item.Process );
    item_Process->setTextAlignment( Qt::AlignCenter );
    item_Process->setFlags( item_Process->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 5, item_Process );

    item_ProcessID->setText( item.PID );
    item_ProcessID->setTextAlignment( Qt::AlignCenter );
    item_ProcessID->setFlags( item_ProcessID->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 6, item_ProcessID );

    item_Arch->setText( item.Arch );
    item_Arch->setTextAlignment( Qt::AlignCenter );
    item_Arch->setFlags( item_Arch->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 7, item_Arch );

    item_Last->setText( item.Last );
    item_Last->setTextAlignment( Qt::AlignCenter );
    item_Last->setFlags( item_Last->flags() ^ Qt::ItemIsEditable );
    SessionTableWidget->setItem( SessionTableWidget->rowCount()-1, 8, item_Last );

    SessionTableWidget->setSortingEnabled( isSortingEnabled );

    for ( auto & Session : HavocX::Teamserver.Sessions )
    {
        // TODO: make that on Session receive
        if ( Session.InteractedWidget == nullptr )
        {
            auto AgentMessageInfo = QString();
            auto prev_cursor      = QTextCursor();
            auto PivotStream      = QString();

            Session.InteractedWidget                 = new UserInterface::Widgets::DemonInteracted;
            Session.InteractedWidget->SessionInfo    = Session;
            Session.InteractedWidget->TeamserverName = this->TeamserverName;
            Session.InteractedWidget->setupUi( new QWidget );

            if ( item.PivotParent.size() > 0 )
            {
                PivotStream = "[Pivot: " + item.PivotParent + Util::ColorText::Cyan( "-<>-<>-" ) + item.Name + "]";
                HavocX::Teamserver.TabSession->SessionGraphWidget->GraphPivotNodeAdd( item.PivotParent, item );
            }
            else
            {
                PivotStream = "[Pivot: "+ Util::ColorText::Cyan( "Direct" ) +"]";
                HavocX::Teamserver.TabSession->SessionGraphWidget->GraphNodeAdd( item );
            }

            AgentMessageInfo =
                    Util::ColorText::Comment( item.First ) + " Agent " + Util::ColorText::Red( item.Name.toUpper() ) + " authenticated as "+ Util::ColorText::Purple( item.Computer + "\\" + item.User ) +
                    " :: [Internal: " + Util::ColorText::Cyan( item.Internal ) + "] [Process: " + Util::ColorText::Red( item.Process + "\\" + item.PID ) + "] [Arch: " + Util::ColorText::Pink( item.Arch ) + "] " + PivotStream;

            prev_cursor = Session.InteractedWidget->Console->textCursor();

            Session.InteractedWidget->Console->moveCursor( QTextCursor::End );
            Session.InteractedWidget->Console->insertHtml( AgentMessageInfo );

            Session.InteractedWidget->Console->setTextCursor( prev_cursor );
        }
    }
}

void UserInterface::Widgets::SessionTable::ChangeSessionValue( QString DemonID, int key, QString value )
{
    for ( int i = 0; i < SessionTableWidget->rowCount(); i++ )
    {
        if ( SessionTableWidget->item( i, 0 )->text() == DemonID )
            SessionTableWidget->item( i, key )->setText( value );
    }
}

void UserInterface::Widgets::SessionTable::RemoveSession( Util::SessionItem Session )
{
    for ( int i = 0; i < SessionTableWidget->rowCount(); i++ )
    {
        if ( SessionTableWidget->item( i, 0 )->text() == Session.Name )
            spdlog::info( "Want to remove: {}", Session.Name.toStdString() );
    }
}

void HavocNamespace::UserInterface::Widgets::SessionTable::updateRow()
{
    bool selected = false;

    for ( int count = 0; count < SessionTableWidget->rowCount(); count++ )
        if ( SessionTableWidget->item( count, 0 )->isSelected() )
            selected = true;

    if ( ! selected )
        SessionTableWidget->clearFocus();
}
