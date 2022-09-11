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

void HavocNamespace::UserInterface::Widgets::ListenersTable::setupUi(QWidget *Form) {
    this->ListenerWidget = Form;

    this->Packager = new HavocSpace::Packager;
    this->Packager->setTeamserver(this->TeamserverName);

    if (Form->objectName().isEmpty())
        Form->setObjectName(QString::fromUtf8("Form"));
    Form->resize(1227, 675);

    gridLayout = new QGridLayout(Form);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setContentsMargins(0,0,0,3);

    pushButton = new QPushButton(Form);
    pushButton->setObjectName(QString::fromUtf8("pushButton_New_Profile"));
    gridLayout->addWidget(pushButton, 1, 1, 1, 1);

    pushButton_3 = new QPushButton(Form);
    pushButton_3->setObjectName(QString::fromUtf8("pushButton_3"));
    gridLayout->addWidget(pushButton_3, 1, 3, 1, 1);

    pushButton_4 = new QPushButton(Form);
    pushButton_4->setObjectName(QString::fromUtf8("pushButton_4"));
    gridLayout->addWidget(pushButton_4, 1, 4, 1, 1);

    pushButton_2 = new QPushButton(Form);
    pushButton_2->setObjectName(QString::fromUtf8("pushButton_Close"));
    gridLayout->addWidget(pushButton_2, 1, 2, 1, 1);

    horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    gridLayout->addItem(horizontalSpacer_2, 1, 5, 1, 1);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    gridLayout->addItem(horizontalSpacer, 1, 0, 1, 1);

    tableWidget = new QTableWidget(Form);
    if (tableWidget->columnCount() < 5)
        tableWidget->setColumnCount(5);

    auto *_qtablewidgetitem = new QTableWidgetItem();
    tableWidget->setHorizontalHeaderItem(0, _qtablewidgetitem);
    auto *_qtablewidgetitem1 = new QTableWidgetItem();
    tableWidget->setHorizontalHeaderItem(1, _qtablewidgetitem1);
    auto *_qtablewidgetitem2 = new QTableWidgetItem();
    tableWidget->setHorizontalHeaderItem(2, _qtablewidgetitem2);
    auto *_qtablewidgetitem3 = new QTableWidgetItem();
    tableWidget->setHorizontalHeaderItem(3, _qtablewidgetitem3);
    auto *_qtablewidgetitem4 = new QTableWidgetItem();
    tableWidget->setHorizontalHeaderItem(4, _qtablewidgetitem4);
    // auto *_qtablewidgetitem5 = new QTableWidgetItem();
    // tableWidget->setHorizontalHeaderItem(5, _qtablewidgetitem5);

    tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
    tableWidget->setMouseTracking(false);
    tableWidget->setContextMenuPolicy(Qt::ActionsContextMenu);
    tableWidget->setAutoFillBackground(false);
    tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tableWidget->setShowGrid(false);
    tableWidget->setSortingEnabled(false);
    tableWidget->setWordWrap(true);
    tableWidget->setCornerButtonEnabled(true);
    tableWidget->horizontalHeader()->setVisible(true);
    tableWidget->horizontalHeader()->setCascadingSectionResizes(false);
    tableWidget->horizontalHeader()->setHighlightSections(false);
    tableWidget->verticalHeader()->setVisible(false);
    tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableWidget->verticalHeader()->setDefaultSectionSize(12);
    tableWidget->setFocusPolicy(Qt::NoFocus);

    gridLayout->addWidget(tableWidget, 0, 0, 1, 6);

    Form->setWindowTitle(QCoreApplication::translate("Form", "Form", nullptr));
    pushButton->setText(QCoreApplication::translate("Form", "Add", nullptr));
    pushButton_3->setText(QCoreApplication::translate("Form", "Restart", nullptr));
    pushButton_4->setText(QCoreApplication::translate("Form", "Edit", nullptr));
    pushButton_2->setText(QCoreApplication::translate("Form", "Remove", nullptr));

    QTableWidgetItem *listener_Title_Name = tableWidget->horizontalHeaderItem(0);
    listener_Title_Name->setText(QCoreApplication::translate("Form", "Name", nullptr));

    QTableWidgetItem *listener_Title_Protocol = tableWidget->horizontalHeaderItem(1);
    listener_Title_Protocol->setText(QCoreApplication::translate("Form", "Protocol", nullptr));

    QTableWidgetItem *listener_Title_Host = tableWidget->horizontalHeaderItem(2);
    listener_Title_Host->setText(QCoreApplication::translate("Form", "Host", nullptr));

    QTableWidgetItem *listener_Title_Port = tableWidget->horizontalHeaderItem(3);
    listener_Title_Port->setText(QCoreApplication::translate("Form", "Port", nullptr));

    QTableWidgetItem *listener_Title_Status = tableWidget->horizontalHeaderItem( 4 );
    listener_Title_Status->setText( QCoreApplication::translate( "Form", "Status", nullptr ) );

    ButtonsInit();
    QMetaObject::connectSlotsByName( Form );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::ButtonsInit()
{
    QObject::connect( pushButton, &QPushButton::clicked, this, &Widgets::ListenersTable::onButtonAdd );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::NewListenerItem( Util::ListenerItem item ) const
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

    auto *item_Name     = new QTableWidgetItem();
    auto *item_Protocol = new QTableWidgetItem();
    auto *item_Host     = new QTableWidgetItem();
    auto *item_Port     = new QTableWidgetItem();
    auto *item_Status   = new QTableWidgetItem();

    item_Name->setText( item.Name.c_str() );
    item_Name->setFlags( item_Name->flags() ^ Qt::ItemIsEditable );
    item_Name->setTextAlignment( Qt::AlignLeft );

    item_Protocol->setText( item.Protocol.c_str() );
    item_Protocol->setFlags( item_Protocol->flags() ^ Qt::ItemIsEditable );
    item_Protocol->setTextAlignment( Qt::AlignLeft );

    if ( item.Protocol.compare( "Smb" ) == 0 )
        item_Host->setText( "\\\\.\\pipe\\" + QString( item.Host.c_str() ) );
    else
        item_Host->setText( item.Host.c_str() );
    item_Host->setFlags( item_Host->flags() ^ Qt::ItemIsEditable );
    item_Host->setTextAlignment( Qt::AlignLeft );

    item_Port->setText( item.Port.c_str() );
    item_Port->setFlags( item_Port->flags() ^ Qt::ItemIsEditable );
    item_Port->setTextAlignment( Qt::AlignLeft );

    item_Status->setText( item.Status.c_str() );
    item_Status->setFlags( item_Status->flags() ^ Qt::ItemIsEditable );
    item_Status->setTextAlignment( Qt::AlignLeft );

    if ( item.Status.compare( "online" ) == 0 )
    {
        item_Status->setForeground( QColor( Util::ColorText::Colors::Hex::Green ) );
    }

    tableWidget->setItem( tableWidget->rowCount() - 1, 0, item_Name );
    tableWidget->setItem( tableWidget->rowCount() - 1, 1, item_Protocol );
    tableWidget->setItem( tableWidget->rowCount() - 1, 2, item_Host );
    tableWidget->setItem( tableWidget->rowCount() - 1, 3, item_Port );
    tableWidget->setItem( tableWidget->rowCount() - 1, 4, item_Status );

    tableWidget->setSortingEnabled( isSortingEnabled );

    std::string Protocol = item.Protocol;
    std::transform( Protocol.begin(), Protocol.end(), Protocol.begin(), ::tolower );

    auto Time   = QTime::currentTime().toString( "hh:mm:ss" );

    HavocX::Teamserver.Listeners.push_back( item );
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::setDBManager( HavocSpace::DBManager* dbManager )
{
    this->dbManager = dbManager;
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::onButtonAdd() const
{
    auto ListenerDialog = new UserInterface::Dialogs::NewListener( new QDialog );
    auto ListenerInfo   = ListenerDialog->Start();

    if ( ListenerDialog->DialogSaved )
    {
        auto Package = this->CreateNewPackage( Util::Packager::Listener::Add, ListenerInfo );
        HavocX::Connector->SendPackage( &Package );
    }
}

void HavocNamespace::UserInterface::Widgets::ListenersTable::onButtonEdit() const {

}

void HavocNamespace::UserInterface::Widgets::ListenersTable::onButtonRemove() const {

}

void HavocNamespace::UserInterface::Widgets::ListenersTable::onButtonRestart() const {

}

Util::Packager::Package UserInterface::Widgets::ListenersTable::CreateNewPackage( int EventID, map<string, string> Listener ) const
{
    Util::Packager::Package ListenerPackage;

    auto Head = Util::Packager::Head_t {
            .Event = Util::Packager::Listener::Type,
            .User = HavocX::Teamserver.User.toStdString(),
            .Time = QTime::currentTime().toString("hh:mm:ss").toStdString(),
    };

    Util::Packager::Body_t Body;

    switch ( EventID )
    {
        case 0x1:
        {
            // TODO: check protocol first then convert info
            auto BodyInfo = QMap<string, string>( Listener );

            Body.SubEvent = Util::Packager::Listener::Add;
            Body.Info     = BodyInfo;

            ListenerPackage.Head = Head;
            ListenerPackage.Body = Body;

            return ListenerPackage;
        }

        case 0x2:
        {

        }

        case 0x3: {

        }

        case 0x4: {

        }

        case 0x5: {

        }

    };
    return Util::Packager::Package();
}
