#include <UserInterface/Widgets/ProcessList.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <QClipboard>

void HavocNamespace::UserInterface::Widgets::ProcessList::setupUi(QWidget *Widget) {
    this->ProcessListWidget = Widget;

    QString MenuStyle = "QMenu {\n"
                        "    background-color: #282a36;\n"
                        "    color: #f8f8f2;\n"
                        "    border: 1px solid #44475a;\n"
                        "}\n"
                        "\n"
                        "QMenu::separator {\n"
                        "    background: #44475a;\n"
                        "}\n"
                        "\n"
                        "QMenu::item:selected {\n"
                        "    background: #44475a;\n"
                        "}\n"
                        "\n"
                        "QAction {\n"
                        "    background-color: #282a36;\n"
                        "    color: #f8f8f2;\n"
                        "}";


    if (this->ProcessListWidget->objectName().isEmpty())
        this->ProcessListWidget->setObjectName(QString::fromUtf8("ProcessListWidget"));
    this->ProcessListWidget->resize(1012, 535);
    gridLayout = new QGridLayout(this->ProcessListWidget);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    splitter = new QSplitter(this->ProcessListWidget);
    splitter->setObjectName(QString::fromUtf8("splitter"));
    splitter->setOrientation(Qt::Horizontal);
    ProcessTree = new QTreeWidget(splitter);

    ProcessTree->setObjectName(QString::fromUtf8("ProcessTree"));
    ProcessTree->setAnimated(false);
    ProcessTree->header()->setVisible(false);
    ProcessTree->setContextMenuPolicy(Qt::CustomContextMenu);
    ProcessTree->setStyleSheet(
                               "QTreeView::branch:has-siblings:!adjoins-item {\n"
                               "    border-image: url(:/treewidget/vline) 0;\n"
                               "}\n"
                               "\n"
                               "QTreeView::branch:has-siblings:adjoins-item {\n"
                               "    border-image: url(:/treewidget/branch-more) 0;\n"
                               "}\n"
                               "\n"
                               "QTreeView::branch:!has-children:!has-siblings:adjoins-item {\n"
                               "    border-image: url(:/treewidget/branch-end) 0;\n"
                               "}\n"
                               "\n"
                               "QTreeView::branch:has-children:!has-siblings:closed,\n"
                               "QTreeView::branch:closed:has-children:has-siblings {\n"
                               "        border-image: none;\n"
                               "        image: url(:/treewidget/branch-closed);\n"
                               "}\n"
                               "\n"
                               "QTreeView::branch:open:has-children:!has-siblings,\n"
                               "QTreeView::branch:open:has-children:has-siblings  {\n"
                               "        border-image: none;\n"
                               "        image: url(:/treewidget/branch-open);\n"
                               "}"
                               "QMenu {\n"
                               "    background-color: #282a36;\n"
                               "    color: #f8f8f2;\n"
                               "    border: 1px solid #44475a;\n"
                               "}\n"
                               "\n"
                               "QMenu::separator {\n"
                               "    background: #44475a;\n"
                               "}\n"
                               "\n"
                               "QMenu::item:selected {\n"
                               "    background: #44475a;\n"
                               "}\n"
                               "\n"
                               "QAction {\n"
                               "    background-color: #282a36;\n"
                               "    color: #f8f8f2;\n"
                               "}");

    splitter->addWidget(ProcessTree);

    ProcessTable = new QTableWidget(splitter);

    if (ProcessTable->columnCount() < 6)
        ProcessTable->setColumnCount(6);

    ProcessTable->setHorizontalHeaderItem(0, new QTableWidgetItem());
    ProcessTable->setHorizontalHeaderItem(1, new QTableWidgetItem());
    ProcessTable->setHorizontalHeaderItem(2, new QTableWidgetItem());
    ProcessTable->setHorizontalHeaderItem(3, new QTableWidgetItem());
    ProcessTable->setHorizontalHeaderItem(4, new QTableWidgetItem());
    ProcessTable->setHorizontalHeaderItem(5, new QTableWidgetItem());

    ProcessTable->setObjectName(QString::fromUtf8("ProcessTable"));

    QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    sizePolicy.setHorizontalStretch(100);
    sizePolicy.setVerticalStretch(0);
    sizePolicy.setHeightForWidth(ProcessTable->sizePolicy().hasHeightForWidth());
    ProcessTable->setSizePolicy(sizePolicy);
    splitter->addWidget(ProcessTable);

    ProcessTable->horizontalHeader()->setStretchLastSection(true);
    ProcessTable->setShowGrid(false);
    ProcessTable->setSortingEnabled(false);
    ProcessTable->setWordWrap(true);
    ProcessTable->setCornerButtonEnabled(true);
    ProcessTable->horizontalHeader()->setVisible(true);
    ProcessTable->horizontalHeader()->setCascadingSectionResizes(false);
    ProcessTable->horizontalHeader()->setHighlightSections(false);
    ProcessTable->verticalHeader()->setVisible(false);
    ProcessTable->verticalHeader()->setDefaultSectionSize(12);
    ProcessTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    ProcessTable->setSelectionMode( QAbstractItemView::SingleSelection );
    ProcessTable->setContextMenuPolicy( Qt::CustomContextMenu );

    gridLayout->addWidget(splitter, 0, 0, 1, 6);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 1, 0, 1, 1);

    pushButton_Refresh = new QPushButton(this->ProcessListWidget);
    pushButton_Refresh->setObjectName(QString::fromUtf8("pushButton_Refresh"));

    gridLayout->addWidget(pushButton_Refresh, 1, 1, 1, 1);

    /*pushButton_Kill = new QPushButton(this->ProcessListWidget);
    pushButton_Kill->setObjectName(QString::fromUtf8("pushButton_Kill"));

    gridLayout->addWidget(pushButton_Kill, 1, 2, 1, 1);

    pushButton_Steal_Token = new QPushButton(this->ProcessListWidget);
    pushButton_Steal_Token->setObjectName(QString::fromUtf8("pushButton_Steal_Token"));

    gridLayout->addWidget(pushButton_Steal_Token, 1, 3, 1, 1);

    // pushButton_Inject = new QPushButton(this->ProcessListWidget);
    // pushButton_Inject->setObjectName(QString::fromUtf8("pushButton_Inject"));

    // gridLayout->addWidget(pushButton_Inject, 1, 4, 1, 1);*/

    horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_2, 1, 2, 1, 1);


    actionCopyProcessID = new QAction("Copy PID");
    // actionSetAsParentProcess = new QAction("Set as Parent Process");

    ProcessListMenu = new QMenu( this );
    ProcessListMenu->setStyleSheet( MenuStyle );

    ProcessListMenu->addAction( actionCopyProcessID );
    // ProcessListMenu->addAction( actionSetAsParentProcess );

    ProcessListWidget->setWindowTitle(QCoreApplication::translate("Process List", "Process List", nullptr));

    ProcessTree->headerItem()->setText(0, QCoreApplication::translate("Process List", "Process Tree", nullptr));
    ProcessTree->setSortingEnabled(false);

    ProcessTable->horizontalHeaderItem(0)->setText(QCoreApplication::translate("Process List", "Name", nullptr));
    ProcessTable->horizontalHeaderItem(1)->setText(QCoreApplication::translate("Process List", "PID", nullptr));
    ProcessTable->horizontalHeaderItem(2)->setText(QCoreApplication::translate("Process List", "PPID", nullptr));
    ProcessTable->horizontalHeaderItem(3)->setText(QCoreApplication::translate("Process List", "Session", nullptr));
    ProcessTable->horizontalHeaderItem(4)->setText(QCoreApplication::translate("Process List", "Arch", nullptr));
    ProcessTable->horizontalHeaderItem(5)->setText(QCoreApplication::translate("Process List", "User", nullptr));

    ProcessTable->horizontalHeader()->resizeSection(0, 200);
    ProcessTable->horizontalHeader()->resizeSection(1, 70);
    ProcessTable->horizontalHeader()->resizeSection(2, 70);
    ProcessTable->horizontalHeader()->resizeSection(3, 70);
    ProcessTable->horizontalHeader()->resizeSection(4, 70);

    pushButton_Refresh->setText(QCoreApplication::translate("Process List", "Refresh", nullptr));
    // pushButton_Kill->setText(QCoreApplication::translate("Process List", "Kill", nullptr));
    // pushButton_Steal_Token->setText(QCoreApplication::translate("Process List", "Impersonate Token", nullptr));
    // pushButton_Inject->setText(QCoreApplication::translate("Process List", "Inject", nullptr));

    // Context Menu
    connect( ProcessTable,   &QTableWidget::customContextMenuRequested, this,  &ProcessList::handleTableListMenuContext );
    connect( ProcessTree,    &QTreeWidget::customContextMenuRequested, this,  &ProcessList::handleTreeListMenuContext );

    // Context Menu Actions
    connect( actionCopyProcessID,      &QAction::triggered, this, &ProcessList::onActionCopyPID );
    // connect( actionSetAsParentProcess, &QAction::triggered, this, &ProcessList::onActionSetParentProcess );

    // Buttons
    connect( pushButton_Refresh, &QPushButton::clicked, this, &ProcessList::onButton_Refresh );

    // List Widget actions
    connect( ProcessTable, &QTableWidget::clicked, this, &ProcessList::onTableChange );
    connect( ProcessTree, &QTreeWidget::clicked, this, &ProcessList::onTreeChange );
}

void HavocNamespace::UserInterface::Widgets::ProcessList::UpdateProcessListJson( QJsonDocument ProcessListData )
{
    ProcessTable->setRowCount( 0 );
    ProcessTree->clear();

    if ( ProcessListData.isArray() )
    {
        auto ProcessListArray = ProcessListData.array();

        for ( QJsonValueRef ProcessInfo : ProcessListArray )
        {
            auto Process        = ProcessInfo.toObject();
            auto ProcessInfoMap = std::map<QString, QString>() ;
            auto ProcessIsWow   = Process[ "IsWow" ].toInt();

            ProcessInfoMap.insert( { "Name",    Process[ "Name" ].toString() } );
            ProcessInfoMap.insert( { "PID",     Process[ "PID" ].toString() } );
            ProcessInfoMap.insert( { "PPID",    Process[ "PPID" ].toString() } );
            ProcessInfoMap.insert( { "Session", Process[ "Session" ].toString() } );
            ProcessInfoMap.insert( { "Arch",    ProcessIsWow ? "x86" : "x64" } );
            ProcessInfoMap.insert( { "User",    Process[ "User" ].toString() } );

            NewTableProcess( ProcessInfoMap );
            NewTreeProcess( ProcessInfoMap );
        }
    }

    ProcessTree->expandAll();
}

void HavocNamespace::UserInterface::Widgets::ProcessList::NewTableProcess(std::map<QString, QString> ProcessInfo) {

    if ( this->ProcessTable->rowCount() < 1 )
        this->ProcessTable->setRowCount( 1 );
    else
        this->ProcessTable->setRowCount( this->ProcessTable->rowCount() + 1 );

    this->ProcessTable->setSortingEnabled( false );

    auto Name = new QTableWidgetItem();
    Name->setText(ProcessInfo["Name"]);
    Name->setFlags(Name->flags() ^ Qt::ItemIsEditable);
    if (this->Session.PID.compare(ProcessInfo["PID"]) == 0) {
        Name->setForeground(QColor(255, 85, 85));
    }
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 0, Name);

    auto PID = new QTableWidgetItem();
    PID->setText(ProcessInfo["PID"]);
    PID->setTextAlignment( Qt::AlignCenter );
    PID->setFlags(PID->flags() ^ Qt::ItemIsEditable);
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 1, PID);

    auto PPID = new QTableWidgetItem();
    PPID->setText(ProcessInfo["PPID"]);
    PPID->setTextAlignment( Qt::AlignCenter );
    PPID->setFlags(PPID->flags() ^ Qt::ItemIsEditable);
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 2, PPID);

    // Session and Arch are swapped...
    auto SessionID = new QTableWidgetItem();
    SessionID->setText(ProcessInfo["Session"]);
    SessionID->setTextAlignment( Qt::AlignCenter );
    SessionID->setFlags(SessionID->flags() ^ Qt::ItemIsEditable);
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 3, SessionID);

    auto Arch = new QTableWidgetItem();
    Arch->setText(ProcessInfo["Arch"]);
    Arch->setTextAlignment( Qt::AlignCenter );
    Arch->setFlags(Arch->flags() ^ Qt::ItemIsEditable);
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 4, Arch);

    auto User = new QTableWidgetItem();
    User->setText(ProcessInfo["User"]);
    User->setFlags(User->flags() ^ Qt::ItemIsEditable);
    this->ProcessTable->setItem(this->ProcessTable->rowCount()-1, 5, User);
}

void HavocNamespace::UserInterface::Widgets::ProcessList::NewTreeProcess( std::map<QString,QString> ProcessInfo )
{
    auto ProcessItem = new QTreeWidgetItem;
    auto it          = QTreeWidgetItemIterator( ProcessTree );

    ProcessItem->setText( 0, ProcessInfo[ "PID" ] + ": " + ProcessInfo[ "Name" ] );

    while ( *it )
    {
        if ( ( *it )->text( 0 ).split( ": " )[ 0 ].compare( ProcessInfo[ "PPID" ] ) == 0 )
        {
            ( *it )->addChild( ProcessItem );
            return;
        }
        ++it;
    }

    ProcessTree->addTopLevelItem( ProcessItem );
}

void HavocNamespace::UserInterface::Widgets::ProcessList::onButton_Refresh() const
{
    for ( auto & Session : HavocX::Teamserver.Sessions )
    {
        if ( Session.Name.compare( Session.Name ) == 0 )
        {
            if ( Session.ProcessList )
            {
                Session.InteractedWidget->DemonCommands->Execute.ProcList( Util::gen_random( 8 ).c_str(), true );
                return;
            }
        }
    }
}

void HavocNamespace::UserInterface::Widgets::ProcessList::onTableChange()
{
    auto PID = ProcessTable->item( ProcessTable->currentRow(), 1 )->text();
    auto it  = QTreeWidgetItemIterator ( ProcessTree );

    while ( *it )
    {
        if ( ( *it )->text( 0 ).split( ": " )[ 0 ].compare( PID ) == 0 )
        {
            ProcessTree->setCurrentItem( *it );
            return;
        }
        ++it;
    }
}

void HavocNamespace::UserInterface::Widgets::ProcessList::onTreeChange()
{
    auto PID = ProcessTree->currentItem()->text( ProcessTree->currentColumn() ).split( ":" )[ 0 ];

    for ( u32 i = 0; i < ProcessTable->rowCount(); i++ )
    {
        if ( ProcessTable->item( i, 1 )->text().compare( PID ) == 0 )
        {
            ProcessTable->setCurrentItem( ProcessTable->item( i, 1 ) );
        }
    }
}

void HavocNamespace::UserInterface::Widgets::ProcessList::handleTableListMenuContext( const QPoint &pos )
{
    if ( ! ProcessTable->itemAt( pos ) )
        return;

    ProcessListMenu->popup( ProcessTable->horizontalHeader()->viewport()->mapToGlobal( pos ) );
}

void HavocNamespace::UserInterface::Widgets::ProcessList::handleTreeListMenuContext( const QPoint &pos )
{
    if ( ! ProcessTable->itemAt( pos ) )
        return;

    ProcessListMenu->popup( ProcessTree->viewport()->mapToGlobal( pos ) );
}

void HavocNamespace::UserInterface::Widgets::ProcessList::onActionCopyPID()
{
    spdlog::info("PID saved to clipboard");
    auto PID = this->ProcessTree->currentItem()->text(this->ProcessTree->currentColumn()).split(":")[0];

    QApplication::clipboard()->setText( PID );
}

void HavocNamespace::UserInterface::Widgets::ProcessList::onActionSetParentProcess()
{

}