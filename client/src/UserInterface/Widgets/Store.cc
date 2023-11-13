#include <UserInterface/Widgets/Store.hpp>

#include <QScrollBar>

void Store::setupUi( QWidget* Store)
{
    StoreWidget = Store;

    if ( Store->objectName().isEmpty() )
        Store->setObjectName( QString::fromUtf8( "Extentions" ) );

    horizontalLayout = new QHBoxLayout( Store );
    horizontalLayout->setObjectName( QString::fromUtf8( "horizontalLayout" ) );

    StoreSplitter = new QSplitter();

    StoreLogger = new QTextEdit( /* PageLogger */ );
    StoreLogger->setObjectName( QString::fromUtf8( "StoreLogger" ) );
    StoreLogger->setReadOnly( true );

    panelStore = new QWidget();
    root_panelStore = new QWidget();
    panelLayout = new QVBoxLayout(root_panelStore);

    panelScroll = new QScrollArea(panelStore);
    panelScroll->setWidgetResizable(true);
    panelScroll->setWidget(root_panelStore);

    root_panelLayout = new QVBoxLayout(panelStore);
    root_panelLayout->addWidget(panelScroll);

    headerLabelTitle = new QLabel( "<h1>Havoc Extentions!</h1>", panelStore );
    panelLayout->addWidget(headerLabelTitle);
    panelLabelDescription = new QLabel( "This tab is to install extentions inside of havoc!", panelStore );
    panelLayout->addWidget(panelLabelDescription);

    StoreTable = new QTableWidget();
    StoreTable->setRowCount(3);
    StoreTable->setColumnCount(3);

    labelTitle = new QTableWidgetItem( "Title"       );
    labelDescription  = new QTableWidgetItem( "Description" );
    labelAuthor  = new QTableWidgetItem( "Author"      );
    StoreTable->setHorizontalHeaderItem( 0, labelTitle   );
    StoreTable->setHorizontalHeaderItem( 1, labelAuthor  );
    StoreTable->setHorizontalHeaderItem( 2, labelDescription  );

    StoreTable->setEnabled( true );
    StoreTable->setShowGrid( false );
    StoreTable->setSortingEnabled( false );
    StoreTable->setWordWrap( true );
    StoreTable->setCornerButtonEnabled( true );
    StoreTable->horizontalHeader()->setVisible( true );
    StoreTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    StoreTable->setContextMenuPolicy( Qt::CustomContextMenu );
    StoreTable->horizontalHeader()->setSectionResizeMode( QHeaderView::ResizeMode::Stretch );
    StoreTable->horizontalHeader()->setStretchLastSection( true );
    StoreTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    StoreTable->verticalHeader()->setVisible( false );
    StoreTable->setFocusPolicy( Qt::NoFocus );



    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 3; ++col) {
            QTableWidgetItem *item = new QTableWidgetItem(QString("Item %1-%2").arg(row + 1).arg(col + 1));
            StoreTable->setItem(row, col, item);
        }
    }


    StoreSplitter->addWidget( StoreTable );
    StoreSplitter->addWidget( panelStore );

    horizontalLayout->addWidget( StoreSplitter );

    retranslateUi(  );

    QMetaObject::connectSlotsByName( StoreWidget );
}

void Store::retranslateUi()
{
    StoreWidget->setWindowTitle( QCoreApplication::translate( "Extentions", "Extentions", nullptr ) );
}
