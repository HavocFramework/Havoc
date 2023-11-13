#include <UserInterface/Widgets/Store.hpp>

#include <QScrollBar>

void Store::setupUi( QWidget* Store)
{
    StoreWidget = Store;

    if ( Store->objectName().isEmpty() )
        Store->setObjectName( QString::fromUtf8( "Store" ) );

    horizontalLayout = new QHBoxLayout( Store );
    horizontalLayout->setObjectName( QString::fromUtf8( "horizontalLayout" ) );

    StoreSplitter = new QSplitter();
    StoreLogger = new QTextEdit( /* PageLogger */ );
    StoreLogger->setObjectName( QString::fromUtf8( "StoreLogger" ) );
    StoreLogger->setReadOnly( true );
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
    StoreTable->verticalHeader()->setVisible( false );
    StoreTable->setFocusPolicy( Qt::NoFocus );



    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 3; ++col) {
            QTableWidgetItem *item = new QTableWidgetItem(QString("Item %1-%2").arg(row + 1).arg(col + 1));
            StoreTable->setItem(row, col, item);
        }
    }


    StoreSplitter->addWidget( StoreTable );
    StoreSplitter->addWidget( StoreLogger );
    horizontalLayout->addWidget( StoreSplitter );

    retranslateUi(  );

    QMetaObject::connectSlotsByName( StoreWidget );
}

void Store::retranslateUi()
{
    StoreWidget->setWindowTitle( QCoreApplication::translate( "Store", "Store", nullptr ) );
}
