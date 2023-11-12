#include <UserInterface/Widgets/Store.hpp>

#include <QScrollBar>

void Store::setupUi( QWidget* Store)
{
    StoreWidget = Store;

    if ( Store->objectName().isEmpty() )
        Store->setObjectName( QString::fromUtf8( "STore" ) );

    gridLayout = new QGridLayout( Store );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );

    StoreLogger = new QTextEdit( /* PageLogger */ );
    StoreLogger->setObjectName( QString::fromUtf8( "StoreLogger" ) );
    StoreLogger->setReadOnly( true );

    gridLayout->addWidget( StoreLogger, 0, 0, 0, 0 );

    retranslateUi(  );

    QMetaObject::connectSlotsByName( StoreWidget );
}

void Store::retranslateUi()
{
    StoreWidget->setWindowTitle( QCoreApplication::translate( "Store", "Store", nullptr ) );
}

void Store::AddLoggerText( const QString& Text ) const
{
    StoreLogger->append( Text );
    StoreLogger->verticalScrollBar()->setValue( StoreLogger->verticalScrollBar()->maximum() );
}
