#include <UserInterface/Widgets/Teamserver.hpp>

#include <QScrollBar>

void Teamserver::setupUi( QWidget* Teamserver )
{
    TeamserverWidget = Teamserver;

    if ( Teamserver->objectName().isEmpty() )
        Teamserver->setObjectName( QString::fromUtf8( "Teamserver" ) );

    gridLayout = new QGridLayout( Teamserver );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );

    /*splitter = new QSplitter( Teamserver );
    splitter->setObjectName( QString::fromUtf8( "splitter" ) );
    splitter->setOrientation( Qt::Horizontal );
    splitter->setSizes( QList<int>() << 1 << 250 );

    TeamserverList = new QListWidget( splitter );
    TeamserverList->setObjectName( QString::fromUtf8( "TeamserverList" ) );
    TeamserverList->setStyleSheet( "QListView {\n"
                                   "    margin-top: 7px;\n"
                                   "}\n"
                                   "\n"
                                   "QListView::item {\n"
                                   "    height: 22px;\n"
                                   "}\n"
                                   "\n"
                                   "QListView::item:selected {\n"
                                   "    background: #313342;\n"
                                   "    color: #f8f8f2;\n"
                                   "}" );
    TeamserverList->addItem( "Logger" );

    splitter->addWidget( TeamserverList );

    StackedWidget = new QStackedWidget( splitter );
    StackedWidget->setObjectName( QString::fromUtf8( "StackedWidget" ) );

    PageLogger = new QWidget();
    PageLogger->setObjectName( QString::fromUtf8( "PageLogger" ) );

    formLayout = new QFormLayout( PageLogger );
    formLayout->setObjectName( QString::fromUtf8( "formLayout" ) );

    formLayout->setWidget( 0, QFormLayout::SpanningRole, TeamserverLogger );

    PageProfile = new QWidget();
    PageProfile->setObjectName( QString::fromUtf8( "PageProfile" ) );

    gridLayout_3 = new QGridLayout( PageProfile );
    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );

    TeamserverTreeProfile = new QTreeWidget( PageProfile );
    TeamserverTreeProfile->setObjectName( QString::fromUtf8( "TeamserverTreeProfile" ) );

    gridLayout_3->addWidget( TeamserverTreeProfile, 0, 0, 1, 1 );

    StackedWidget->addWidget( PageLogger );
    StackedWidget->addWidget( PageProfile );

    splitter->addWidget( StackedWidget );
    */

    TeamserverLogger = new QTextEdit( /* PageLogger */ );
    TeamserverLogger->setObjectName( QString::fromUtf8( "TeamserverLogger" ) );
    TeamserverLogger->setReadOnly( true );

    gridLayout->addWidget( TeamserverLogger, 0, 0, 0, 0 );

    retranslateUi(  );

    // StackedWidget->setCurrentIndex( 0 );

    QMetaObject::connectSlotsByName( TeamserverWidget );
}

void Teamserver::retranslateUi()
{
    TeamserverWidget->setWindowTitle( QCoreApplication::translate( "Teamserver", "Teamserver", nullptr ) );
}

void Teamserver::onListChange()
{

}

void Teamserver::AddLoggerText( const QString& Text ) const
{
    TeamserverLogger->append( Text );
    TeamserverLogger->verticalScrollBar()->setValue( TeamserverLogger->verticalScrollBar()->maximum() );
}
