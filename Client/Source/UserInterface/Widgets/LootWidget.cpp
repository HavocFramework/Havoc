#include <global.hpp>
#include <spdlog/spdlog.h>

#include <UserInterface/Widgets/LootWidget.h>
#include <QGraphicsScene>
#include <QGraphicsView>
#include <QGraphicsPixmapItem>
#include <QLabel>
#include <QFile>
#include <QTreeWidgetItem>
#include <QHeaderView>
#include <QScrollBar>
#include <QKeyEvent>
#include <QGraphicsSceneWheelEvent>

// imagelabel.cpp
ImageLabel::ImageLabel( QWidget* parent ) : QWidget( parent )
{
    label      = new QLabel;
    scrollArea = new QScrollArea( this );

    label->setBackgroundRole( QPalette::Base );
    label->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Ignored );
    label->setScaledContents( true );
    label->setStyleSheet( "background-color: #282a36;\n"
                          "    color: #f8f8f2;" );
    label->setPixmap( QPixmap() );

    scrollArea->setBackgroundRole(QPalette::Dark);
    scrollArea->setWidget( label );
}

void ImageLabel::resizeEvent( QResizeEvent* event )
{
    QWidget::resizeEvent( event );
    resizeImage();
}

const QPixmap* ImageLabel::pixmap() const
{
    return label->pixmap();
}

bool ImageLabel::event( QEvent* e )
{
    if ( e->type() == e->KeyPress )
    {
        auto eventKey = dynamic_cast<QKeyEvent*>( e );

        if ( eventKey->key() == Qt::Key_Control )
        {
            // spdlog::info( "Key_Control pressed" );
            key_ctrl = false;
        }
    }

    return QWidget::event( e );
}

void ImageLabel::keyReleaseEvent( QKeyEvent* event )
{
    if ( event->key() == Qt::Key_Control )
    {
        // spdlog::info( "Key_Control released" );
        key_ctrl = true;
    }

    QWidget::keyReleaseEvent( event );
}

void ImageLabel::wheelEvent( QWheelEvent* ev )
{
    // spdlog::info( "wheelEvent: {}", ev->angleDelta().y() );

    QWidget::wheelEvent( ev );
}

void ImageLabel::setPixmap( const QPixmap &pixmap )
{
    label->setPixmap( pixmap );
    scrollArea->setWidget( label );
    resizeImage();
}

void ImageLabel::resizeImage()
{
    label->setMinimumSize( size() );
    label->adjustSize();
    scrollArea->resize( size() );
}

LootWidget::LootWidget()
{
    if ( objectName().isEmpty() )
        setObjectName( QString::fromUtf8( "LootWidget" ) );

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

    gridLayout = new QGridLayout( this );
    gridLayout->setContentsMargins( 0, 0, 0, 0 );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    
    LabelShow = new QLabel( this );
    LabelShow->setObjectName( QString::fromUtf8( "LabelShow" ) );

    gridLayout->addWidget( LabelShow, 0, 3, 1, 1 );

    ComboShow = new QComboBox( this );
    ComboShow->addItem( QString( "Screenshots" ) );
    ComboShow->addItem( QString( "Downloads" ) );
    ComboShow->setObjectName( QString::fromUtf8( "ComboShow" ) );
    ComboShow->setMinimumSize( QSize( 150, 0 ) );

    gridLayout->addWidget( ComboShow, 0, 4, 1, 1 );

    LabelAgentID = new QLabel( this );
    LabelAgentID->setObjectName( QString::fromUtf8( "LabelAgentID" ) );
    LabelAgentID->setText( "AgentID: " );
    gridLayout->addWidget( LabelAgentID, 0, 1, 1, 1 );

    ComboAgentID = new QComboBox( this );
    ComboAgentID->setObjectName( QString::fromUtf8( "ComboAgentID" ) );
    ComboAgentID->setMinimumSize( QSize( 150, 0 ) );
    gridLayout->addWidget( ComboAgentID, 0, 2, 1, 1 );

    horizontalSpacer = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    gridLayout->addItem( horizontalSpacer, 0, 0, 1, 1 );

    StackWidget = new QStackedWidget( this );
    StackWidget->setObjectName( QString::fromUtf8( "StackWidget" ) );
    StackWidget->setContentsMargins( 0, 0, 0, 0 );

    Screenshots = new QWidget();
    Screenshots->setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Ignored );

    Screenshots->setObjectName( QString::fromUtf8( "Screenshots" ) );
    gridLayout_2 = new QGridLayout( Screenshots );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );

    splitter = new QSplitter( Screenshots );
    splitter->setObjectName( QString::fromUtf8( "splitter" ) );
    splitter->setOrientation( Qt::Horizontal );
    splitter->setSizes( QList<int>() << 10 << 200 );

    ScreenshotTable = new QTableWidget( splitter );
    if ( ScreenshotTable->columnCount() < 2 )
        ScreenshotTable->setColumnCount( 2 );

    ScreenshotTable->setEnabled( true );
    ScreenshotTable->setShowGrid( false );
    ScreenshotTable->setSortingEnabled( false );
    ScreenshotTable->setWordWrap( true );
    ScreenshotTable->setCornerButtonEnabled( true );
    ScreenshotTable->horizontalHeader()->setVisible( true );
    ScreenshotTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    ScreenshotTable->setContextMenuPolicy( Qt::CustomContextMenu );
    ScreenshotTable->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    ScreenshotTable->verticalHeader()->setVisible(false);
    ScreenshotTable->verticalHeader()->setStretchLastSection( false );
    ScreenshotTable->verticalHeader()->setDefaultSectionSize( 12 );
    ScreenshotTable->setFocusPolicy( Qt::NoFocus );
    ScreenshotTable->setObjectName( QString::fromUtf8( "ScreenshotTable" ) );

    splitter->addWidget( ScreenshotTable );

    ScreenshotImage = new ImageLabel( splitter );
    ScreenshotImage->setObjectName( QString::fromUtf8( "ScreenshotImage" ) );

    splitter->addWidget( ScreenshotImage );

    gridLayout_2->addWidget(splitter, 0, 0, 1, 1);

    StackWidget->addWidget( Screenshots );
    Downloads = new QWidget();
    Downloads->setObjectName(QString::fromUtf8("Downloads"));
    gridLayout_3 = new QGridLayout( Downloads );
    gridLayout_3->setObjectName(QString::fromUtf8("gridLayout_3"));

    DownloadTable = new QTableWidget( Downloads );
    if ( DownloadTable->columnCount() < 3 )
        DownloadTable->setColumnCount( 3 );

    DownloadTable->setEnabled( true );
    DownloadTable->setShowGrid( false );
    DownloadTable->setSortingEnabled( false );
    DownloadTable->setWordWrap( true );
    DownloadTable->setCornerButtonEnabled( true );
    DownloadTable->horizontalHeader()->setVisible( true );
    DownloadTable->setSelectionBehavior( QAbstractItemView::SelectRows );
    DownloadTable->setContextMenuPolicy( Qt::CustomContextMenu );
    DownloadTable->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    DownloadTable->verticalHeader()->setVisible(false);
    DownloadTable->verticalHeader()->setStretchLastSection( false );
    DownloadTable->verticalHeader()->setDefaultSectionSize( 12 );
    DownloadTable->setFocusPolicy( Qt::NoFocus );
    DownloadTable->setObjectName( QString::fromUtf8( "DownloadsTable" ) );

    gridLayout_3->addWidget( DownloadTable, 0, 0, 1, 1 );

    StackWidget->addWidget( Downloads );

    gridLayout->addWidget( StackWidget, 1, 0, 1, 6 );

    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

    gridLayout->addItem( horizontalSpacer_2, 0, 5, 1, 1 );

    StackWidget->setCurrentIndex( 0 );

    ScreenshotTable->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" ) );
    ScreenshotTable->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Date" ) );

    DownloadTable->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" ) );
    DownloadTable->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Size" ) );
    DownloadTable->setHorizontalHeaderItem( 2, new QTableWidgetItem( "Date" ) );

    LabelShow->setText( "Show: " );

    ScreenshotMenu           = new QMenu( this );
    ScreenshotActionDownload = new QAction( "Download" );

    ScreenshotMenu->setStyleSheet( MenuStyle );
    ScreenshotMenu->addAction( ScreenshotActionDownload );

    connect( this, &QTableWidget::customContextMenuRequested, this, &LootWidget::onScreenshotTableCtx );
    connect( ScreenshotTable, &QTableWidget::clicked, this, &LootWidget::onScreenshotTableClick );
    connect( DownloadTable, &QTableWidget::clicked, this, &LootWidget::onDownloadTableClick );
    connect( splitter, &QSplitter::splitterMoved, ScreenshotImage, &ImageLabel::resizeImage );
    connect( ComboAgentID, &QComboBox::currentTextChanged, this, &LootWidget::onAgentChange );
    connect( ComboShow, &QComboBox::currentTextChanged, this, &LootWidget::onShowChange );

    Reload();

    QMetaObject::connectSlotsByName( this );
}

void LootWidget::AddScreenshot( const QString& DemonID, const QString& Name, const QString& Date, const QByteArray& Data )
{
    spdlog::info( "Add Screenshot" );

    auto Item = LootData{
        .Type       = LOOT_IMAGE,
        .AgentID    = DemonID,
        .Data       = {
            .Name   = Name,
            .Date   = Date,
            .Data   = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
        ScreenshotTableAdd( Name, Date );
}

void LootWidget::AddDownload( const QString &DemonID, const QString &Name, const QString& Size, const QString &Date, const QByteArray &Data )
{
    auto Item = LootData{
        .Type       = LOOT_FILE,
        .AgentID    = DemonID,
        .Data       = {
            .Name = Name,
            .Date = Date,
            .Size = Size,
            .Data = Data,
        },
    };

    LootItems.push_back( Item );

    if ( ComboAgentID->currentText().compare( DemonID ) == 0 || ComboAgentID->currentText().compare( "[ All ]" ) == 0 )
        DownloadTableAdd( Name, Size, Date );
}

void LootWidget::Reload()
{
    ComboAgentID->clear();
    ComboAgentID->addItem( "[ All ]" );

    for ( auto& Session : HavocX::Teamserver.Sessions )
        ComboAgentID->addItem( Session.Name );

    // TODO: iterate over table items and free memory
    ScreenshotTable->setRowCount( 0 );
    DownloadTable->setRowCount( 0 );
}

void LootWidget::onScreenshotTableClick( const QModelIndex &index )
{
    auto DemonID  = ComboAgentID->currentText();
    auto FileName = ScreenshotTable->item( index.row(), 0 )->text();

    for ( auto& item : LootItems )
    {
        if ( DemonID.compare( "[ All ]" ) == 0 || DemonID.compare( item.AgentID ) == 0 )
        {
            if ( item.Type == LOOT_IMAGE )
            {
                if ( item.Data.Name.compare( FileName ) == 0 )
                {
                    auto image = QPixmap();
                    if ( image.loadFromData( item.Data.Data, "BMP" ) )
                    {
                        ScreenshotImage->setPixmap( image );
                    }
                }
            }
        }
    }
}

void LootWidget::onDownloadTableClick( const QModelIndex &index )
{

}

void LootWidget::onAgentChange( const QString& text )
{
    ScreenshotImage->setPixmap( QPixmap() );

    // todo: free columns items
    for ( int i = ScreenshotTable->rowCount(); i >= 0; i-- )
        ScreenshotTable->removeRow( i );

    for ( auto& item : LootItems )
    {
        if ( item.AgentID.compare( text ) == 0 || text.compare( "[ All ]" ) == 0 )
        {
            switch ( item.Type )
            {
                case LOOT_IMAGE:
                {
                    ScreenshotTableAdd( item.Data.Name, item.Data.Date );
                    break;
                }

                case LOOT_FILE:
                {
                    DownloadTableAdd( item.Data.Name, item.Data.Size, item.Data.Date );
                    break;
                }
            }
        }
    }
}

void LootWidget::AddSessionSection( const QString& AgentID )
{
    for ( int index = 0; index < ComboAgentID->count(); index++ )
    {
        if ( ComboAgentID->itemText( index ).compare( AgentID ) == 0 )
        {
            return;
        }
    }

    ComboAgentID->addItem( AgentID );
}

void LootWidget::onShowChange( const QString& text )
{
    if ( text.compare( "Screenshots" ) == 0 )
    {
        StackWidget->setCurrentIndex( 0 );
    }
    else if ( text.compare( "Downloads" ) == 0 )
    {
        StackWidget->setCurrentIndex( 1 );
    }
}

void LootWidget::ScreenshotTableAdd( const QString &Name, const QString &Date )
{
    for ( int i = 0; i < ScreenshotTable->rowCount(); i++ )
    {
        if ( ScreenshotTable->item( i, 0 )->text().compare( Name ) == 0 )
        {
            return;
        }
    }

    auto item_Name = new QTableWidgetItem( Name );
    auto item_Date = new QTableWidgetItem( Date );

    item_Name->setTextAlignment( Qt::AlignCenter );
    item_Name->setFlags( item_Name->flags() ^ Qt::ItemIsEditable );

    item_Date->setTextAlignment( Qt::AlignCenter );
    item_Date->setFlags( item_Date->flags() ^ Qt::ItemIsEditable );

    ScreenshotTable->rowCount() < 1 ? ScreenshotTable->setRowCount( 1 ) : ScreenshotTable->setRowCount( ScreenshotTable->rowCount() + 1 );

    ScreenshotTable->setItem( ScreenshotTable->rowCount() - 1, 0, item_Name );
    ScreenshotTable->setItem( ScreenshotTable->rowCount() - 1, 1, item_Date );
}

void LootWidget::DownloadTableAdd( const QString &Name, const QString &Size, const QString &Date )
{
    auto item_Name = new QTableWidgetItem( Name );
    auto item_Size = new QTableWidgetItem( Size );
    auto item_Date = new QTableWidgetItem( Date );

    item_Name->setTextAlignment( Qt::AlignCenter );
    item_Name->setFlags( item_Name->flags() ^ Qt::ItemIsEditable );

    item_Size->setTextAlignment( Qt::AlignCenter );
    item_Size->setFlags( item_Size->flags() ^ Qt::ItemIsEditable );

    item_Date->setTextAlignment( Qt::AlignCenter );
    item_Date->setFlags( item_Date->flags() ^ Qt::ItemIsEditable );

    DownloadTable->rowCount() < 1 ? DownloadTable->setRowCount( 1 ) : DownloadTable->setRowCount( DownloadTable->rowCount() + 1 );

    DownloadTable->setItem( DownloadTable->rowCount() - 1, 0, item_Name );
    DownloadTable->setItem( DownloadTable->rowCount() - 1, 1, item_Size );
    DownloadTable->setItem( DownloadTable->rowCount() - 1, 2, item_Date );
}

void LootWidget::onScreenshotTableCtx( const QPoint &pos )
{
    if ( ! ScreenshotTable->itemAt( pos ) )
        return;

    ScreenshotMenu->popup( ScreenshotTable->horizontalHeader()->viewport()->mapToGlobal( pos ) );
}
