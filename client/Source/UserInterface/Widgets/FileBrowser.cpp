#include <global.hpp>

#include <UserInterface/Widgets/FileBrowser.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>

#include <QList>
#include <spdlog/spdlog.h>

static auto JoinAtIndex( QStringList list, int index, QString sep ) -> QString
{
    auto string = QString();

    for ( int i = 0; i < list.size(); i++ )
    {
        if ( i == index )
            break;

        string = string + list[ i ] + sep;
    }

    return string;
}

auto PathGetParent( QString MainPath ) -> QString
{
    auto Path = MainPath.toStdString();
    auto Indx = 0;

    for ( Indx = Path.size() ;; Indx-- )
        if ( Path[ Indx ] == '\\' ) break;

    Path = Path.substr( 0, Indx );

    spdlog::info( "Path: {}", Path );

    return QString( Path.c_str() );
}

void FileBrowser::setupUi( QWidget* FileBrowser )
{
    FileBrowserWidget = FileBrowser;

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

    if ( FileBrowser->objectName().isEmpty() )
        FileBrowser->setObjectName( QString::fromUtf8( "FileBrowser" ) );

    gridLayout = new QGridLayout( FileBrowser );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    splitter = new QSplitter( FileBrowser );
    splitter->setObjectName( QString::fromUtf8( "splitter" ) );
    splitter->setOrientation( Qt::Horizontal );

    FileBrowserTree = new QTreeWidget( splitter );
    FileBrowserTree->setObjectName( QString::fromUtf8( "FileBrowserTree" ) );

    FileBrowserListWidget = new QWidget( splitter );
    FileBrowserListWidget->setObjectName( QString::fromUtf8( "FileBrowserListWidget" ) );

    formLayout = new QFormLayout( FileBrowserListWidget );
    formLayout->setObjectName( QString::fromUtf8( "formLayout" ) );

    ButtonGoUpDir = new QPushButton( FileBrowserListWidget );
    ButtonGoUpDir->setObjectName( QString::fromUtf8( "ButtonGoUpDir" ) );

    formLayout->setWidget( 0, QFormLayout::LabelRole, ButtonGoUpDir );

    InputFileBrowserPath = new QLineEdit( FileBrowserListWidget );
    InputFileBrowserPath->setObjectName( QString::fromUtf8( "InputFileBrowserPath" ) );

    formLayout->setWidget( 0, QFormLayout::FieldRole, InputFileBrowserPath );

    TableFileBrowser = new QTableWidget( FileBrowserListWidget );
    TableFileBrowser->setObjectName( QString::fromUtf8( "TableFileBrowser" ) );
    TableFileBrowser->setEnabled( true );
    TableFileBrowser->setShowGrid( false );
    TableFileBrowser->setSortingEnabled( false );
    TableFileBrowser->setWordWrap( true );
    TableFileBrowser->setCornerButtonEnabled( true );
    TableFileBrowser->horizontalHeader()->setVisible( true );
    TableFileBrowser->setSelectionBehavior( QAbstractItemView::SelectRows );
    TableFileBrowser->setContextMenuPolicy( Qt::CustomContextMenu );
    TableFileBrowser->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    TableFileBrowser->verticalHeader()->setVisible(false);
    TableFileBrowser->verticalHeader()->setStretchLastSection( false );
    TableFileBrowser->verticalHeader()->setDefaultSectionSize( 12 );
    TableFileBrowser->setFocusPolicy( Qt::NoFocus );

    if ( TableFileBrowser->columnCount() < 3 )
        TableFileBrowser->setColumnCount( 3 );

    TableFileBrowser->setHorizontalHeaderItem( 0, new QTableWidgetItem( "Name" ) );
    TableFileBrowser->setHorizontalHeaderItem( 1, new QTableWidgetItem( "Size" ) );
    TableFileBrowser->setHorizontalHeaderItem( 2, new QTableWidgetItem( "Modified" ) );

    formLayout->setWidget( 1, QFormLayout::SpanningRole, TableFileBrowser );

    splitter->addWidget( FileBrowserTree );
    splitter->addWidget( FileBrowserListWidget );
    splitter->setSizes( QList<int>() << 1 << 250 );

    gridLayout->addWidget( splitter, 0, 0, 1, 1 );

    MenuFileBrowserTable = new QMenu( this );
    MenuFileBrowserTable->setStyleSheet( MenuStyle );
    // MenuFileBrowserTable->addAction( "Remove", this, &FileBrowser::onTableMenuRemove );
    // MenuFileBrowserTable->addAction( "Reload", this, &FileBrowser::onTableMenuReload );
    // MenuFileBrowserTable->addAction( "Mkdir",  this, &FileBrowser::onTableMenuMkdir );
    TableFileBrowser->addAction( MenuFileBrowserTable->menuAction() );

    MenuFileBrowserTree  = new QMenu( this );
    MenuFileBrowserTree->setStyleSheet( MenuStyle );
    // MenuFileBrowserTree->addAction( "List Drives", this, &FileBrowser::onTreeMenuListDrives );
    // MenuFileBrowserTree->addAction( "Remove",      this, &FileBrowser::onTreeMenuRemove );
    // MenuFileBrowserTree->addAction( "Reload",      this, &FileBrowser::onTreeMenuReload );
    // MenuFileBrowserTree->addAction( "Mkdir",       this, &FileBrowser::onTreeMenuMkdir  );
    FileBrowserTree->addAction( MenuFileBrowserTree->menuAction() );

    retranslateUi( );

    QObject::connect( TableFileBrowser, &QTableWidget::cellDoubleClicked, this, &FileBrowser::onTableDoubleClick );
    QObject::connect( TableFileBrowser, &QTableWidget::customContextMenuRequested, this, &FileBrowser::onTableContextMenu );
    QObject::connect( FileBrowserTree, &QTreeWidget::customContextMenuRequested, this, &FileBrowser::onTableContextMenu );
    QObject::connect( ButtonGoUpDir, &QPushButton::clicked, this, &FileBrowser::onButtonUp );
    QObject::connect( InputFileBrowserPath, &QLineEdit::returnPressed, this, &FileBrowser::onInputPath );

    QMetaObject::connectSlotsByName( FileBrowser );
}

void FileBrowser::retranslateUi()
{
    auto Pix = QPixmap( ":/icons/FileBrowserFolder" );
    FileBrowserWidget->setWindowTitle( QCoreApplication::translate("FileBrowser", "FileBrowser", nullptr));

    FileBrowserTree->headerItem()->setText( 0, "Files" );

    ButtonGoUpDir->setIcon( QIcon( Pix ) );
    ButtonGoUpDir->setIconSize( Pix.rect().size() );
}

void FileBrowser::AddData( QJsonDocument JsonData )
{
    auto Path  = QString();
    auto Files = QJsonDocument();
    auto Data  = FileDirData();

    if ( ! JsonData[ "Path" ].isString() )
    {
        spdlog::error( "[FileBrowser::AddData] Path is not string" );
        return;
    }

    if ( ! JsonData[ "Files" ].isArray() )
    {
        spdlog::error( "[FileBrowser::AddData] Files is not an array" );
        return;
    }

    Path  = QByteArray::fromBase64( JsonData[ "Path" ].toString().toLocal8Bit() );
    Path.replace( "\\*", "" );

    for ( int i = 0; i < DirData.size(); i++ )
    {
        if ( Path.compare( DirData[ i ].Path ) == 0 )
        {
            spdlog::info( "Path already exists. remove it" );
            DirData.erase( DirData.begin() + i );
        }
    }

    Files = QJsonDocument( JsonData[ "Files" ].toArray() );
    Data  = FileDirData {
        .Path = Path,
        .Data = Files
    };

    if ( Files.isArray() )
    {
        for ( auto data : Files.array() )
        {
            if ( data.isObject() )
            {
                auto Type     = data.toObject()[ "Type" ].toString();
                auto Name     = data.toObject()[ "Name" ].toString();
                auto Size     = data.toObject()[ "Size" ].toString();
                auto Modified = data.toObject()[ "Modified" ].toString();
                auto fileData = FileData{
                    .Path     = Path,
                    .Type     = Type,
                    .Name     = Name,
                    .Size     = Size,
                    .Modified = Modified,
                };

                Data.Files.push_back( fileData );
            }
            else spdlog::error( "Files isn't array" );
        }
    }
    else spdlog::error( "Files isn't array" );

    DirData.push_back( Data );

    for ( auto& data : Data.Files )
    {
        TableAddData( data );
        // TreeAddData( data );
    }

    TreeUpdate();

    Path.replace( "\\*", "" );
    InputFileBrowserPath->setText( Path );
}

void FileBrowser::TreeAddData( FileData Data )
{
    spdlog::info( "Append tree" );
}

void FileBrowser::TableAddData( FileData Data )
{
    auto ItemName     = new FileBrowserTableItem();
    auto ItemSize     = new FileBrowserTableItem();
    auto ItemModified = new FileBrowserTableItem();

    if ( TableFileBrowser->rowCount() < 1 )
        TableFileBrowser->setRowCount( 1 );
    else
        TableFileBrowser->setRowCount( TableFileBrowser->rowCount() + 1 );

    if ( Data.Type.compare( "dir" ) == 0 )
        ItemName->setIcon( QIcon( ":/icons/FileBrowserFolder" ) );
    else
        ItemName->setIcon( QIcon( ":/icons/FileBrowserFile" ) );

    ItemName->setText( Data.Name );
    ItemName->setFlags( ItemName->flags() ^ Qt::ItemIsEditable );
    ItemName->setTextAlignment( Qt::AlignLeft );

    ItemSize->setText( Data.Size );
    ItemSize->setFlags( ItemSize->flags() ^ Qt::ItemIsEditable );
    ItemSize->setTextAlignment( Qt::AlignLeft );

    ItemModified->setText( Data.Modified );
    ItemModified->setFlags( ItemModified->flags() ^ Qt::ItemIsEditable );
    ItemModified->setTextAlignment( Qt::AlignLeft );

    ItemName->Data     = Data;
    ItemSize->Data     = Data;
    ItemModified->Data = Data;

    TableFileBrowser->setItem( TableFileBrowser->rowCount() - 1, 0, ItemName );
    TableFileBrowser->setItem( TableFileBrowser->rowCount() - 1, 1, ItemSize );
    TableFileBrowser->setItem( TableFileBrowser->rowCount() - 1, 2, ItemModified );
}

void FileBrowser::onTableDoubleClick( int row, int column )
{
    auto Item = ( ( FileBrowserTableItem* ) TableFileBrowser->item( row, column ) );

    if ( Item->Data.Type.compare( "dir" ) == 0 )
    {
        TableClear();
        ChangePathAndSendRequest( Item->Data.Path + "\\" + Item->Data.Name );
        return;
    }

}

void FileBrowser::onTreeDoubleClick()
{

}

void FileBrowser::ChangePathAndSendRequest( QString Path )
{
    Path.replace( "\\*", "" );

    InputFileBrowserPath->setText( Path );

    for ( auto& Session : HavocX::Teamserver.Sessions )
    {
        if ( Session.Name.compare( SessionID ) == 0 )
        {
            Session.InteractedWidget->DemonCommands->Execute.FS( Util::gen_random( 8 ).c_str(), "dir;ui", Path );
        }
    }

}

void FileBrowser::TableClear()
{
    // TODO: free items
    for ( int i = TableFileBrowser->rowCount() - 1; i >= 0; i-- )
        TableFileBrowser->removeRow( i );
}

void FileBrowser::onButtonUp()
{
    auto Path = PathGetParent( InputFileBrowserPath->text() );

    TableClear();
    ChangePathAndSendRequest( Path );
}

void FileBrowser::onTableContextMenu( const QPoint &pos )
{
    if ( ! TableFileBrowser->itemAt( pos ) )
        return;

    MenuFileBrowserTable->popup( TableFileBrowser->horizontalHeader()->viewport()->mapToGlobal( pos ) );
}

void FileBrowser::onTreeContextMenu( const QPoint &pos )
{
    /*if ( ! FileBrowserTree->itemAt( pos ) )
        return;

    MenuFileBrowserTree->popup( TableFileBrowser->horizontalHeader()->viewport()->mapToGlobal( pos ) );*/
}

void FileBrowser::onTableMenuMkdir()
{

}

void FileBrowser::onTableMenuReload()
{

}

void FileBrowser::onTableMenuRemove()
{

}

void FileBrowser::onTreeMenuListDrives()
{

}

void FileBrowser::onTreeMenuMkdir()
{

}

void FileBrowser::onTreeMenuReload()
{

}

void FileBrowser::onTreeMenuRemove()
{

}

void FileBrowser::onInputPath()
{
    auto Path = InputFileBrowserPath->text();

    TableClear();
    ChangePathAndSendRequest( Path );
}

void FileBrowser::TreeUpdate()
{
    TreeClear( );

    for ( auto& Data : DirData )
    {
        auto Split = Data.Path.split( "\\" );

        // check if any Dir contains an empty space. if so then remove it.
        for ( int i = 0; i < Split.size(); i++ )
        {
            if ( Split[ i ].compare( "" ) == 0 )
                Split.removeAt( i );
        }

        for ( int i = 0; i < Split.size(); i++ )
        {
            if ( i == 0 )
            {
                TreeAddDisk( Split[ i ] + "\\" );
                continue;
            }

            auto Parent = JoinAtIndex( Split, i, "\\" );
            auto Item   = new FileBrowserTreeItem;

            Item->setText( 0, Split[ i ] );
            Item->setIcon( 0, QIcon( ":/icons/FileBrowserFolder" ) );
            Item->ParentPath = Parent + Split[ i ] + "\\";

            TreeAddChildToParent( Parent, Item );
        }

        for ( auto& subData : Data.Files )
        {
            if ( subData.Type.compare( "dir" ) == 0 )
            {
                auto Path = subData.Path;
                auto Item = new FileBrowserTreeItem;

                auto SubPath = subData.Path.replace( "\\\\", "\\" );
                if ( ! SubPath.endsWith( '\\' ) )
                    SubPath = subData.Path + "\\";

                auto SubName = subData.Name.replace( "\\\\", "\\" );;
                if ( ! SubName.endsWith( '\\' ) )
                    SubName = subData.Name + "\\";

                Item->setText( 0, subData.Name );
                Item->setIcon( 0, QIcon( ":/icons/FileBrowserFolder" ) );

                Item->ParentPath = SubPath + SubName;

                TreeAddChildToParent( Path, Item );
            }
        }
    }

    FileBrowserTree->expandAll();
}

void FileBrowser::TreeClear( )
{
    FileBrowserTree->clear();
}

auto FileBrowser::TreeSearchPath( QString ParentPath ) -> FileBrowserTreeItem*
{
    auto Iterator = QTreeWidgetItemIterator( FileBrowserTree );
    auto Item     = ( ( FileBrowserTreeItem* ) nullptr );

    while ( *Iterator )
    {
        Item = ( ( FileBrowserTreeItem* ) ( *Iterator ) );

        if ( ( Item->ParentPath.compare( ParentPath ) == 0 ) )
            return Item;

        ++Iterator;
    }

    return nullptr;
}

void FileBrowser::TreeAddDisk( QString Disk )
{
    if ( ! TreeSearchPath( Disk ) )
    {
        auto DiskItem = new FileBrowserTreeItem;

        DiskItem->setIcon( 0, QIcon( ":/icons/FileBrowserHardDisk" ) );
        DiskItem->setText( 0, Disk );
        DiskItem->ParentPath = Disk;

        FileBrowserTree->addTopLevelItem( DiskItem );
    }
}

void FileBrowser::TreeAddChildToParent( QString ParentPath, FileBrowserTreeItem* DataItem )
{
    auto Parent = TreeSearchPath( ParentPath );

    if ( Parent )
    {
        if ( TreePathExists( DataItem->ParentPath ) )
            return;

        Parent->addChild( DataItem );
        return;
    }
}

auto FileBrowser::TreePathExists( QString Path ) -> bool
{
    auto Iterator = QTreeWidgetItemIterator( FileBrowserTree );
    auto Item     = ( ( FileBrowserTreeItem* ) nullptr );

    while ( *Iterator )
    {
        Item = ( ( FileBrowserTreeItem* ) ( *Iterator ) );

        if ( ( Item->ParentPath.compare( Path ) == 0 ) )
            return true;

        ++Iterator;
    }
    return false;
}
