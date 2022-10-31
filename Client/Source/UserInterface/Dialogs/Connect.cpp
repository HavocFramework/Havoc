#include <global.hpp>

#include <Havoc/DBManager/DBManager.hpp>
#include <Havoc/Connector.hpp>
#include <Havoc/Havoc.hpp>

#include <UserInterface/Dialogs/Connect.hpp>

void HavocNamespace::UserInterface::Dialogs::Connect::setupUi( QDialog* Form )
{
    this->ConnectDialog = Form;

    if ( Form->objectName().isEmpty() )
        Form->setObjectName( QString::fromUtf8( "Form" ) );

    Form->resize( 500, 260 );
    Form->setMinimumSize( QSize( 500, 260 ) );
    Form->setMaximumSize( QSize( 500, 260 ) );

    Form->setStyleSheet( FileRead( ":/stylesheets/Dialogs/Connect" ) );

    gridLayout = new QGridLayout( Form );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );

    plainTextEdit = new QPlainTextEdit( Form );
    plainTextEdit->setObjectName( QString::fromUtf8( "plainTextEdit" ) );
    plainTextEdit->setMaximumSize( QSize( 16777215, 45 ) );
    plainTextEdit->setMinimumSize( QSize( 0, 45 ) );
    plainTextEdit->setReadOnly( true );
    plainTextEdit->setPlainText( "Havoc connection dialog. Connect to a havoc teamserver." );

    label_Port = new QLabel( Form );
    label_Port->setObjectName( QString::fromUtf8( "label_Port" ) );

    ButtonNewProfile = new QPushButton( Form );
    ButtonNewProfile->setObjectName( QString::fromUtf8( "ButtonNewProfile" ) );
    ButtonNewProfile->setMinimumSize( QSize( 10, 30 ) );

    label_Name = new QLabel( Form );
    label_Name->setObjectName( QString::fromUtf8( "label_Name" ) );

    lineEdit_Name = new QLineEdit( Form );
    lineEdit_Name->setObjectName( QString::fromUtf8( "lineEdit_Name" ) );
    lineEdit_Name->setMinimumSize( QSize( 150, 0 ) );

    lineEdit_Host = new QLineEdit( Form );
    lineEdit_Host->setObjectName( QString::fromUtf8( "lineEdit_Host" ) );

    lineEdit_Port = new QLineEdit( Form );
    lineEdit_Port->setObjectName( QString::fromUtf8( "lineEdit_Port" ) );

    lineEdit_User = new QLineEdit( Form );
    lineEdit_User->setObjectName( QString::fromUtf8( "lineEdit_User" ) );

    lineEdit_Password = new QLineEdit( Form );
    lineEdit_Password->setObjectName( QString::fromUtf8( "lineEdit_Password" ) );
    lineEdit_Password->setEchoMode( QLineEdit::Password );

    label_User = new QLabel( Form );
    label_User->setObjectName( QString::fromUtf8( "label_User" ) );

    ButtonConnect = new QPushButton( Form );
    ButtonConnect->setObjectName( QString::fromUtf8( "ButtonConnect" ) );

    label_Host = new QLabel( Form );
    label_Host->setObjectName( QString::fromUtf8( "label_Host" ) );

    label_Password = new QLabel( Form );
    label_Password->setObjectName( QString::fromUtf8( "label_Password" ) );

    horizontalSpacer = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

    listContextMenu = new QMenu( this );
    listContextMenu->addAction( "Remove", this, &Connect::itemRemove );
    listContextMenu->addAction( "Clear",  this, &Connect::itemsClear );
    listContextMenu->setStyleSheet( "QMenu {"
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
                                    "}" );

    listWidget = new QListWidget( Form );
    listWidget->setObjectName( QString::fromUtf8( "listWidget" ) );
    listWidget->setMaximumSize( QSize( 170, 16777215 ) );
    listWidget->setContextMenuPolicy( Qt::CustomContextMenu );
    listWidget->addAction( listContextMenu->menuAction() );

    gridLayout->addWidget( ButtonNewProfile, 0, 0, 1, 1 );
    gridLayout->addWidget( listWidget,       1, 0, 8, 1 );
    gridLayout->addItem(   horizontalSpacer, 1, 2, 1, 1 );

    gridLayout->addWidget( plainTextEdit,    0, 1, 1, 2 );
    gridLayout->addWidget( label_Name,       2, 1, 1, 1 );
    gridLayout->addWidget( lineEdit_Name,    2, 2, 1, 1 );

    gridLayout->addWidget( label_Host,       3, 1, 1, 1 );
    gridLayout->addWidget( lineEdit_Host,    3, 2, 1, 1 );

    gridLayout->addWidget( label_Port,       4, 1, 1, 1 );
    gridLayout->addWidget( lineEdit_Port,    4, 2, 1, 1 );

    gridLayout->addWidget( label_User,       5, 1, 1, 1 );
    gridLayout->addWidget( lineEdit_User,    5, 2, 1, 1 );

    gridLayout->addWidget( label_Password,   6, 1, 1, 1 );
    gridLayout->addWidget( lineEdit_Password,6, 2, 1, 1 );

    gridLayout->addWidget( ButtonConnect,    8, 2, 1, 1 );

    paletteGray = new QPalette();
    paletteGray->setColor( QPalette::Base, Qt::gray );

    paletteWhite = new QPalette();
    paletteWhite->setColor( QPalette::Base, Qt::white );

    Form->setWindowTitle( "Connect" );

    ButtonNewProfile->setText( "New Profile" );

    label_Name->setText( "Name:" );
    label_Host->setText( "Host:" );
    label_Port->setText( "Port:" );
    label_User->setText( "User:" );
    label_Password->setText( "Password:" );

    ButtonConnect->setText( "Connect" );
    ButtonConnect->setFocus();

    connect( listWidget, &QListWidget::itemPressed, this, &Connect::itemSelected );
    connect( listWidget, &QListWidget::customContextMenuRequested, this, &Connect::handleContextMenu );

    connect( lineEdit_Name, &QLineEdit::returnPressed, this, [&](){
        onButton_Connect();
    } );

    connect( lineEdit_User, &QLineEdit::returnPressed, this, [&](){
        onButton_Connect();
    } );

    connect( lineEdit_Host, &QLineEdit::returnPressed, this, [&](){
        onButton_Connect();
    } );

    connect( lineEdit_Port, &QLineEdit::returnPressed, this, [&](){
        onButton_Connect();
    } );

    connect( lineEdit_Password, &QLineEdit::returnPressed, this, [&](){
        onButton_Connect();
    } );

    QMetaObject::connectSlotsByName( Form );
}

Util::ConnectionInfo HavocNamespace::UserInterface::Dialogs::Connect::StartDialog( bool FromAction )
{
    listWidget->clear();

    for ( auto & TeamserverConnection : TeamserverList )
    {
        listWidget->addItem( TeamserverConnection.Name );
    }

    listWidget->setCurrentRow( 0 );

    if ( ! listWidget->selectedItems().empty() )
        this->itemSelected();
    else
        this->isNewProfile = true;

    connect( ButtonConnect,    &QPushButton::clicked, this, &Connect::onButton_Connect );
    connect( ButtonNewProfile, &QPushButton::clicked, this, &Connect::onButton_NewProfile );

    ConnectDialog->exec();

    auto ConnectionInfo = new Util::ConnectionInfo;

    ConnectionInfo->Name     = lineEdit_Name->text();
    ConnectionInfo->Host     = lineEdit_Host->text();
    ConnectionInfo->Port     = lineEdit_Port->text();
    ConnectionInfo->User     = lineEdit_User->text();
    ConnectionInfo->Password = lineEdit_Password->text();

    if ( this->tryConnect )
    {
        auto ConnectionInstant = new Connector( ConnectionInfo );

        HavocX::Teamserver = *ConnectionInfo;
        HavocX::Connector  = ConnectionInstant;

        if ( this->isNewProfile )
        {
            if ( ! this->dbManager->addTeamserverInfo( *ConnectionInfo ) )
                spdlog::warn( "Failed to add Teamserver Info to database" );
        }
        else if ( ConnectionInstant->ErrorString == nullptr )
        {
            spdlog::info( "Connecting to profile: {}", ConnectionInfo->Name.toStdString() );
        }
        else
        {
            spdlog::critical( "Couldn't connect to profile: {}", ConnectionInfo->Name.toStdString() );
            Havoc::Exit();
        }

    } else {

        if (!FromAction) {
            spdlog::info("Exit program from Connection Dialog");
            HavocNamespace::HavocSpace::Havoc::Exit();
        }

    }

    return *ConnectionInfo;
}

void HavocNamespace::UserInterface::Dialogs::Connect::passDB(HavocNamespace::HavocSpace::DBManager* db)
{
    this->dbManager = db;
}

void HavocNamespace::UserInterface::Dialogs::Connect::onButton_Connect()
{
    if ( lineEdit_Name->text().isEmpty() )
    {
        auto MessageBox = QMessageBox();
        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "Name is empty" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    if ( lineEdit_Host->text().isEmpty() )
    {
        auto MessageBox = QMessageBox();

        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "Host is empty" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    if ( lineEdit_Port->text().isEmpty()  )
    {
        auto MessageBox = QMessageBox();

        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "Port is empty" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    if ( lineEdit_User->text().isEmpty() )
    {
        auto MessageBox = QMessageBox();

        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "User is empty" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    if ( lineEdit_Password->text().isEmpty() )
    {
        auto MessageBox = QMessageBox();

        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "Password is empty" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    if ( this->dbManager->checkTeamserverExists( lineEdit_Name->text() ) && this->isNewProfile )
    {
        auto MessageBox = QMessageBox();

        MessageBox.setWindowTitle( "Error" );
        MessageBox.setText( "Profile Name already exists" );
        MessageBox.setIcon( QMessageBox::Critical );
        MessageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        MessageBox.exec();

        return;
    }

    this->tryConnect = true;
    this->listWidget->addItem( lineEdit_Name->text() );
    this->ConnectDialog->close();
}

void HavocNamespace::UserInterface::Dialogs::Connect::itemSelected()
{
    auto ProfileName = listWidget->currentItem()->text();
    this->isNewProfile = false;

    for ( auto& Profile : TeamserverList )
    {
        if ( Profile.Name == ProfileName )
        {
            lineEdit_Name->setPalette( *paletteGray );
            lineEdit_Name->setReadOnly( true );
            lineEdit_Name->setText( Profile.Name );
            lineEdit_Host->setText( Profile.Host );
            lineEdit_Port->setText( Profile.Port );
            lineEdit_User->setText( Profile.User );
            lineEdit_Password->setText( Profile.Password );
        }
    }

    ButtonConnect->setFocus();
}

void HavocNamespace::UserInterface::Dialogs::Connect::onButton_NewProfile()
{
    this->isNewProfile = true;

    listWidget->setCurrentIndex(QModelIndex());

    lineEdit_Name->setText( "Death Star" );
    lineEdit_Name->setPalette(*paletteWhite);
    lineEdit_Name->setReadOnly(false);

    lineEdit_Host->setText( "127.0.0.1" );
    lineEdit_Port->setText( "40056" );
    lineEdit_User->setText( "5pider" );
    lineEdit_Password->setText( "password" );
}

void HavocNamespace::UserInterface::Dialogs::Connect::handleContextMenu( const QPoint &pos )
{
    auto globalPos = listWidget->mapToGlobal( pos );
    listContextMenu->exec( globalPos );
}

void HavocNamespace::UserInterface::Dialogs::Connect::itemRemove()
{
    for ( int i = 0; i < listWidget->selectedItems().size(); ++i )
    {
        auto item = listWidget->takeItem( listWidget->currentRow() );

        this->dbManager->removeTeamserverInfo( item->text() );

        delete item;
    }

    this->onButton_NewProfile();
}

void HavocNamespace::UserInterface::Dialogs::Connect::itemsClear()
{
    this->listWidget->clear();
    this->dbManager->removeAllTeamservers();
    this->onButton_NewProfile();
}
