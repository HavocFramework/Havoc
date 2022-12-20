#include <global.hpp>

#include <UserInterface/Dialogs/Payload.hpp>
#include <UserInterface/Dialogs/Listener.hpp>
#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>
#include <Util/ColorText.h>

#include <QIODevice>
#include <QFileDialog>
#include <QJsonArray>
#include <QHeaderView>
#include <vector>

using namespace std;

void Payload::setupUi( QDialog* Dialog )
{
    PayloadDialog = Dialog;

    if ( PayloadDialog->objectName().isEmpty() )
        PayloadDialog->setObjectName( QString::fromUtf8( "PayloadDialog" ) );

    PayloadDialog->resize( 550, 660 );

    gridLayout_3  = new QGridLayout( PayloadDialog );
    OptionsBox    = new QGroupBox( PayloadDialog );
    gridLayout_2  = new QGridLayout( OptionsBox );
    ComboListener = new QComboBox( OptionsBox );

    horizontalSpacer   = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_3 = new QSpacerItem( 40, 5,  QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_4 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_5 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_6 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    horizontalSpacer_7 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );
    OptionsBox->setObjectName( QString::fromUtf8( "OptionsBox" ) );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );
    ComboListener->setObjectName( QString::fromUtf8( "ComboListener" ) );

    gridLayout_2->addWidget( ComboListener, 0, 1, 1, 1 );

    LabelListener = new QLabel( OptionsBox );
    LabelListener->setObjectName( QString::fromUtf8( "LabelListener" ) );

    gridLayout_2->addWidget( LabelListener, 0, 0, 1, 1 );

    ComboFormat = new QComboBox( OptionsBox );
    ComboFormat->setObjectName( QString::fromUtf8( "ComboFormat" ) );

    gridLayout_2->addWidget( ComboFormat, 2, 1, 1, 1 );

    ComboArch = new QComboBox( OptionsBox );
    ComboArch->setObjectName( QString::fromUtf8( "ComboArch" ) );

    gridLayout_2->addWidget( ComboArch, 1, 1, 1, 1 );

    LabelArch = new QLabel( OptionsBox );
    LabelArch->setObjectName( QString::fromUtf8( "LabelArch" ) );

    gridLayout_2->addWidget( LabelArch, 1, 0, 1, 1 );

    LabelFormat = new QLabel( OptionsBox );
    LabelFormat->setObjectName( QString::fromUtf8( "LabelFormat" ) );

    gridLayout_2->addWidget( LabelFormat, 2, 0, 1, 1 );

    gridLayout_2->addItem( horizontalSpacer_3, 3, 1, 1, 1 );

    TreeConfig = new QTreeWidget( OptionsBox );
    TreeConfig->headerItem()->setText( 0, "Config" );
    TreeConfig->headerItem()->setText( 1, "Value" );
    TreeConfig->header()->resizeSection( 0, 155 );

    gridLayout_2->addWidget( TreeConfig, 4, 0, 1, 2 );
    gridLayout_3->addWidget( OptionsBox, 1, 0, 1, 8 );

    gridLayout_3->addItem( horizontalSpacer_5, 4, 4, 1, 1 );
    gridLayout_3->addItem( horizontalSpacer_2, 4, 6, 1, 1 );

    ButtonGenerate = new QPushButton( PayloadDialog );
    ButtonGenerate->setObjectName( QString::fromUtf8( "ButtonGenerate" ) );

    gridLayout_3->addWidget( ButtonGenerate, 4, 3, 1, 1 );

    gridLayout_3->addItem( horizontalSpacer_6, 4, 1, 1, 1 );
    gridLayout_3->addItem( horizontalSpacer,   4, 0, 1, 1 );
    gridLayout_3->addItem( horizontalSpacer_4, 4, 2, 1, 1 );

    LabelAgentType = new QLabel( PayloadDialog );
    LabelAgentType->setObjectName( QString::fromUtf8( "LabelAgentType" ) );

    gridLayout_3->addWidget( LabelAgentType, 0, 0, 1, 1 );

    BuildConsoleBox = new QGroupBox( PayloadDialog );
    BuildConsoleBox->setObjectName( QString::fromUtf8( "BuildConsoleBox" ) );
    gridLayout = new QGridLayout( BuildConsoleBox );
    gridLayout->setSpacing( 3 );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    gridLayout->setContentsMargins( 3, 3, 3, 3 );

    ConsoleText = new QTextEdit( BuildConsoleBox );
    ConsoleText->setObjectName( QString::fromUtf8( "ConsoleText" ) );
    ConsoleText->setReadOnly( true );

    gridLayout->addWidget( ConsoleText, 0, 0, 1, 1 );

    gridLayout_3->addWidget( BuildConsoleBox, 3, 0, 1, 8 );

    gridLayout_3->addItem( horizontalSpacer_7, 4, 5, 1, 1 );

    ComboAgentType = new QComboBox( PayloadDialog );
    ComboAgentType->setObjectName( QString::fromUtf8( "ComboAgentType" ) );

    gridLayout_3->addWidget( ComboAgentType, 0, 1, 1, 7 );

    retranslateUi(  );

    connect( ButtonGenerate, &QPushButton::clicked, this, &Payload::buttonGenerate );
    connect( ComboAgentType, &QComboBox::currentTextChanged, this, &Payload::CtxAgentPayloadChange );
    connect( ComboFormat, &QComboBox::currentTextChanged, this, [&]( const QString& text ){

        // only add config if our agent type is the default one (demon)
        if ( ComboAgentType->currentText().compare( "Demon" ) == 0 )
            DefaultConfig();

    } );

    QMetaObject::connectSlotsByName( PayloadDialog );
}

auto Payload::retranslateUi() -> void
{
    PayloadDialog->setStyleSheet( FileRead( ":/stylesheets/Dialogs/BasicDialog" ) );

    PayloadDialog->setWindowTitle( QCoreApplication::translate( "PayloadDialog", "Payload", nullptr ) );
    OptionsBox->setTitle( QCoreApplication::translate( "PayloadDialog", "Options", nullptr ) );

    if ( HavocX::Teamserver.Listeners.size() > 0 )
    {
        ComboListener->setDisabled( false );
        for ( auto& Listener : HavocX::Teamserver.Listeners )
            ComboListener->addItem( Listener.Name.c_str() );
    }
    else
    {
        ComboListener->addItem( "[ Empty ]" );
        ComboListener->setDisabled( true );
    }


    LabelListener->setText( QCoreApplication::translate( "PayloadDialog", "Listener:   ", nullptr ) );

    DefaultConfig();

    ComboFormat->addItem( "Windows Exe" );
    ComboFormat->addItem( "Windows Dll" );
    ComboFormat->addItem( "Windows Shellcode" );

    ComboArch->addItem( "x64" );

    ComboAgentType->addItem( "Demon" );

    for ( auto& Agents : HavocX::Teamserver.ServiceAgents )
        ComboAgentType->addItem( Agents.Name );

    LabelArch->setText( QCoreApplication::translate( "PayloadDialog", "Arch", nullptr ) );
    LabelFormat->setText( QCoreApplication::translate( "PayloadDialog", "Format", nullptr ) );
    ButtonGenerate->setText( QCoreApplication::translate( "PayloadDialog", "Generate", nullptr ) );
    ButtonGenerate->setStyleSheet(
        "padding-top: 5px;"
        "padding-bottom: 5px;"
        "padding-left: 10px;"
        "padding-right: 10px;"
    );
    LabelAgentType->setText( QCoreApplication::translate( "PayloadDialog", "Agent:", nullptr ) );
    BuildConsoleBox->setTitle( QCoreApplication::translate( "PayloadDialog", "Building Console", nullptr ) );
    BuildConsoleBox->setStyleSheet(
      "border: 1px solid #282a36;"
    );
}

void Payload::buttonGenerate()
{
    if ( ButtonClicked )
        return;

    if ( HavocX::Teamserver.Listeners.size() == 0 )
    {
        auto messageBox = QMessageBox(  );

        messageBox.setWindowTitle( "Payload Generator Error" );
        messageBox.setText( "No Listener specified/available" );
        messageBox.setIcon( QMessageBox::Critical );
        messageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
        messageBox.setMaximumSize( QSize(500, 500 ) );
        messageBox.exec();

        return;
    }
    else
    {
        for ( auto& listener : HavocX::Teamserver.Listeners )
        {
            if ( ComboListener->currentText().toStdString() == listener.Name )
            {
                if ( listener.Status.compare( "Offline" ) == 0 )
                {
                    MessageBox( "Payload Generator Error", "Selected listener is offline", QMessageBox::Critical );
                    return;
                }
            }
        }
    }

    ConsoleText->clear();
    ButtonClicked = true;

    auto Config  = GetConfigAsJson().toJson().toStdString();
    auto Package = new Util::Packager::Package;

    auto Head = Util::Packager::Head_t {
            .Event   = Util::Packager::Gate::Type,
            .User    = HavocX::Teamserver.User.toStdString(),
            .Time    = QTime::currentTime().toString( "hh:mm:ss" ).toStdString(),
            .OneTime = "true",
    };

    auto Body = Util::Packager::Body_t {
            .SubEvent = Util::Packager::Gate::Stageless,
            .Info = {
                { "AgentType", this->ComboAgentType->currentText().toStdString() },
                { "Listener",  this->ComboListener->currentText().toStdString() },
                { "Arch",      this->ComboArch->currentText().toStdString() },
                { "Format",    this->ComboFormat->currentText().toStdString() },
                { "Config",    Config },
            },
    };

    Package->Head = Head;
    Package->Body = Body;

    HavocX::Connector->SendPackage( Package );
}

auto Payload::ReceivedImplantAndSave( QString FileName, QByteArray ImplantArray ) -> void
{
    auto FileDialog = QFileDialog();
    auto Filename   = QUrl();
    auto Style      = FileRead( ":/stylesheets/Dialogs/FileDialog" ).toStdString();

    ButtonClicked = false;

    Style.erase( std::remove( Style.begin(), Style.end(), '\n' ), Style.end() );

    FileDialog.setStyleSheet( Style.c_str() );
    FileDialog.setAcceptMode( QFileDialog::AcceptSave );
    FileDialog.setDirectory( QDir::homePath() );
    FileDialog.selectFile( FileName );

    if ( FileDialog.exec() == QFileDialog::Accepted )
    {
        Filename = FileDialog.selectedUrls().value( 0 ).toLocalFile();

        if ( ! Filename.toString().isNull() )
        {
            // Save to file
            auto file       = QFile( Filename.toString() );
            auto messageBox = QMessageBox(  );

            if ( file.open( QIODevice::ReadWrite ) )
                file.write( ImplantArray );
            else
                spdlog::error("Couldn't write to file {}", Filename.toString().toStdString());

            file.close();

            messageBox.setWindowTitle( "Payload Generator" );
            messageBox.setText( "Payload saved under: " + Filename.toString() );
            messageBox.setIcon( QMessageBox::Information );
            messageBox.setStyleSheet( FileRead( ":/stylesheets/MessageBox" ) );
            messageBox.setMaximumSize( QSize(500, 500 ) );
            messageBox.exec();
        }
    }
}

auto Payload::addConsoleLog( QString MsgType, QString Message ) -> void
{
    Message = Message.replace( "\n", "<br>" );

    if ( MsgType.compare( "Good" ) == 0 )
    {
        ConsoleText->append( Util::ColorText::Green( "[+] " ) + Message );
    }
    else if ( MsgType.compare( "Info" ) == 0 )
    {
        ConsoleText->append( Util::ColorText::Cyan( "[*] " ) + Message );
    }
    else if ( MsgType.compare( "Error" ) == 0 )
    {
        ConsoleText->append( Util::ColorText::Red( "[-] " ) + Message );
    }
    else if ( MsgType.compare( "Warning" ) == 0 || MsgType.compare( "Warn" ) == 0 )
    {
        ConsoleText->append( Util::ColorText::Yellow( "[!] " ) + Message );
    }
    else
    {
        ConsoleText->append( Util::ColorText::Yellow( "[^] " ) + Message );
    }
}

auto Payload::CtxAgentPayloadChange( const QString& AgentType ) -> void
{
    if ( ! Closed )
    {
        for ( auto& Agent : HavocX::Teamserver.ServiceAgents )
        {
            if ( AgentType.compare( Agent.Name ) == 0 )
            {
                ComboFormat->clear();
                ComboArch->clear();

                AddConfigFromJson( Agent.BuildingConfig );

                for ( const auto& Arch : Agent.Arch )
                    ComboArch->addItem( Arch );

                for ( const auto& Format : Agent.Formats )
                    ComboFormat->addItem( Format.Name );

                return;
            }
        }

        if ( AgentType.compare( "Demon" ) == 0 )
        {
            // If agent not found means it's the default Demon
            DefaultConfig();

            ComboFormat->clear();
            ComboFormat->addItem( "Windows Exe" );
            ComboFormat->addItem( "Windows Dll" );
            ComboFormat->addItem( "Windows Shellcode" );
            ComboFormat->addItem( "Windows Service Exe" );

            ComboArch->clear();
            ComboArch->addItem( "x64" );
        }
    }
}

auto Payload::Clear() -> void
{
    Closed = true;
    ButtonClicked = false;

    ComboAgentType->setCurrentIndex( 0 );
    ComboListener->setCurrentIndex( 0 );
    ComboFormat->setCurrentIndex( 0 );
    ComboArch->setCurrentIndex( 0 );

    ConsoleText->clear();
}

auto Payload::AddConfigFromJson( QJsonDocument Config ) -> void
{
    auto Object = Config.object();

    TreeConfig->clear();

    for ( const auto& Key : Object.keys() )
    {
        auto KeyValue   = Object[ Key ];
        auto TreeItem   = new QTreeWidgetItem( TreeConfig );
        auto ObjectItem = ( QWidget* ) nullptr;

        TreeItem->setText( 0, Key );
        TreeItem->setFlags( Qt::NoItemFlags );

        if ( KeyValue.isBool() )
        {
            ObjectItem = new QCheckBox;
            ObjectItem->setObjectName( "bool" );
            ( ( QCheckBox* ) ObjectItem )->setChecked( KeyValue.toBool() );

            auto p = ObjectItem->palette();
            p.setColor( QPalette::Window, Qt::gray );
            ObjectItem->setPalette( p );

            TreeConfig->setItemWidget( TreeItem, 1, ObjectItem );
        }
        else if ( KeyValue.isString() )
        {
            ObjectItem = new QLineEdit;
            ObjectItem->setObjectName( "text" );
            ( ( QLineEdit* ) ObjectItem )->setText( KeyValue.toString() );

            TreeConfig->setItemWidget( TreeItem, 1, ObjectItem );
        }
        else if ( KeyValue.isArray() )
        {
            auto List = QStringList();

            ObjectItem = new QComboBox;
            ObjectItem->setObjectName( "list" );

            for ( auto item : KeyValue.toArray() )
                List << item.toString();

            ( ( QComboBox* ) ObjectItem )->addItems( List );

            TreeConfig->setItemWidget( TreeItem, 1, ObjectItem );
        }
        else if ( KeyValue.isObject() )
        {
            auto SubObject = KeyValue.toObject();

            for ( const auto& SubKey : SubObject.keys() )
            {
                auto SubKeyValue   = SubObject[ SubKey ];
                auto TreeChildItem = new QTreeWidgetItem( TreeItem );

                TreeChildItem->setText( 0, SubKey );

                if ( SubKeyValue.isBool() )
                {
                    ObjectItem = new QCheckBox;
                    ObjectItem->setObjectName( "bool" );
                    ( ( QCheckBox* ) ObjectItem )->setChecked( SubKeyValue.toBool() );

                    auto p = ObjectItem->palette();
                    p.setColor( QPalette::Window, Qt::gray );
                    ObjectItem->setPalette( p );

                    TreeConfig->setItemWidget( TreeChildItem, 1, ObjectItem );
                }
                else if ( SubKeyValue.isString() )
                {
                    ObjectItem = new QLineEdit;
                    ObjectItem->setObjectName( "text" );
                    ( ( QLineEdit* ) ObjectItem )->setText( SubKeyValue.toString() );

                    TreeConfig->setItemWidget( TreeChildItem, 1, ObjectItem );
                }
                else if ( SubKeyValue.isArray() )
                {
                    auto List = QStringList();

                    ObjectItem = new QComboBox;
                    ObjectItem->setObjectName( "list" );

                    for ( auto item : SubKeyValue.toArray() )
                        List << item.toString();

                    ( ( QComboBox* ) ObjectItem )->addItems( List );

                    TreeConfig->setItemWidget( TreeChildItem, 1, ObjectItem );
                }
            }
        }
    }

}

auto Payload::DefaultConfig() -> void
{
    TreeConfig->clear();

    auto Format                  = ComboFormat->currentText();
    auto DemonConfig             = HavocX::Teamserver.DemonConfig;
    auto ConfigSleep             = new QTreeWidgetItem( TreeConfig );

    auto ConfigServiceName       = ( QTreeWidgetItem* ) nullptr;
    auto ConfigServiceNameInput  = ( QLineEdit* ) nullptr;
    if ( Format.compare( "Windows Service Exe" ) == 0 )
    {
        ConfigServiceName       = new QTreeWidgetItem( TreeConfig );
        ConfigServiceNameInput  = new QLineEdit( "DemonSvc" );
    }

    auto ConfigIndirectSyscalls  = new QTreeWidgetItem( TreeConfig );
    auto ConfigSleepObfTechnique = new QTreeWidgetItem( TreeConfig );
    auto ConfigInjection         = new QTreeWidgetItem( TreeConfig );

    auto ConfigInjectionAlloc    = new QTreeWidgetItem( ConfigInjection );
    auto ConfigInjectionExecute  = new QTreeWidgetItem( ConfigInjection );
    auto ConfigInjectionSpawn64  = new QTreeWidgetItem( ConfigInjection );
    auto ConfigInjectionSpawn32  = new QTreeWidgetItem( ConfigInjection );

    auto SleepObfTechnique       = new QComboBox;
    auto SleepObfSpoofAddress    = new QLineEdit;

    auto ConfigSleepLineEdit     = new QLineEdit( QString::number( DemonConfig[ "Sleep" ].toInt() ) );
    auto ConfigIndSyscallCheck   = new QCheckBox;
    auto ConfigInjectAlloc       = new QComboBox;
    auto ConfigInjectExecute     = new QComboBox;
    auto ConfigSpawn64LineEdit   = new QLineEdit( DemonConfig[ "ProcessInjection" ].toObject()[ "Spawn64" ].toString() );
    auto ConfigSpawn32LineEdit   = new QLineEdit( DemonConfig[ "ProcessInjection" ].toObject()[ "Spawn32" ].toString() );

    ConfigSleep->setFlags( Qt::NoItemFlags );
    if ( Format.compare( "Windows Service Exe" ) == 0 )
    {
        ConfigServiceName->setFlags( Qt::NoItemFlags );
        ConfigServiceNameInput->setObjectName( "ConfigItem" );
    }

    ConfigIndirectSyscalls->setFlags( Qt::NoItemFlags );
    ConfigInjection->setFlags( Qt::NoItemFlags );
    ConfigSleepObfTechnique->setFlags( Qt::NoItemFlags );
    ConfigInjectionSpawn64->setFlags( Qt::NoItemFlags );
    ConfigInjectionSpawn32->setFlags( Qt::NoItemFlags );

    ConfigSleepLineEdit->setObjectName( "ConfigItem" );
    ConfigIndSyscallCheck->setObjectName( "ConfigItem" );
    ConfigInjectAlloc->setObjectName( "ConfigItem" );
    ConfigInjectExecute->setObjectName( "ConfigItem" );
    ConfigSpawn64LineEdit->setObjectName( "ConfigItem" );
    ConfigSpawn32LineEdit->setObjectName( "ConfigItem" );
    SleepObfTechnique->setObjectName( "ConfigItem" );
    SleepObfSpoofAddress->setObjectName( "ConfigItem" );

    ConfigIndSyscallCheck->setChecked( true );

    ConfigInjectAlloc->addItems( QStringList() << "Win32" << "Native/Syscall" );
    ConfigInjectExecute->addItems( QStringList() << "Win32" << "Native/Syscall" );
    SleepObfTechnique->addItems( QStringList() << "WaitForSingleObjectEx" << "Foliage" << "Ekko" );

    ConfigInjectAlloc->setCurrentIndex( 1 );
    ConfigInjectExecute->setCurrentIndex( 1 );

    TreeConfig->setItemWidget( ConfigSleep, 1, ConfigSleepLineEdit );
    if ( Format.compare( "Windows Service Exe" ) == 0 )
        TreeConfig->setItemWidget( ConfigServiceName, 1, ConfigServiceNameInput );
    TreeConfig->setItemWidget( ConfigIndirectSyscalls, 1, ConfigIndSyscallCheck );
    TreeConfig->setItemWidget( ConfigSleepObfTechnique,1, SleepObfTechnique );

    TreeConfig->setItemWidget( ConfigInjectionAlloc, 1, ConfigInjectAlloc );
    TreeConfig->setItemWidget( ConfigInjectionExecute, 1, ConfigInjectExecute );
    TreeConfig->setItemWidget( ConfigInjectionSpawn64, 1, ConfigSpawn64LineEdit );
    TreeConfig->setItemWidget( ConfigInjectionSpawn32, 1, ConfigSpawn32LineEdit );

    ConfigSleep->setText( 0, "Sleep" );
    if ( Format.compare( "Windows Service Exe" ) == 0 )
        ConfigServiceName->setText( 0, "Service Name" );
    ConfigIndirectSyscalls->setText(  0, "Indirect Syscall" );
    ConfigSleepObfTechnique->setText( 0, "Sleep Technique" );

    ConfigInjection->setText( 0, "Injection" );
    ConfigInjection->setExpanded( true );
    ConfigInjection->addChild( ConfigInjectionSpawn64 );
    ConfigInjection->addChild( ConfigInjectionSpawn32 );

    ConfigInjectionAlloc->setText( 0, "Alloc" );
    ConfigInjectionExecute->setText( 0, "Execute" );
    ConfigInjectionSpawn64->setText( 0, "Spawn64" );
    ConfigInjectionSpawn32->setText( 0, "Spawn32" );
}

auto Payload::GetConfigAsJson() -> QJsonDocument
{
    auto ConfigJson   = QJsonDocument();
    auto JsonObject   = QJsonObject();
    auto SubObjects   = map<QString, QJsonObject>();
    auto TreeIterator = QTreeWidgetItemIterator( TreeConfig );

    while ( *TreeIterator )
    {
        auto Parent  = QString();
        auto Name    = QString();
        auto ObjType = QString();
        auto Object  = ( QWidget* ) nullptr;

        if ( ( *TreeIterator )->parent() )
            Parent = ( *TreeIterator )->parent()->text( 0 );

        Name = ( *TreeIterator )->text( 0 );

        if ( TreeConfig->itemWidget( ( *TreeIterator ), 1 ) )
            ObjType = TreeConfig->itemWidget( ( *TreeIterator ), 1 )->metaObject()->className();

        if ( Parent.isEmpty() )
        {
            if ( ! ObjType.isEmpty() )
            {
                Object = TreeConfig->itemWidget( ( *TreeIterator ), 1 );
                if ( ObjType.compare( "QComboBox" ) == 0 )
                {
                    JsonObject.insert( Name, QJsonValue::fromVariant( ( ( QComboBox* ) Object )->currentText() ) );
                }
                else if ( ObjType.compare( "QCheckBox" ) == 0 )
                {
                    JsonObject.insert( Name, QJsonValue::fromVariant( ( ( QCheckBox* ) Object )->isChecked() ) );
                }
                else if ( ObjType.compare( "QLineEdit" ) == 0 )
                {
                    JsonObject.insert( Name, QJsonValue::fromVariant( ( ( QLineEdit* ) Object )->text() ) );
                }
                else
                {
                    spdlog::error( "ObjType not found: {}", ObjType.toStdString() );

                    ++TreeIterator;
                    continue;
                }
            }
        }
        else
        {
            Object = TreeConfig->itemWidget( ( *TreeIterator ), 1 );
            if ( ObjType.compare( "QComboBox" ) == 0 )
            {
                SubObjects[ Parent ].insert( Name, QJsonValue::fromVariant( ( ( QComboBox* ) Object )->currentText() ) );
            }
            else if ( ObjType.compare( "QCheckBox" ) == 0 )
            {
                SubObjects[ Parent ].insert( Name, QJsonValue::fromVariant( ( ( QCheckBox* ) Object )->isChecked() ) );
            }
            else if ( ObjType.compare( "QLineEdit" ) == 0 )
            {
                SubObjects[ Parent ].insert( Name, QJsonValue::fromVariant( ( ( QLineEdit* ) Object )->text() ) );
            }
            else
            {
                spdlog::error( "ObjType not found: {}", ObjType.toStdString() );

                ++TreeIterator;
                continue;
            }

        }

        ++TreeIterator;
    }

    for ( const auto& object : SubObjects )
        JsonObject.insert( object.first, object.second );

    ConfigJson.setObject( JsonObject );

    return ConfigJson;
}

auto Payload::Start() -> void
{
    ComboAgentType->clear();
    ComboListener->clear();
    ComboFormat->clear();
    ComboArch->clear();
    ConsoleText->clear();
    TreeConfig->clear();

    retranslateUi();

    PayloadDialog->show();
}
