#include <global.hpp>
#include <UserInterface/Dialogs/Listener.hpp>
#include <QFile>

#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>

using namespace HavocNamespace::HavocSpace;

class InputDialog : public QWidget
{
    QSpacerItem*    spacer2             = nullptr;
    QSpacerItem*    spacer              = nullptr;

    QPushButton*    button_Save         = nullptr;
    QPushButton*    button_Close        = nullptr;

public:
    QDialog*        InputDialogWidget   = nullptr;
    QGridLayout*    gridLayout          = nullptr;

    QLabel*         Description         = nullptr;
    QLineEdit*      Input               = nullptr;

    bool            DialogSave          = false;

    InputDialog( QDialog *Dialog )
    {
        InputDialogWidget = Dialog;

        if ( InputDialogWidget->objectName().isEmpty() )
            InputDialogWidget->setObjectName( QString::fromUtf8( "InputDialog" ) );


        Dialog->setStyleSheet(
            "QDialog {\n"
            "    background-color: #282a36;\n"
            "    color: #f8f8f2;\n"
            "}"

            "QLabel {\n"
            "    color: #f8f8f2;\n"
            "}\n"

            "QLineEdit {\n"
            "    background-color: #44475a;\n"
            "    color: #f8f8f2;\n"
            "}\n"

            "QLineEdit:read-only {\n"
            "    background-color: #313342;\n"
            "    color: #f8f8f2;\n"
            "}"

            "QPushButton {\n"
            "    border: 1px solid #bd93f9;\n"
            "    border-radius: 2px;\n"
            "    background-color: #bd93f9;\n"
            "    color: #282a36;\n"
            "    padding: 3px;\n"
            "    padding-right: 20px;\n"
            "    padding-left:  20px;\n"
            "}"
        );

        // InputDialogWidget->setMaximumSize( 432, 90 );
        // InputDialogWidget->resize( 432, 103 );

        gridLayout = new QGridLayout( InputDialogWidget );
        gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
        spacer2 = new QSpacerItem( 115, 30, QSizePolicy::Expanding, QSizePolicy::Minimum );

        gridLayout->addItem( spacer2, 2, 0, 1, 1 );

        button_Save = new QPushButton( InputDialogWidget );
        button_Save->setObjectName( QString::fromUtf8( "button_Save" ) );

        gridLayout->addWidget( button_Save, 2, 1, 1, 1 );

        button_Close = new QPushButton( InputDialogWidget );
        button_Close->setObjectName( QString::fromUtf8( "button_Close" ) );

        gridLayout->addWidget( button_Close, 2, 2, 1, 1 );

        spacer = new QSpacerItem( 115, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );

        gridLayout->addItem( spacer, 2, 3, 1, 1 );

        Description = new QLabel( InputDialogWidget );
        Description->setObjectName( QString::fromUtf8( "Description" ) );

        gridLayout->addWidget( Description, 0, 0, 1, 3 );

        Input = new QLineEdit( InputDialogWidget );
        Input->setObjectName( QString::fromUtf8( "Input" ) );
        Input->setFocus();

        gridLayout->addWidget( Input, 1, 0, 1, 4 );

        retranslateUi( InputDialogWidget );

        QObject::connect( button_Save, &QPushButton::clicked, this, &InputDialog::onButton_Save );
        QObject::connect( button_Close, &QPushButton::clicked, this, &InputDialog::onButton_Close );

        QMetaObject::connectSlotsByName( InputDialogWidget );
    }

    void retranslateUi(QDialog *InputDialog)
    {
        InputDialog->setWindowTitle( QCoreApplication::translate( "InputDialog", "Dialog", nullptr ) );
        button_Save->setText( QCoreApplication::translate( "InputDialog", "Save", nullptr ) );
        button_Close->setText( QCoreApplication::translate( "InputDialog", "Close", nullptr ) );
        Description->setText( QCoreApplication::translate( "InputDialog", "Description", nullptr ) );
    }

private slots:

    void onButton_Save()
    {
        DialogSave = true;
        InputDialogWidget->close();
    }

    void onButton_Close()
    {
        InputDialogWidget->close();
    }
};


HavocNamespace::UserInterface::Dialogs::NewListener::NewListener( QDialog* Dialog )
{
    ListenerDialog = Dialog;

    auto CtxStyleSheet = QString(
        "QMenu {\n"
        "    background-color: #282a36;\n"
        "    color: #f8f8f2;\n"
        "    border: 1px solid #f8f8f2;\n"
        "}"
        "\n"

        "QMenu::separator {\n"
        "    background: #44475a;\n"
        "}"
        "\n"

        "QMenu::item:selected {\n"
        "    background: #44475a;\n"
        "}"
        "\n"

        "QAction {\n"
        "    background-color: #282a36;\n"
        "    color: #f8f8f2;\n"
        "}"
    );

    if ( ListenerDialog->objectName().isEmpty() )
        ListenerDialog->setObjectName( QString::fromUtf8( "ListenerWidget" ) );

    Dialog->setStyleSheet( FileRead( ":/stylesheets/Dialogs/Listener" ) );

    CtxHeaders = new QMenu( this );
    CtxHeaders->addAction( "Add", this, &NewListener::ctx_itemHeadersAdd );
    CtxHeaders->addAction( "Remove", this, &NewListener::ctx_itemHeadersRemove );
    CtxHeaders->addAction( "Clear", this, &NewListener::ctx_itemHeadersClear );
    CtxHeaders->setStyleSheet( CtxStyleSheet );

    CtxUris = new QMenu( this );
    CtxUris->addAction( "Add", this, &NewListener::ctx_itemUrisAdd );
    CtxUris->addAction( "Remove", this, &NewListener::ctx_itemUrisRemove );
    CtxUris->addAction( "Clear", this, &NewListener::ctx_itemUrisClear );
    CtxUris->setStyleSheet( CtxStyleSheet );

    ListenerDialog->resize( 500, 541 );

    gridLayout = new QGridLayout( ListenerDialog );
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));

    ConfigBox = new QGroupBox( ListenerDialog );
    ConfigBox->setObjectName(QString::fromUtf8("ConfigBox"));

    gridLayout_2 = new QGridLayout( ConfigBox );
    gridLayout_2->setObjectName( QString::fromUtf8( "gridLayout_2" ) );
    gridLayout_2->setHorizontalSpacing( 0 );
    gridLayout_2->setContentsMargins( 0, 0, 0, 0 );

    StackWidgetConfigPages = new QStackedWidget( ConfigBox );
    StackWidgetConfigPages->setObjectName( QString::fromUtf8( "StackWidgetConfigPages" ) );

    PageHTTP = new QWidget();
    PageHTTP->setObjectName( QString::fromUtf8( "PageHTTP" ) );

    LabelHosts = new QLabel( PageHTTP );
    LabelHosts->setObjectName( QString::fromUtf8( "LabelHosts" ) );
    InputHost = new QLineEdit( PageHTTP );
    InputHost->setObjectName( QString::fromUtf8( "InputHost" ) );

    LabelPort = new QLabel( PageHTTP );
    LabelPort->setObjectName( QString::fromUtf8( "LabelPort" ) );
    InputPort = new QLineEdit( PageHTTP );
    InputPort->setObjectName( QString::fromUtf8( "InputPort" ) );

    InputUserAgent = new QLineEdit( PageHTTP );
    InputUserAgent->setObjectName( QString::fromUtf8( "InputUserAgent" ) );
    InputUserAgent->setText( "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" );
    InputUserAgent->setCursorPosition( 0 );

    ListHeaders = new QListWidget( PageHTTP );
    ListHeaders->setObjectName( QString::fromUtf8( "ListHeaders" ) );
    ListHeaders->setContextMenuPolicy( Qt::CustomContextMenu );
    ListHeaders->addAction( CtxHeaders->menuAction() );

    LabelUris = new QLabel( PageHTTP );
    LabelUris->setObjectName( QString::fromUtf8( "LabelUris" ) );

    LabelHeaders = new QLabel( PageHTTP );
    LabelHeaders->setObjectName( QString::fromUtf8( "LabelHeaders" ) );

    verticalSpacerHeader = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );

    LabelUserAgent = new QLabel( PageHTTP );
    LabelUserAgent->setObjectName(QString::fromUtf8("LabelUserAgent"));

    verticalSpacerUris = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    ListUris = new QListWidget(PageHTTP);
    ListUris->setObjectName(QString::fromUtf8("ListUris"));
    ListUris->setContextMenuPolicy( Qt::CustomContextMenu );
    ListUris->addAction( CtxUris->menuAction() );

    InputHostHeader = new QLineEdit(PageHTTP);
    InputHostHeader->setObjectName(QString::fromUtf8("InputHostHeader"));

    LabelHostHeader = new QLabel(PageHTTP);
    LabelHostHeader->setObjectName(QString::fromUtf8("LabelHostHeader"));

    CheckEnableProxy = new QCheckBox( PageHTTP );
    CheckEnableProxy->setObjectName( "bool" );
    CheckEnableProxy->setText( "Enable Proxy Connection" );

    ProxyConfigBox = new QGroupBox( PageHTTP );
    ProxyConfigBox->setObjectName( QString::fromUtf8( "ProxyConfigBox" ) );

    formLayout_3 = new QFormLayout( ProxyConfigBox );
    formLayout_3->setObjectName( QString::fromUtf8( "formLayout_3" ) );

    LabelProxyType = new QLabel( ProxyConfigBox );
    LabelProxyType->setObjectName( QString::fromUtf8( "LabelProxyHost" ) );
    LabelProxyType->setText( "Proxy Type" );
    formLayout_3->setWidget( 0, QFormLayout::LabelRole, LabelProxyType );

    ComboProxyType = new QComboBox( ProxyConfigBox );
    ComboProxyType->setObjectName( QString::fromUtf8( "ComboProxyType" ) );
    ComboProxyType->addItem( QString( "http" ) );
    ComboProxyType->addItem( QString( "https" ) );
    formLayout_3->setWidget( 0, QFormLayout::FieldRole, ComboProxyType );

    LabelProxyHost = new QLabel( ProxyConfigBox );
    LabelProxyHost->setObjectName( QString::fromUtf8( "LabelProxyHost" ) );
    formLayout_3->setWidget( 1, QFormLayout::LabelRole, LabelProxyHost );

    InputProxyHost = new QLineEdit( ProxyConfigBox );
    InputProxyHost->setObjectName( QString::fromUtf8( "InputProxyHost" ) );
    formLayout_3->setWidget( 1, QFormLayout::FieldRole, InputProxyHost );

    LabelProxyPort = new QLabel( ProxyConfigBox );
    LabelProxyPort->setObjectName(QString::fromUtf8("LabelProxyPort"));
    formLayout_3->setWidget( 2, QFormLayout::LabelRole, LabelProxyPort );

    InputProxyPort = new QLineEdit(ProxyConfigBox);
    InputProxyPort->setObjectName(QString::fromUtf8("InputProxyPort"));
    formLayout_3->setWidget( 2, QFormLayout::FieldRole, InputProxyPort );

    LabelUserName = new QLabel(ProxyConfigBox);
    LabelUserName->setObjectName(QString::fromUtf8("LabelUserName"));
    formLayout_3->setWidget( 3, QFormLayout::LabelRole, LabelUserName );

    InputUserName = new QLineEdit(ProxyConfigBox);
    InputUserName->setObjectName(QString::fromUtf8("InputUserName"));
    formLayout_3->setWidget( 3, QFormLayout::FieldRole, InputUserName );

    LabelPassword = new QLabel( ProxyConfigBox );
    LabelPassword->setObjectName( QString::fromUtf8( "LabelPassword" ) );
    formLayout_3->setWidget( 4, QFormLayout::LabelRole, LabelPassword );

    InputPassword = new QLineEdit( ProxyConfigBox );
    InputPassword->setObjectName(QString::fromUtf8("InputPassword"));
    formLayout_3->setWidget( 4, QFormLayout::FieldRole, InputPassword );

    PageSMB = new QWidget();
    PageSMB->setObjectName(QString::fromUtf8("PageSMB"));
    formLayout = new QFormLayout(PageSMB);
    formLayout->setObjectName(QString::fromUtf8("formLayout"));
    LabelPipeName = new QLabel(PageSMB);
    LabelPipeName->setObjectName(QString::fromUtf8("LabelPipeName"));

    formLayout->setWidget(0, QFormLayout::LabelRole, LabelPipeName);

    InputPipeName = new QLineEdit(PageSMB);
    InputPipeName->setObjectName(QString::fromUtf8("InputPipeName"));

    formLayout->setWidget(0, QFormLayout::FieldRole, InputPipeName);

    PageExternal = new QWidget();
    PageExternal->setObjectName(QString::fromUtf8("PageExternal"));
    formLayout_2 = new QFormLayout(PageExternal);
    formLayout_2->setObjectName(QString::fromUtf8("formLayout_2"));
    LabelEndpoint = new QLabel(PageExternal);
    LabelEndpoint->setObjectName(QString::fromUtf8("LabelEndpoint"));

    formLayout_2->setWidget(0, QFormLayout::LabelRole, LabelEndpoint);

    InputEndpoint = new QLineEdit(PageExternal);
    InputEndpoint->setObjectName(QString::fromUtf8("InputEndpoint"));

    formLayout_2->setWidget(0, QFormLayout::FieldRole, InputEndpoint);

    gridLayout_2->addWidget( StackWidgetConfigPages, 0, 0, 1, 1 );


    gridLayout->addWidget(ConfigBox, 3, 0, 1, 6);

    ComboPayload = new QComboBox( ListenerDialog );
    ComboPayload->setObjectName( QString::fromUtf8( "ComboPayload" ) );

    gridLayout->addWidget(ComboPayload, 1, 1, 1, 5);

    LabelListenerName = new QLabel(ListenerDialog);
    LabelListenerName->setObjectName(QString::fromUtf8("LabelListenerName"));

    gridLayout->addWidget(LabelListenerName, 0, 0, 1, 1);

    LabelPayload = new QLabel(ListenerDialog);
    LabelPayload->setObjectName(QString::fromUtf8("LabelPayload"));

    gridLayout->addWidget(LabelPayload, 1, 0, 1, 1);

    horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_5, 4, 4, 1, 1);

    ButtonSave = new QPushButton(ListenerDialog);
    ButtonSave->setObjectName(QString::fromUtf8("ButtonSave"));

    gridLayout->addWidget(ButtonSave, 4, 2, 1, 1);

    horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_4, 4, 1, 1, 1);

    horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_3, 4, 5, 1, 1);

    InputListenerName = new QLineEdit(ListenerDialog);
    InputListenerName->setObjectName(QString::fromUtf8("InputListenerName"));

    gridLayout->addWidget(InputListenerName, 0, 1, 1, 5);

    horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_2, 4, 0, 1, 1);

    ButtonClose = new QPushButton(ListenerDialog);
    ButtonClose->setObjectName(QString::fromUtf8("ButtonClose"));

    gridLayout->addWidget(ButtonClose, 4, 3, 1, 1);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 2, 0, 1, 6);

    StackWidgetConfigPages->setCurrentIndex( 0 );

    // Page HTTP/HTTPs
    gridLayout_3 = new QGridLayout( PageHTTP );
    gridLayout_3->setObjectName( QString::fromUtf8( "gridLayout_3" ) );

    gridLayout_3->addWidget( LabelHosts, 0, 0, 1, 1 );
    gridLayout_3->addWidget( InputHost,  0, 1, 1, 1 );

    gridLayout_3->addWidget( LabelPort, 1, 0, 1, 1 );
    gridLayout_3->addWidget( InputPort, 1, 1, 1, 1 );

    gridLayout_3->addWidget( LabelHeaders, 5, 0, 1, 1 );
    gridLayout_3->addWidget( ListHeaders,  5, 1, 2, 1 );
    gridLayout_3->addItem( verticalSpacerHeader, 6, 0, 1, 1 );

    gridLayout_3->addWidget( LabelUserAgent, 3, 0, 1, 1 );
    gridLayout_3->addWidget( InputUserAgent, 3, 1, 1, 1 );

    gridLayout_3->addWidget( LabelUris, 7, 0, 1, 1 );
    gridLayout_3->addWidget( ListUris,  7, 1, 2, 1 );
    gridLayout_3->addItem( verticalSpacerUris, 8, 0, 1, 1 );

    gridLayout_3->addWidget( LabelHostHeader, 9, 0, 1, 1 );
    gridLayout_3->addWidget( InputHostHeader, 9, 1, 1, 1 );

    gridLayout_3->addWidget( CheckEnableProxy, 10, 0, 1, 2 );
    gridLayout_3->addWidget( ProxyConfigBox,   11, 0, 1, 2 );

    ProxyConfigBox->setEnabled( false );

    InputProxyHost->setReadOnly( true );
    InputProxyPort->setReadOnly( true );
    InputUserName->setReadOnly( true );
    InputPassword->setReadOnly( true );

    InputProxyHost->setPlaceholderText( "" );

    LabelProxyHost->setEnabled( false );
    LabelProxyPort->setEnabled( false );
    LabelUserName->setEnabled( false );
    LabelPassword->setEnabled( false );

    auto style = QString( "color: #44475a;" );
    LabelProxyType->setStyleSheet( style );
    LabelProxyHost->setStyleSheet( style );
    LabelProxyPort->setStyleSheet( style );
    LabelUserName->setStyleSheet( style );
    LabelPassword->setStyleSheet( style );

    // Add Pages
    StackWidgetConfigPages->addWidget( PageHTTP );
    StackWidgetConfigPages->addWidget( PageSMB );
    StackWidgetConfigPages->addWidget( PageExternal );

    ListenerDialog->setWindowTitle( "Create Listener" );
    ConfigBox->setTitle( QCoreApplication::translate( "ListenerWidget", "Config Options", nullptr ) );
    LabelPort->setText( QCoreApplication::translate( "ListenerWidget", "Port:", nullptr ) );
    LabelHosts->setText( QCoreApplication::translate( "ListenerWidget", "Host:", nullptr ) );
    LabelUris->setText( QCoreApplication::translate( "ListenerWidget", "Uris:", nullptr ) );
    LabelHeaders->setText( QCoreApplication::translate( "ListenerWidget", "Headers:", nullptr ) );
    LabelProxyHost->setText( QCoreApplication::translate( "ListenerWidget", "Proxy Host:", nullptr ) );
    LabelProxyPort->setText( QCoreApplication::translate( "ListenerWidget", "Proxy Port: ", nullptr ) );
    LabelUserName->setText( QCoreApplication::translate( "ListenerWidget", "UserName: ", nullptr ) );
    LabelPassword->setText( QCoreApplication::translate( "ListenerWidget", "Password: ", nullptr ) );
    LabelUserAgent->setText( QCoreApplication::translate( "ListenerWidget", "User Agent:  ", nullptr ) );
    LabelHostHeader->setText( QCoreApplication::translate( "ListenerWidget", "Host Header: ", nullptr ) );
    LabelPipeName->setText( QCoreApplication::translate( "ListenerWidget", "Pipe Name: :", nullptr ) );
    LabelEndpoint->setText( QCoreApplication::translate( "ListenerWidget", "Endpoint: ", nullptr ) );

    LabelListenerName->setText(QCoreApplication::translate("ListenerWidget", "Name:", nullptr));
    LabelPayload->setText(QCoreApplication::translate("ListenerWidget", "Payload: ", nullptr));
    ButtonSave->setText(QCoreApplication::translate("ListenerWidget", "Save", nullptr));
    ButtonClose->setText(QCoreApplication::translate("ListenerWidget", "Close", nullptr));

    ComboPayload->addItem( "Https" );
    ComboPayload->addItem( "Http" );
    ComboPayload->addItem( "Smb" );
    ComboPayload->addItem( "External" );

    QObject::connect( ButtonSave, &QPushButton::clicked, this, &NewListener::onButton_Save );
    QObject::connect( ButtonClose, &QPushButton::clicked, this, &NewListener::onButton_Close );

    QObject::connect( ListHeaders, &QListWidget::customContextMenuRequested, this, &NewListener::ctx_handleHeaders );
    QObject::connect( ListUris, &QListWidget::customContextMenuRequested, this, &NewListener::ctx_handleUris );

    QObject::connect( ComboPayload, &QComboBox::currentTextChanged, this, &NewListener::ctx_PayloadChange );
    QObject::connect( CheckEnableProxy, &QCheckBox::toggled, this, &NewListener::onProxyEnabled );

    QMetaObject::connectSlotsByName( Dialog );
}

bool is_number(const std::string& s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}

map<string, string> HavocNamespace::UserInterface::Dialogs::NewListener::Start( Util::ListenerItem Item, bool Edit ) const
{
    auto ListenerInfo = map<string,string>{};
    auto Payload      = QString();

    if ( Edit )
    {
        InputListenerName->setText( Item.Name.c_str() );
        InputListenerName->setReadOnly( true );

        if ( ( Item.Protocol == Listener::PayloadHTTP.toStdString() ) || ( Item.Protocol == Listener::PayloadHTTPS.toStdString() ) )
        {
            if ( Item.Protocol == Listener::PayloadHTTP.toStdString() )
                ComboPayload->setCurrentIndex( 0 );
            else
                ComboPayload->setCurrentIndex( 1 );
            ComboPayload->setDisabled( true );

            auto Info = any_cast<Listener::HTTP>( Item.Info );

            InputHost->setText( Info.Host );
            InputHost->setReadOnly( true );

            InputPort->setText( Info.Port );
            InputPort->setReadOnly( true );

            InputUserAgent->setText( Info.UserAgent );
            ListHeaders->addItems( Info.Headers );
            ListUris->addItems( Info.Uris );
            InputHostHeader->setText( Info.HostHeader );

            if ( Info.ProxyEnabled.compare( "true" ) == 0 )
                CheckEnableProxy->setCheckState( Qt::CheckState::Checked );
            else
                CheckEnableProxy->setCheckState( Qt::CheckState::Unchecked );

            if ( Info.ProxyType.compare( "http" ) == 0 )
                ComboProxyType->setCurrentIndex( 0 );
            else
                ComboProxyType->setCurrentIndex( 1 );

            InputProxyHost->setText( Info.ProxyHost );
            InputProxyPort->setText( Info.ProxyPort );
            InputUserName->setText( Info.ProxyUsername );
            InputPassword->setText( Info.ProxyPassword );
        }
        else if ( Item.Protocol == Listener::PayloadSMB.toStdString() )
        {
            ComboPayload->setCurrentIndex( 2 );
            auto Info = any_cast<Listener::SMB>( Item.Info );

            InputPipeName->setText( Info.PipeName );
            InputPipeName->setReadOnly( true );
        }
        else if ( Item.Protocol == Listener::PayloadExternal.toStdString() )
        {
            ComboPayload->setCurrentIndex( 3 );

            auto Info = any_cast<Listener::External>( Item.Info );

            InputEndpoint->setText( Info.Endpoint );
            InputEndpoint->setReadOnly( true );
        }

        ListenerDialog->setWindowTitle( "Edit Listener" );
        ComboPayload->setDisabled( true );
    }

    ListenerDialog->exec();

    Payload = ComboPayload->currentText();

    ListenerInfo.insert( { "Name", InputListenerName->text().toStdString() } );
    ListenerInfo.insert( { "Protocol", ComboPayload->currentText().toStdString() } );
    ListenerInfo.insert( { "Status", "online" } );

    if ( ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 ) || ( Payload.compare( HavocSpace::Listener::PayloadHTTP ) == 0 ) )
    {
        auto Headers = std::string();
        auto Uris    = std::string();

        if ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
            ListenerInfo.insert( { "Secure", "true" } );
        else
            ListenerInfo.insert( { "Secure", "false" } );

        for ( u32 i = 0; i < ListHeaders->count(); ++i )
        {
            if ( i == ( ListHeaders->count() - 1 ) )
                Headers += ListHeaders->item( i )->text().toStdString();
            else
                Headers += ListHeaders->item( i )->text().toStdString() + ", ";
        }

        for ( u32 i = 0; i < ListUris->count(); ++i )
        {
            if ( i == ( ListUris->count() - 1 ) )
                Uris += ListUris->item( i )->text().toStdString();
            else
                Uris += ListUris->item( i )->text().toStdString() + ", ";
        }

        ListenerInfo.insert( { "Hosts", InputHost->text().toStdString() } );
        ListenerInfo.insert( { "Port", InputPort->text().toStdString() } );
        ListenerInfo.insert( { "Headers", Headers } );
        ListenerInfo.insert( { "Uris", Uris } );
        ListenerInfo.insert( { "UserAgent", InputUserAgent->text().toStdString() } );
        ListenerInfo.insert( { "HostHeader", InputHostHeader->text().toStdString() } );

        ListenerInfo.insert( { "Proxy Enabled", CheckEnableProxy->isChecked() ? "true" : "false" } );

        if ( CheckEnableProxy->isChecked() )
        {
            ListenerInfo.insert( { "Proxy Type", ComboProxyType->currentText().toStdString() } );
            ListenerInfo.insert( { "Proxy Host", InputProxyHost->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Port", InputProxyPort->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Username", InputUserName->text().toStdString() } );
            ListenerInfo.insert( { "Proxy Password", InputPassword->text().toStdString() } );
        }
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadSMB ) == 0 )
    {
        ListenerInfo.insert( { "PipeName", InputPipeName->text().toStdString() } );
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadExternal ) == 0 )
    {
        for ( auto& Listener : HavocX::Teamserver.Listeners )
        {
            if ( Listener.Protocol == HavocSpace::Listener::PayloadExternal.toStdString() )
            {
                if ( any_cast<HavocSpace::Listener::External>( Listener.Info ).Endpoint.compare( InputEndpoint->text() ) == 0 )
                {
                    MessageBox( "Listener Error", "Listener External: Endpoint already registered.", QMessageBox::Icon::Critical );
                    return map<string,string>{};
                }
            }
        }

        ListenerInfo.insert( { "Endpoint", InputEndpoint->text().toStdString() } );
    }
    else
    {
        spdlog::error( "Payload not found" );
        return map<string,string>{};
    }

    return ListenerInfo;
}

void HavocNamespace::UserInterface::Dialogs::NewListener::onButton_Save()
{
    auto Style   = QFile(":/stylesheets/MessageBox");
    auto MsgBox  = QMessageBox();
    auto Payload = ComboPayload->currentText();

    if (
        ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 ) ||
        ( Payload.compare( HavocSpace::Listener::PayloadHTTP )  == 0 )
    )
    {
        if ( InputHost->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Host specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();
            return;
        }

        if ( ListUris->count() == 0 )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Uris specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            return;
        }

        if ( InputPort->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Port specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();
            return;
        }
        else
        {
            if ( ! is_number( InputPort->text().toStdString() ) )
            {
                Style.open( QIODevice::ReadOnly );

                MsgBox.setWindowTitle( "Listener Error" );
                MsgBox.setText( "Port is not a number" );
                MsgBox.setIcon( QMessageBox::Critical );
                MsgBox.setStyleSheet( Style.readAll() );
                MsgBox.exec();

                Style.close();
                return;
            }
        }

        if ( InputUserAgent->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No UserAgent specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();
            return;
        }

        if ( CheckEnableProxy->isChecked() )
        {
            if ( InputProxyHost->text().isEmpty() )
            {
                Style.open( QIODevice::ReadOnly );

                MsgBox.setWindowTitle( "Listener Error" );
                MsgBox.setText( "No Proxy Host specified" );
                MsgBox.setIcon( QMessageBox::Critical );
                MsgBox.setStyleSheet( Style.readAll() );
                MsgBox.exec();

                Style.close();
                return;
            }

            if ( InputProxyPort->text().isEmpty() )
            {
                Style.open( QIODevice::ReadOnly );

                MsgBox.setWindowTitle( "Listener Error" );
                MsgBox.setText( "No Proxy Port specified" );
                MsgBox.setIcon( QMessageBox::Critical );
                MsgBox.setStyleSheet( Style.readAll() );
                MsgBox.exec();

                Style.close();
                return;
            }
            else
            {
                if ( ! is_number( InputProxyPort->text().toStdString() ) )
                {
                    Style.open( QIODevice::ReadOnly );

                    MsgBox.setWindowTitle( "Listener Error" );
                    MsgBox.setText( "Port is not a number" );
                    MsgBox.setIcon( QMessageBox::Critical );
                    MsgBox.setStyleSheet( Style.readAll() );
                    MsgBox.exec();

                    Style.close();
                    return;
                }
            }
        }

    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadSMB )  == 0 )
    {
        if ( InputPipeName->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Pipe name specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();
            return;
        }
    }
    else if ( Payload.compare( HavocSpace::Listener::PayloadExternal )  == 0 )
    {
        if ( InputEndpoint->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Endpoint specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();Style.close();
            return;
        }
    }

    this->DialogSaved = true;
    this->ListenerDialog->close();

}

void HavocNamespace::UserInterface::Dialogs::NewListener::onButton_Close()
{
    this->DialogClosed = true;
    this->ListenerDialog->close();
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_handleHeaders( const QPoint &pos )
{
    QPoint globalPos = ListHeaders->mapToGlobal( pos );
    CtxHeaders->exec( globalPos );
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_handleUris( const QPoint &pos )
{
    QPoint globalPos = ListUris->mapToGlobal( pos );
    CtxUris->exec( globalPos );
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_PayloadChange( const QString& text )
{
    if ( text.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 0 );
    }
    else if ( text.compare( HavocSpace::Listener::PayloadHTTP ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 0 );
    }
    else if ( text.compare( HavocSpace::Listener::PayloadSMB ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 1 );
    }
    else if ( text.compare( HavocSpace::Listener::PayloadExternal ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 2 );
    }
    else
    {
        spdlog::error( "Payload not found" );
    }
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemHeadersAdd()
{
    auto InputHeaders = new InputDialog( new QDialog );

    InputHeaders->Description->setText( "Add one or multiple Headers" );
    InputHeaders->InputDialogWidget->setWindowTitle( "Headers" );

    InputHeaders->InputDialogWidget->exec();

    if ( InputHeaders->DialogSave )
    {
        auto Headers = InputHeaders->Input->text();
        if ( Headers.size() > 0 )
        {
            for ( auto& Header : Headers.split( "," ) )
                ListHeaders->addItem( new QListWidgetItem( Header.replace( " ", "" ), ListHeaders ) );
        }
    }

    delete InputHeaders;
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemHeadersRemove()
{
    QList< QListWidgetItem* > items = ListHeaders->selectedItems();

    foreach( QListWidgetItem* item, items )
    {
        delete ListHeaders->takeItem( ListHeaders->row( item ) );
    }
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemHeadersClear()
{
    ListHeaders->clear();
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemUrisAdd()
{
    auto InputUri = new InputDialog( new QDialog );

    InputUri->Description->setText( "Add one or multiple Uris" );
    InputUri->InputDialogWidget->setWindowTitle( "Uris" );

    InputUri->InputDialogWidget->exec();

    if ( InputUri->DialogSave )
    {
        auto Uris = InputUri->Input->text();
        if ( Uris.size() > 0 )
        {
            for ( auto& Uri : Uris.split( "," ) )
                ListUris->addItem( new QListWidgetItem( Uri.replace( " ", "" ), ListUris ) );
        }
    }

    delete InputUri;
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemUrisRemove()
{
    QList< QListWidgetItem* > items = ListUris->selectedItems();

    foreach( QListWidgetItem* item, items )
    {
        delete ListUris->takeItem( ListUris->row( item ) );
    }
}

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_itemUrisClear()
{
    ListUris->clear();
}

void HavocNamespace::UserInterface::Dialogs::NewListener::onProxyEnabled()
{
    if ( CheckEnableProxy->isChecked() )
    {
        ProxyConfigBox->setEnabled( true );

        auto style = QString( "color: #f8f8f2;" );
        LabelProxyType->setStyleSheet( style );
        LabelProxyHost->setStyleSheet( style );
        LabelProxyPort->setStyleSheet( style );
        LabelUserName->setStyleSheet( style );
        LabelPassword->setStyleSheet( style );

        InputProxyHost->setReadOnly( false );
        InputProxyPort->setReadOnly( false );
        InputUserName->setReadOnly( false );
        InputPassword->setReadOnly( false );

        LabelProxyHost->setEnabled( false );
        LabelProxyPort->setEnabled( false );
        LabelUserName->setEnabled( false );
        LabelPassword->setEnabled( false );
    }
    else
    {
        ProxyConfigBox->setEnabled( false );

        auto style = QString( "color: #44475a;" );
        LabelProxyType->setStyleSheet( style );
        LabelProxyHost->setStyleSheet( style );
        LabelProxyPort->setStyleSheet( style );
        LabelUserName->setStyleSheet( style );
        LabelPassword->setStyleSheet( style );

        InputProxyHost->setReadOnly( true );
        InputProxyPort->setReadOnly( true );
        InputUserName->setReadOnly( true );
        InputPassword->setReadOnly( true );

        LabelProxyHost->setEnabled( true );
        LabelProxyPort->setEnabled( true );
        LabelUserName->setEnabled( true );
        LabelPassword->setEnabled( true );
    }
}
