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

    if ( ListenerDialog->objectName().isEmpty() )
        ListenerDialog->setObjectName( QString::fromUtf8( "ListenerWidget" ) );

    Dialog->setStyleSheet( FileRead( ":/stylesheets/Dialogs/Listener" ) );

    ListenerDialog->resize( 550, 600 );

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

    // ============
    // === HTTP ===
    // ============
    PageHTTP = new QWidget();
    PageHTTP->setObjectName( QString::fromUtf8( "PageHTTP" ) );

    LabelHosts              = new QLabel( PageHTTP );
    HostsGroup              = new QGroupBox( PageHTTP );
    ButtonHostsGroupAdd     = new QPushButton( PageHTTP );
    ButtonHostsGroupClear   = new QPushButton( PageHTTP );

    LabelHostRotation       = new QLabel( PageHTTP );
    ComboHostRotation       = new QComboBox( PageHTTP );

    LabelHostBind           = new QLabel( PageHTTP );
    ComboHostBind           = new QComboBox( PageHTTP );

    LabelPort               = new QLabel( PageHTTP );
    InputPort               = new QLineEdit( PageHTTP );

    LabelUserAgent          = new QLabel( PageHTTP );
    InputUserAgent          = new QLineEdit( PageHTTP );

    LabelHeaders            = new QLabel( PageHTTP );
    HeadersGroup            = new QGroupBox( PageHTTP );
    ButtonHeaderGroupAdd    = new QPushButton( PageHTTP );
    ButtonHeaderGroupClear  = new QPushButton( PageHTTP );

    LabelUris               = new QLabel( PageHTTP );
    UrisGroup               = new QGroupBox( PageHTTP );
    ButtonUriGroupClear     = new QPushButton( PageHTTP );
    ButtonUriGroupAdd       = new QPushButton( PageHTTP );

    LabelHostHeader         = new QLabel( PageHTTP );
    InputHostHeader         = new QLineEdit( PageHTTP );

    CheckEnableProxy        = new QCheckBox( PageHTTP );

    horizontalSpacer_6      = new QSpacerItem( 0, 0, QSizePolicy::Expanding, QSizePolicy::Minimum );
    verticalSpacer          = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );
    verticalSpacerHeader    = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );
    ProxyConfigBox          = new QGroupBox( PageHTTP );
    verticalSpacerUris      = new QSpacerItem( 20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding );

    formLayout_Hosts        = new QFormLayout( HostsGroup );
    formLayout_Header       = new QFormLayout( HeadersGroup );
    formLayout_Uri          = new QFormLayout( UrisGroup );
    formLayout_3            = new QFormLayout( ProxyConfigBox );

    LabelProxyType = new QLabel( ProxyConfigBox );
    ComboProxyType = new QComboBox( ProxyConfigBox );
    LabelProxyHost = new QLabel( ProxyConfigBox );
    InputProxyHost = new QLineEdit( ProxyConfigBox );
    LabelProxyPort = new QLabel( ProxyConfigBox );
    InputProxyPort = new QLineEdit( ProxyConfigBox );
    LabelUserName  = new QLabel( ProxyConfigBox );
    InputUserName  = new QLineEdit( ProxyConfigBox );
    LabelPassword  = new QLabel( ProxyConfigBox );
    InputPassword  = new QLineEdit( ProxyConfigBox );

    formLayout_3->setWidget( 0, QFormLayout::LabelRole, LabelProxyType );
    formLayout_3->setWidget( 0, QFormLayout::FieldRole, ComboProxyType );
    formLayout_3->setWidget( 1, QFormLayout::LabelRole, LabelProxyHost );
    formLayout_3->setWidget( 1, QFormLayout::FieldRole, InputProxyHost );
    formLayout_3->setWidget( 2, QFormLayout::LabelRole, LabelProxyPort );
    formLayout_3->setWidget( 2, QFormLayout::FieldRole, InputProxyPort );
    formLayout_3->setWidget( 3, QFormLayout::LabelRole, LabelUserName );
    formLayout_3->setWidget( 3, QFormLayout::FieldRole, InputUserName );
    formLayout_3->setWidget( 4, QFormLayout::LabelRole, LabelPassword );
    formLayout_3->setWidget( 4, QFormLayout::FieldRole, InputPassword );

    ComboHostBind->addItems( QStringList() << HavocX::Teamserver.IpAddresses << "127.0.0.1" << "0.0.0.0" );

    CheckEnableProxy->setObjectName( "bool" );
    ProxyConfigBox->setEnabled( true );
    InputUserAgent->setText( "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" ); // default. maybe make it dynamic/random ?
    InputUserAgent->setCursorPosition( 0 );
    InputPort->setText( "443" );

    // =============
    // ==== SMB ====
    // =============
    PageSMB = new QWidget();
    PageSMB->setObjectName(QString::fromUtf8("PageSMB"));
    formLayout = new QFormLayout( PageSMB );
    formLayout->setObjectName(QString::fromUtf8("formLayout"));
    LabelPipeName = new QLabel( PageSMB );
    LabelPipeName->setObjectName(QString::fromUtf8("LabelPipeName"));

    formLayout->setWidget(0, QFormLayout::LabelRole, LabelPipeName);

    InputPipeName = new QLineEdit( PageSMB );
    InputPipeName->setObjectName( QString::fromUtf8( "InputPipeName" ) );

    formLayout->setWidget(0, QFormLayout::FieldRole, InputPipeName);

    // ==============
    // == External ==
    // ==============
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

    gridLayout_3->addWidget( LabelUserAgent, 8, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonUriGroupClear, 16, 2, 1, 1 );
    gridLayout_3->addWidget( ComboHostBind, 5, 1, 1, 2 );
    gridLayout_3->addWidget( LabelUris, 15, 0, 1, 1 );
    gridLayout_3->addWidget( LabelHostHeader, 19, 0, 1, 1 );
    gridLayout_3->addWidget( InputPort, 6, 1, 1, 2 );
    gridLayout_3->addWidget( CheckEnableProxy, 20, 0, 1, 3 );
    gridLayout_3->addWidget( ButtonHeaderGroupClear, 11, 2, 1, 1 );
    gridLayout_3->addWidget( InputHostHeader, 19, 1, 1, 2 );
    gridLayout_3->addWidget( LabelHeaders, 10, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonHostsGroupAdd, 0, 2, 1, 1 );
    gridLayout_3->addWidget( LabelHostBind, 5, 0, 1, 1 );
    gridLayout_3->addWidget( InputUserAgent, 8, 1, 1, 2 );
    gridLayout_3->addWidget( ButtonUriGroupAdd, 15, 2, 1, 1 );
    gridLayout_3->addWidget( HeadersGroup, 10, 1, 3, 1 );
    gridLayout_3->addWidget( LabelHosts, 0, 0, 1, 1 );
    gridLayout_3->addWidget( ButtonHostsGroupClear, 1, 2, 1, 1 );
    gridLayout_3->addWidget( ButtonHeaderGroupAdd, 10, 2, 1, 1 );
    gridLayout_3->addWidget( HostsGroup, 0, 1, 4, 1 );
    gridLayout_3->addWidget( LabelPort, 6, 0, 1, 1 );
    gridLayout_3->addWidget( ProxyConfigBox, 21, 0, 1, 3 );
    gridLayout_3->addWidget( UrisGroup, 15, 1, 3, 1 );
    gridLayout_3->addWidget( LabelHostRotation, 4, 0, 1, 1 );
    gridLayout_3->addWidget( ComboHostRotation, 4, 1, 1, 2 );
    gridLayout_3->addItem( horizontalSpacer_6, 18, 1, 1, 1 );
    gridLayout_3->addItem( verticalSpacer, 2, 0, 1, 1 );
    gridLayout_3->addItem( verticalSpacerHeader, 12, 0, 1, 1 );
    gridLayout_3->addItem( verticalSpacerUris, 17, 0, 1, 1 );

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
    LabelPayload->setText(QCoreApplication::translate("ListenerWidget", "Payload: ", nullptr));
    ComboPayload->setItemText(0, QCoreApplication::translate("ListenerWidget", "Https", nullptr));
    ComboPayload->setItemText(1, QCoreApplication::translate("ListenerWidget", "Http", nullptr));
    ComboPayload->setItemText(2, QCoreApplication::translate("ListenerWidget", "Smb", nullptr));
    ComboPayload->setItemText(3, QCoreApplication::translate("ListenerWidget", "External", nullptr));

    LabelListenerName->setText(QCoreApplication::translate("ListenerWidget", "Name:", nullptr));
    ButtonSave->setText(QCoreApplication::translate("ListenerWidget", "Save", nullptr));
    ButtonClose->setText(QCoreApplication::translate("ListenerWidget", "Close", nullptr));
    ConfigBox->setTitle(QCoreApplication::translate("ListenerWidget", "Config Options", nullptr));
    LabelUserAgent->setText(QCoreApplication::translate("ListenerWidget", "User Agent:  ", nullptr));
    ButtonUriGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    LabelUris->setText(QCoreApplication::translate("ListenerWidget", "Uris:", nullptr));
    LabelHostHeader->setText(QCoreApplication::translate("ListenerWidget", "Host Header: ", nullptr));
    CheckEnableProxy->setText(QCoreApplication::translate("ListenerWidget", "Enable Proxy connection", nullptr));
    ButtonHeaderGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    LabelHeaders->setText(QCoreApplication::translate("ListenerWidget", "Headers:", nullptr));
    ButtonHostsGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelHostBind->setText(QCoreApplication::translate("ListenerWidget", "Host (Bind):", nullptr));
    ButtonUriGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelHosts->setText(QCoreApplication::translate("ListenerWidget", "Hosts", nullptr));
    ButtonHostsGroupClear->setText(QCoreApplication::translate("ListenerWidget", "Clear", nullptr));
    ButtonHeaderGroupAdd->setText(QCoreApplication::translate("ListenerWidget", "Add", nullptr));
    LabelPort->setText(QCoreApplication::translate("ListenerWidget", "Port:", nullptr));
    LabelProxyType->setText(QCoreApplication::translate("ListenerWidget", "Proxy Type:", nullptr));
    LabelProxyHost->setText(QCoreApplication::translate("ListenerWidget", "Proxy Host:", nullptr));
    LabelProxyPort->setText(QCoreApplication::translate("ListenerWidget", "Proxy Port: ", nullptr));
    LabelUserName->setText(QCoreApplication::translate("ListenerWidget", "UserName: ", nullptr));
    LabelPassword->setText(QCoreApplication::translate("ListenerWidget", "Password: ", nullptr));
    LabelHostRotation->setText(QCoreApplication::translate("ListenerWidget", "Host Rotation: ", nullptr));
    LabelPipeName->setText(QCoreApplication::translate("ListenerWidget", "Pipe Name: :", nullptr));
    LabelEndpoint->setText(QCoreApplication::translate("ListenerWidget", "Endpoint: ", nullptr));

    ComboPayload->addItem( "Https" );
    ComboPayload->addItem( "Http" );
    ComboPayload->addItem( "Smb" );
    ComboPayload->addItem( "External" );

    ComboProxyType->addItem( "http" );
    ComboProxyType->addItem( "https" );

    ComboHostRotation->addItem( "round-robin" );
    ComboHostRotation->addItem( "random" );

    QObject::connect( ButtonSave, &QPushButton::clicked, this, &NewListener::onButton_Save );
    QObject::connect( ButtonClose, &QPushButton::clicked, this, &NewListener::onButton_Close );

    QObject::connect( ButtonHostsGroupAdd, &QPushButton::clicked, this, [&](){
        auto Item = new QLineEdit;
        Item->setFocus();

        if ( HostsData.size() == 0 )
            Item->setText( HavocX::Teamserver.IpAddresses[ 0 ] );

        formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, Item );

        HostsData.push_back( Item );
        ListenerDialog->resize( 550, 500 );
    } );

    QObject::connect( ButtonHostsGroupClear, &QPushButton::clicked, this, [&](){
        for ( auto& uri : HostsData )
            delete uri;

        HostsData.clear();

        ListenerDialog->resize( 550, 500 );
    } );

    QObject::connect( ButtonUriGroupAdd, &QPushButton::clicked, this, [&](){
        auto Item = new QLineEdit;
        Item->setFocus();

        formLayout_Uri->setWidget( UrisData.size(), QFormLayout::FieldRole, Item );

        UrisData.push_back( Item );
        ListenerDialog->resize( 550, 500 );
    } );

    QObject::connect( ButtonUriGroupClear, &QPushButton::clicked, this, [&](){
        for ( auto& uri : UrisData )
            delete uri;

        UrisData.clear();

        ListenerDialog->resize( 550, 500 );
    } );

    QObject::connect( ButtonHeaderGroupAdd, &QPushButton::clicked, this, [&](){
        auto Item = new QLineEdit;
        Item->setFocus();

        formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, Item );

        HeadersData.push_back( Item );
        ListenerDialog->resize( 550, 500 );
    } );

    QObject::connect( ButtonHeaderGroupClear, &QPushButton::clicked, this, [&](){
        for ( auto& header : HeadersData )
            delete header;

        HeadersData.clear();

        ListenerDialog->resize( 550, 500 );
    } );

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

map<string, string> HavocNamespace::UserInterface::Dialogs::NewListener::Start( Util::ListenerItem Item, bool Edit )
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

            ComboHostBind->addItem( Info.HostBind );
            ComboHostBind->setDisabled( true );

            if ( Info.HostRotation.compare( "round-robin" ) == 0 )
                ComboHostRotation->setCurrentIndex( 0 );
            else if ( Info.HostRotation.compare( "random" ) == 0 )
                ComboHostRotation->setCurrentIndex( 1 );
            else
                ComboHostRotation->setCurrentIndex( 0 );

            InputPort->setText( Info.Port );
            InputPort->setReadOnly( true );

            InputUserAgent->setText( Info.UserAgent );
            InputUserAgent->setCursorPosition( 0 );

            if ( ! Info.Hosts.empty() )
            {
                for ( const auto& host : Info.Hosts )
                {
                    if ( host.isEmpty() )
                        continue;

                    auto input = new QLineEdit;
                    input->setText( host );

                    formLayout_Hosts->setWidget( HostsData.size(), QFormLayout::FieldRole, input );

                    HostsData.push_back( input );
                }
            }

            if ( ! Info.Headers.empty() )
            {
                for ( const auto& header : Info.Headers )
                {
                    if ( header.isEmpty() )
                        continue;

                    auto input = new QLineEdit;
                    input->setText( header );

                    formLayout_Header->setWidget( HeadersData.size(), QFormLayout::FieldRole, input );

                    HeadersData.push_back( input );
                }
            }

            if ( ! Info.Uris.empty() )
            {
                for ( const auto& uri : Info.Uris )
                {
                    if ( uri.isEmpty() )
                        continue;

                    auto input = new QLineEdit;
                    input->setText(uri );

                    formLayout_Uri->setWidget(UrisData.size(), QFormLayout::FieldRole, input );

                    UrisData.push_back(input );
                }
            }

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
        auto Hosts   = std::string();
        auto Headers = std::string();
        auto Uris    = std::string();

        if ( Payload.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
            ListenerInfo.insert( { "Secure", "true" } );
        else
            ListenerInfo.insert( { "Secure", "false" } );

        if ( HostsData.size() > 0 )
        {
            for ( u32 i = 0; i < HostsData.size(); ++i )
            {
                if ( i == ( HostsData.size() - 1 ) )
                    Hosts += HostsData.at( i )->text().toStdString();
                else
                    Hosts += HostsData.at( i )->text().toStdString() + ", ";

                delete HostsData.at( i );
            }
        }
        else
        {
            Hosts = ComboHostBind->currentText().toStdString();
        }

        if ( HeadersData.size() > 0 )
        {
            for ( u32 i = 0; i < HeadersData.size(); ++i )
            {
                if ( i == ( HeadersData.size() - 1 ) )
                    Headers += HeadersData.at( i )->text().toStdString();
                else
                    Headers += HeadersData.at( i )->text().toStdString() + ", ";

                delete HeadersData.at( i );
            }
        }

        if ( UrisData.size() > 0 )
        {
            for ( u32 i = 0; i < UrisData.size(); ++i )
            {
                if ( i == ( UrisData.size() - 1 ) )
                    Uris += UrisData.at( i )->text().toStdString();
                else
                    Uris += UrisData.at( i )->text().toStdString() + ", ";

                delete UrisData.at( i );
            }
        }

        ListenerInfo.insert( { "Hosts", Hosts } );
        ListenerInfo.insert( { "HostBind", ComboHostBind->currentText().toStdString() } );
        ListenerInfo.insert( { "HostRotation", ComboHostRotation->currentText().toStdString() } );
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
        if ( InputListenerName->text().isEmpty() )
        {
            Style.open( QIODevice::ReadOnly );

            MsgBox.setWindowTitle( "Listener Error" );
            MsgBox.setText( "No Listener Name specified" );
            MsgBox.setIcon( QMessageBox::Critical );
            MsgBox.setStyleSheet( Style.readAll() );
            MsgBox.exec();

            Style.close();
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

void HavocNamespace::UserInterface::Dialogs::NewListener::ctx_PayloadChange( const QString& text )
{
    if ( text.compare( HavocSpace::Listener::PayloadHTTPS ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 0 );
        InputPort->setText( "443" );
    }
    else if ( text.compare( HavocSpace::Listener::PayloadHTTP ) == 0 )
    {
        StackWidgetConfigPages->setCurrentIndex( 0 );
        InputPort->setText( "80" );
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