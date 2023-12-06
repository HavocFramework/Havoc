
#ifndef HAVOC_LISTENER_HPP
#define HAVOC_LISTENER_HPP

#include <global.hpp>

#include <QLineEdit>
#include <QGroupBox>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QWidget>

using namespace std;

class HavocNamespace::UserInterface::Dialogs::NewListener : public QDialog
{
    typedef struct {
        int         Id;
        QLineEdit*  Input;
    } Data;

    typedef struct {
        std::string  Name;
        QWidget*     Page;
        QFormLayout* Layout;
        int          Index;
        json         Items;
    } ServiceListener;

    std::vector<ServiceListener> ServiceListeners;

public:
    QGridLayout*    gridLayout;
    QGridLayout*    gridLayout_2;
    QGridLayout*    gridLayout_3;
    QGridLayout*    gridLayout_4;

    QWidget*        PageHTTP;
    QWidget*        PageSMB;
    QWidget*        PageExternal;

    QSpacerItem*    horizontalSpacer_2;
    QSpacerItem*    horizontalSpacer_3;
    QSpacerItem*    horizontalSpacer_4;
    QSpacerItem*    horizontalSpacer_5;
    QSpacerItem*    horizontalSpacer_6;
    QSpacerItem*    horizontalSpacer;
    QSpacerItem*    verticalSpacerHeader;
    QSpacerItem*    verticalSpacerUris;

    QLabel*         LabelListenerName;
    QLineEdit*      InputListenerName;
    QLabel*         LabelPayload;
    QComboBox*      ComboPayload;

    QPushButton*    ButtonClose;
    QPushButton*    ButtonSave;

    QGroupBox*      ConfigBox;
    QStackedWidget* StackWidgetConfigPages;

    // Page HTTP

    QLabel*         LabelHosts;
    QGroupBox*      HostsGroup;
    QPushButton*    ButtonHostsGroupAdd;
    QPushButton*    ButtonHostsGroupClear;
    std::vector<QLineEdit*> HostsData;
    QSpacerItem*    verticalSpacer;
    QFormLayout*    formLayout_Hosts;

    QLabel*         LabelHostRotation;
    QComboBox*      ComboHostRotation;

    QLabel*         LabelHostBind;
    QComboBox*      ComboHostBind;

    QLabel*         LabelPortBind;
    QLineEdit*      InputPortBind;

    QLabel*         LabelPortConn;
    QLineEdit*      InputPortConn;

    QLineEdit*      InputUserAgent;
    QLabel*         LabelUserAgent;

    QLabel*         LabelHeaders;
    QGroupBox*      HeadersGroup;
    QPushButton*    ButtonHeaderGroupAdd;
    QPushButton*    ButtonHeaderGroupClear;
    std::vector<QLineEdit*> HeadersData;

    QLabel*         LabelUris;
    QGroupBox*      UrisGroup;
    QPushButton*    ButtonUriGroupAdd;
    QPushButton*    ButtonUriGroupClear;
    std::vector<QLineEdit*> UrisData;

    QLineEdit*      InputHostHeader;
    QLabel*         LabelHostHeader;

    QCheckBox*      CheckEnableProxy;
    QGroupBox*      ProxyConfigBox;
    QLabel*         LabelProxyType;
    QComboBox*      ComboProxyType;
    QLabel*         LabelProxyHost;
    QLineEdit*      InputProxyHost;
    QLabel*         LabelProxyPort;
    QLineEdit*      InputProxyPort;
    QLabel*         LabelUserName;
    QLineEdit*      InputUserName;
    QLabel*         LabelPassword;
    QLineEdit*      InputPassword;

    QFormLayout*    formLayout;
    QFormLayout*    formLayout_2;
    QFormLayout*    formLayout_3;
    QFormLayout*    formLayout_Header;
    QFormLayout*    formLayout_Uri;

    // Page SMB
    QLabel*         LabelPipeName;
    QLineEdit*      InputPipeName;

    // Page External
    QLabel*         LabelEndpoint;
    QLineEdit*      InputEndpoint;

public:
    QDialog* ListenerDialog;

    bool DialogClosed = false;
    bool DialogSaved = false;

    NewListener( QDialog *Dialog );

    MapStrStr Start( Util::ListenerItem Item, bool Edit );

    auto ListenerCustomAdd( QString Listener ) -> bool;
    auto Free() -> void;

protected slots:
    void onButton_Save();

    void onProxyEnabled();
};

#endif
