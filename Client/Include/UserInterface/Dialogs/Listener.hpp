
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
public:
    QGridLayout*    gridLayout;
    QGridLayout*    gridLayout_2;
    QGridLayout*    gridLayout_3;
    QGridLayout*    gridLayout_4;

    QWidget*        PageHTTP;
    QWidget*        PageSMB;
    QWidget*        PageExternal;

    QSpacerItem*    horizontalSpacer_3;
    QSpacerItem*    horizontalSpacer_2;
    QSpacerItem*    horizontalSpacer;
    QSpacerItem*    horizontalSpacer_5;
    QSpacerItem*    verticalSpacerHeader;
    QSpacerItem*    verticalSpacerUris;
    QSpacerItem*    horizontalSpacer_4;

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
    QLineEdit*      InputHost;

    QLabel*         LabelPort;
    QLineEdit*      InputPort;

    QLineEdit*      InputUserAgent;
    QLabel*         LabelUserAgent;

    QMenu*          CtxHeaders;
    QLabel*         LabelHeaders;
    QListWidget*    ListHeaders;

    QMenu*          CtxUris;
    QLabel*         LabelUris;
    QListWidget*    ListUris;

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

    // Page SMB
    QLabel*         LabelPipeName;
    QLineEdit*      InputPipeName;

    // Page External
    QLabel*         LabelEndpoint;
    QLineEdit*      InputEndpoint;
    QGroupBox*      BoxOptional;
    QLineEdit*      InputOptPassword;
    QLabel*         LabelOptPassword;
    QCheckBox*      CheckOptBindLocalHost;

public:
    QDialog* ListenerDialog;

    bool DialogClosed = false;
    bool DialogSaved = false;

    NewListener( QDialog *Dialog );
    map<string, string> Start() const;

protected slots:
    void onButton_Close();
    void onButton_Save();

    void onProxyEnabled();

    void ctx_PayloadChange( const QString& string );

    void ctx_handleHeaders( const QPoint &pos );
    void ctx_handleUris( const QPoint &pos );

    void ctx_itemHeadersAdd();
    void ctx_itemHeadersRemove();
    void ctx_itemHeadersClear();

    void ctx_itemUrisAdd();
    void ctx_itemUrisRemove();
    void ctx_itemUrisClear();

};

#endif
