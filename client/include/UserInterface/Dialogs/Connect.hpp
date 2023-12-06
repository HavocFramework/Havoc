#ifndef HAVOC_CONNECTDIALOG_H
#define HAVOC_CONNECTDIALOG_H

#include <global.hpp>

#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QList>

using namespace std;

class HavocNamespace::UserInterface::Dialogs::Connect : public QDialog
{
private:
    QGridLayout*    gridLayout;

    QPlainTextEdit* plainTextEdit;
    QLabel*         label_Name;
    QLabel*         label_Host;
    QLabel*         label_Port;
    QLabel*         label_User;
    QLabel*         label_Password;

    QLineEdit*      lineEdit_User;
    QLineEdit*      lineEdit_Password;
    QLineEdit*      lineEdit_Host;
    QLineEdit*      lineEdit_Name;
    QLineEdit*      lineEdit_Port;

    QPushButton*    ButtonNewProfile;
    QPushButton*    ButtonConnect;

    QSpacerItem*    horizontalSpacer;
    QListWidget*    listWidget;
    QPalette*       paletteGray;
    QPalette*       paletteWhite;
    QMenu*          listContextMenu;

    HavocNamespace::HavocSpace::DBManager* dbManager;

public:
    vector<Util::ConnectionInfo> TeamserverList;
    QDialog*                     ConnectDialog  = nullptr;
    bool                         tryConnect     = false;
    bool                         isNewProfile   = false;
    bool                         FromAction     = false;

    void setupUi( QDialog* Form );
    Util::ConnectionInfo StartDialog( bool FromAction );
    void passDB( HavocNamespace::HavocSpace::DBManager* db );

private slots:
            void onButton_Connect();
    void onButton_NewProfile();

    void itemSelected();
    void handleContextMenu(const QPoint &pos);

    void itemRemove();
    void itemsClear();
};

#endif
