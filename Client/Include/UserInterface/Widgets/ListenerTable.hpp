#include <global.hpp>
#include <QTableWidget>

#include <Havoc/DBManager/DBManager.hpp>
#include "Include/Havoc/Packager.hpp"

class HavocNamespace::UserInterface::Widgets::ListenersTable : public QWidget
{
private:
    QGridLayout *gridLayout;
    QPushButton *pushButton;
    QPushButton *pushButton_3;
    QPushButton *pushButton_4;
    QPushButton *pushButton_2;
    QSpacerItem *horizontalSpacer_2;
    QSpacerItem *horizontalSpacer;
    QTableWidget *tableWidget;
    HavocSpace::DBManager* dbManager;
    HavocSpace::Packager* Packager;

public:
    QString TeamserverName;
    QWidget* ListenerWidget;

    void setupUi( QWidget* widget );
    void ButtonsInit();
    void setDBManager( HavocSpace::DBManager* dbManager );
    Util::Packager::Package CreateNewPackage( int EventID, map<string,string> ) const;

    void ListenerAdd( Util::ListenerItem item ) const;
    void ListenerEdit( Util::ListenerItem item ) const;
    void ListenerMark( QString ListenerName, QString Mark ) const;
    void ListenerRemove( QString ListenerName ) const;
    void ListenerError( QString ListenerName, QString Error ) const;

private slots:
    void onButtonAdd() const;
    void onButtonRemove() const;
    void onButtonRestart() const;
    void onButtonEdit() const;
};