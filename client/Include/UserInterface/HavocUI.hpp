#ifndef HAVOC_HAVOCUI_HPP
#define HAVOC_HAVOCUI_HPP

#include <global.hpp>

#include <UserInterface/Dialogs/About.hpp>
#include <UserInterface/Dialogs/Connect.hpp>
#include <UserInterface/Dialogs/Listener.hpp>
#include <UserInterface/Dialogs/Payload.hpp>

#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <UserInterface/Widgets/ListenerTable.hpp>

#include <Havoc/DBManager/DBManager.hpp>

// QT libraries
#include <QDesktopServices>
#include <QShortcut>
#include <QStatusBar>
#include <QDockWidget>
#include <QHeaderView>
#include <QSplitter>
#include <QTableWidget>
#include <QFile>
#include <QStackedWidget>

class HavocNamespace::UserInterface::HavocUI : public QMainWindow
{
public:
    QWidget*               centralwidget                 = {};
    QAction*               actionNew_Client              = {};
    QAction*               actionChat                    = {};
    QAction*               actionPreferences             = {};
    QAction*               actionDisconnect              = {};
    QAction*               actionExit                    = {};
    QAction*               actionTeamserver              = {};
    QAction*               actionGeneratePayload         = {};
    QAction*               actionLoad_Script             = {};
    QAction*               actionPythonConsole           = {};
    QAction*               actionAbout                   = {};
    QAction*               actionOpen_Help_Documentation = {};
    QAction*               actionOpen_API_Reference      = {};
    QAction*               actionGithub_Repository       = {};
    QAction*               actionListeners               = {};
    QAction*               actionSessionsTable           = {};
    QAction*               actionSessionsGraph           = {};
    QAction*               actionLogs                    = {};
    QAction*               actionLoot                    = {};
    QGridLayout*           gridLayout                    = {};
    QGridLayout*           gridLayout_3                  = {};
    QTabWidget*            TeamserverTabWidget           = {};
    QMenuBar*              menubar                       = {};
    QMenu*                 menuHavoc                     = {};
    QMenu*                 menuView                      = {};
    QMenu*                 menuAttack                    = {};
    QMenu*                 menuScripts                   = {};
    QMenu*                 menuHelp                      = {};
    QMenu*                 MenuSession                   = {};
    QStatusBar*            statusbar                     = {};
    Dialogs::Connect*      ConnectDialog                 = {};
    About*                 AboutDialog                   = {};
    QMainWindow*           HavocWindow                   = {};
    HavocSpace::DBManager* dbManager                     = {};

public:
    void MarkSessionAs( HavocNamespace::Util::SessionItem session, QString Mark );
    void UpdateSessionsHealth();
    void setupUi( QMainWindow *Havoc );
    void retranslateUi( QMainWindow *Havoc ) const;
    void setDBManager( HavocSpace::DBManager* dbManager );
    void NewTeamserverTab( HavocNamespace::Util::ConnectionInfo* );
    void NewTeamserverTab( QString Name );
    void NewBottomTab( QWidget* TabWidget, const std::string& TitleName, const QString IconPath = "" ) const;
    void NewSmallTab( QWidget* TabWidget, const std::string& TitleName ) const;
    void ConnectEvents();
    void PythonPrepare();

public slots:
    void OneSecondTick();
};

#endif