#ifndef HAVOC_HAVOCUI_HPP
#define HAVOC_HAVOCUI_HPP

#include <global.hpp>

#include <UserInterface/Dialogs/About.hpp>
#include <UserInterface/Dialogs/Connect.hpp>
#include <UserInterface/Dialogs/Listener.hpp>
#include <UserInterface/Dialogs/Payload.hpp>
#include <UserInterface/Dialogs/Preferences.hpp>

#include <UserInterface/Widgets/SessionTable.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <UserInterface/Widgets/ListenerTable.hpp>
#include <UserInterface/Widgets/CredentialsTable.hpp>

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
    QAction* actionNew_Client;
    QAction* actionChat;
    QAction* actionPreferences;
    QAction* actionDisconnect;
    QAction* actionExit;
    QAction* actionTeamserver;
    QAction* actionGeneratePayload;
    QAction* actionLoad_Script;
    QAction* actionPythonConsole;
    QAction* actionAbout;
    QAction* actionOpen_Help_Documentation;
    QAction* actionOpen_API_Reference;
    QAction* actionGithub_Repository;
    QAction* actionListeners;
    QAction* actionSessionsTable;
    QAction* actionSessionsGraph;
    QAction* actionLogs;
    QAction* actionLoot;

    QWidget* centralwidget;

    QGridLayout* gridLayout;
    QGridLayout* gridLayout_3;
    QTabWidget*  TeamserverTabWidget;
    QMenuBar*    menubar;

    QMenu* menuHavoc;
    QMenu* menuView;
    QMenu* menuAttack;
    QMenu* menuScripts;
    QMenu* menuHelp;
    QMenu* MenuSession;

    QStatusBar *statusbar;

    Dialogs::Connect*     ConnectDialog = nullptr;
    About*                AboutDialog = nullptr;
    Dialogs::Preferences* PreferencesDialogs = nullptr;

    QMainWindow* HavocWindow;
    HavocSpace::DBManager* dbManager;

    QWidget* SessionView;

public:
    HavocNamespace::UserInterface::Widgets::SessionTable *SessionTable;

    void setupUi(QMainWindow *Havoc);
    void retranslateUi(QMainWindow *Havoc) const;
    void setDBManager(HavocSpace::DBManager* dbManager);

    void NewTeamserverTab( HavocNamespace::Util::ConnectionInfo* );
    void NewTeamserverTab( QString Name );

    void NewBottomTab(QWidget* TabWidget, const std::string& TitleName, const QString IconPath = "") const;
    void NewSmallTab(QWidget* TabWidget, const std::string& TitleName) const;

    void InitializeButtons() const;
    void InitShortCuts();

public slots:
    void removeTab(int) const; // TODO: <-- TEAMSERVER
    void tabSelected() const;

    // Menubar --> Havoc
    void onButton_Havoc_Client();
    void onButton_Havoc_Chat();
    void onButton_Havoc_Preferences();
    static void onButton_Havoc_Disconnect();
    void onButton_Havoc_Exit();

    // Menubar --> View
    void onButton_View_SessionsTable();
    void onButton_View_SessionsGraph();
    void onButton_View_Teamserver();
    void onButton_View_Listeners();
    void onButton_View_Logs();
    void onButtonViewLoot();

    // Menubar --> Attack
    void onButton_Attack_Payload();

    // Menubar --> Scripts
    void onButton_Scripts_Interpreter();
    void onButtonScriptsManager();

    // Menubar --> Help
    void onButton_Help_About();
    void onButton_Help_Github();
    void onButton_Help_Documentation();

    // ShortCuts
    void ApplicationScreenshot();

protected:
    bool event(QEvent*) override;

};

#endif