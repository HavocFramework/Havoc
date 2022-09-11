#ifndef HAVOC_TEAMSERVERTABSESSION_H
#define HAVOC_TEAMSERVERTABSESSION_H

#include <global.hpp>
#include <QStackedWidget>
#include <QSplitter>

#include <UserInterface/Widgets/LootWidget.h>
#include <UserInterface/Widgets/SessionGraph.hpp>
#include "Include/UserInterface/Dialogs/Payload.hpp"

using namespace HavocNamespace;

class HavocNamespace::UserInterface::Widgets::TeamserverTabSession : public QWidget
{
public:
    QGridLayout* gridLayout                             = nullptr;
    QGridLayout* gridLayout_2                           = nullptr;
    QGridLayout* gridLayout_3                           = nullptr;
    QWidget*     layoutWidget                           = nullptr;
    QSplitter*   splitter_TopBot                        = nullptr;
    QSplitter*   splitter_SessionAndTabs                = nullptr;
    QWidget*     widget                                 = nullptr;
    QVBoxLayout* verticalLayout                         = nullptr;
    QTabWidget*  tabWidget                              = nullptr;
    QTabWidget*  tabWidgetSmall                         = nullptr;

    QAction*     actionSeperator                        = nullptr;
    QAction*     actionSeperator1                       = nullptr;
    QAction*     actionSeperator2                       = nullptr;
    QAction*     actionSeperator3                       = nullptr;

    QMenu*       DemonContextMenu                       = nullptr;
    QAction*     SessionTableMenu_Interact              = nullptr;
    QMenu*       SessionTableMenu_Explore               = nullptr;
    QAction*     SessionTableMenu_Explore_ProcessList   = nullptr;
    QAction*     SessionTableMenu_Explore_FileExplorer  = nullptr;
    QAction*     SessionTableMenu_MarkAsDead            = nullptr;
    QAction*     SessionTableMenu_Export                = nullptr;
    QAction*     SessionTableMenu_Remove                = nullptr;
    QAction*     SessionTableMenu_Exit                  = nullptr;
    QAction*     SessionTableMenu_Info                  = nullptr;

    typedef struct
    {
        UserInterface::SmallWidgets::EventViewer* EventViewer;
    } SmallAppWidgets_t ;

public:
    Widgets::Chat*                      TeamserverChat          = nullptr;
    Widgets::SessionTable*              SessionTableWidget      = nullptr;
    GraphWidget*                        SessionGraphWidget      = nullptr;
    Widgets::ListenersTable*            ListenerTableWidget     = nullptr;
    Widgets::CredentialsTable*          CredentialsTableWidget  = nullptr;
    Widgets::PythonScriptInterpreter*   PythonScriptWidget      = nullptr;
    Widgets::ScriptManager*             ScriptManagerWidget     = nullptr;
    Payload*                            PayloadDialog           = nullptr;
    LootWidget*                         LootWidget              = nullptr;

    QStackedWidget*                     MainViewWidget          = nullptr;
    QWidget*                            SessionTablePage        = nullptr;
    HavocSpace::DBManager*              dbManager               = nullptr;

    QString                             TeamserverName          = "";
    QWidget*                            PageWidget              = nullptr;

    SmallAppWidgets_t*                  SmallAppWidgets         = nullptr;

    void setupUi( QWidget* Page, QString TeamserverName );
    void setDBManager( HavocSpace::DBManager* dbManager );

    void NewBottomTab( QWidget* TabWidget, const std::string& TitleName, const QString IconPath = "" ) const;
    void NewWidgetTab( QWidget* TabWidget, const std::string& TitleName ) const;

protected:
    bool event( QEvent* ) override;

protected slots:
    void handleDemonContextMenu(const QPoint& pos);
    void removeTab(int) const;
    void removeTabSmall(int) const;

    void Action_Menu_Interact() const;
    void Action_Menu_Explore_ProcessList() const;
    void ActionMenuExploreFileBrowser() const;

    void ActionMenuRemove() const;
    void ActionMenuMarkAsDead() const;
};

#endif
