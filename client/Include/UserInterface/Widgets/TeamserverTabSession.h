#ifndef HAVOC_TEAMSERVERTABSESSION_H
#define HAVOC_TEAMSERVERTABSESSION_H

#include <global.hpp>
#include <QStackedWidget>
#include <QSplitter>

#include <UserInterface/Widgets/LootWidget.h>
#include <UserInterface/Widgets/SessionGraph.hpp>
#include <UserInterface/Widgets/Teamserver.hpp>

#include <UserInterface/Dialogs/Payload.hpp>

using namespace HavocNamespace;

class HavocNamespace::UserInterface::Widgets::TeamserverTabSession : public QWidget
{
    typedef struct
    {
        UserInterface::SmallWidgets::EventViewer* EventViewer;
    } SmallAppWidgets_t;

public:
    QGridLayout* gridLayout              = {};
    QGridLayout* gridLayout_2            = {};
    QWidget*     layoutWidget            = {};
    QSplitter*   splitter_TopBot         = {};
    QSplitter*   splitter_SessionAndTabs = {};
    QVBoxLayout* verticalLayout          = {};
    QTabWidget*  tabWidget               = {};
    QTabWidget*  tabWidgetSmall          = {};

public:
    Widgets::Chat*                    TeamserverChat      = {};
    Teamserver*                       Teamserver          = {};
    Widgets::SessionTable*            SessionTableWidget  = {};
    GraphWidget*                      SessionGraphWidget  = {};
    Widgets::ListenersTable*          ListenerTableWidget = {};
    Widgets::PythonScriptInterpreter* PythonScriptWidget  = {};
    Widgets::ScriptManager*           ScriptManagerWidget = {};
    Payload*                          PayloadDialog       = {};
    LootWidget*                       LootWidget          = {};
    QStackedWidget*                   MainViewWidget      = {};
    QWidget*                          SessionTablePage    = {};
    HavocSpace::DBManager*            dbManager           = {};
    QString                           TeamserverName      = {};
    QWidget*                          PageWidget          = {};
    SmallAppWidgets_t*                SmallAppWidgets     = {};

    void setupUi( QWidget* Page, QString TeamserverName );
    void NewBottomTab( QWidget* TabWidget, const std::string& TitleName, QString IconPath = "" ) const;
    void NewWidgetTab( QWidget* TabWidget, const std::string& TitleName ) const;

protected slots:
    void handleDemonContextMenu( const QPoint& pos );
    void removeTabSmall( int ) const;
};

#endif
