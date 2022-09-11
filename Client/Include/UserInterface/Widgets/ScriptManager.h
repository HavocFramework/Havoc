#ifndef SCRIPTMANAGERVVJSUY_H
#define SCRIPTMANAGERVVJSUY_H

#include <global.hpp>

class HavocNamespace::UserInterface::Widgets::ScriptManager : public QWidget
{
public:
    QGridLayout  *gridLayout          = NULL;
    QPushButton  *buttonLoadScript    = NULL;
    QSpacerItem  *horizontalSpacer    = NULL;
    QSpacerItem  *horizontalSpacer_2  = NULL;
    QTableWidget *tableLoadedScripts  = NULL;
    QWidget      *ScriptManagerWidget = NULL;

    QMenu       *menuScripts          = NULL;
    QAction     *actionReload         = NULL;
    QAction     *actionRemove         = NULL;

    void SetupUi( QWidget *Form );
    void RetranslateUi( void );

    static void AddScript( QString Path );
    void AddScriptTable( QString Path );

private slots:
    void b_LoadScript();
    void menu_ScriptMenu( const QPoint &pos ) const;

    void ReloadScript() const;
    void RemoveScript() const;
};

#endif // SCRIPTMANAGERVVJSUY_H
