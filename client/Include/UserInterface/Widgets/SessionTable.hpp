#ifndef HAVOC_SESSIONTABLE_HPP
#define HAVOC_SESSIONTABLE_HPP

#include <global.hpp>
#include <QTableWidget>

class HavocNamespace::UserInterface::Widgets::SessionTable : public QWidget
{
private:
    QGridLayout*        gridLayout       = nullptr;
    QString             TeamserverName   = nullptr;

    QTableWidgetItem*   TitleAgentID     = nullptr;
    QTableWidgetItem*   TitleInternal    = nullptr;
    QTableWidgetItem*   TitleExternal    = nullptr;
    QTableWidgetItem*   TitleUser        = nullptr;
    QTableWidgetItem*   TitleComputer    = nullptr;
    QTableWidgetItem*   TitleOperating   = nullptr;
    QTableWidgetItem*   TitleProcess     = nullptr;
    QTableWidgetItem*   TitleProcessId   = nullptr;
    QTableWidgetItem*   TitleArch        = nullptr;
    QTableWidgetItem*   TitleLast        = nullptr;
    QTableWidgetItem*   TitleHealth      = nullptr;

public:
    QTableWidget*   SessionTableWidget = nullptr;

    void setupUi( QWidget* widget, QString TeamserverName );
    void NewSessionItem( Util::SessionItem item ) const;
    void RemoveSession( Util::SessionItem session );
    void ChangeSessionValue( QString DemonID, int key, QString value );
    void updateRow();
};

#endif
