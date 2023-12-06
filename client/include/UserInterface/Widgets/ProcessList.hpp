#ifndef HAVOC_PROCESSLIST_HPP
#define HAVOC_PROCESSLIST_HPP

#include <global.hpp>

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QWidget>

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

class HavocNamespace::UserInterface::Widgets::ProcessList : public QWidget {
private:
    QGridLayout *gridLayout;
    QSplitter   *splitter;
    QTreeWidget *ProcessTree;
    QTableWidget *ProcessTable;
    QSpacerItem *horizontalSpacer;
    QPushButton *pushButton_Refresh;
    QPushButton *pushButton_Kill;
    QPushButton *pushButton_Steal_Token;
    QPushButton *pushButton_Inject;
    QSpacerItem *horizontalSpacer_2;

    QMenu       *ProcessListMenu;
    QAction     *actionCopyProcessID;
    QAction     *actionSetAsParentProcess;

public:
    Util::SessionItem Session;
    QWidget* ProcessListWidget;
    QString Teamserver;

    void setupUi(QWidget* Widget);
    void UpdateProcessListJson(QJsonDocument ProcessListData);
    void NewTableProcess(std::map<QString, QString> ProcessInfo);
    void NewTreeProcess(std::map<QString, QString> ProcessInfo);

private slots:
    void onButton_Refresh() const;

    void onTableChange();
    void onTreeChange();

    void handleTableListMenuContext(const QPoint &pos);
    void handleTreeListMenuContext(const QPoint &pos);

    void onActionCopyPID();
    void onActionSetParentProcess();
};

#endif
