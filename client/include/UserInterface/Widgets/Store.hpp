#ifndef HAVOC_STORE_HPP
#define HAVOC_STORE_HPP

#include <QtWidgets/QWidget>
#include <QSplitter>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLabel>
#include <QScrollArea>

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTreeWidget>

class Store
{
public:
    QWidget*            StoreWidget;
    QHBoxLayout*        horizontalLayout;
    QSplitter*          StoreSplitter;
    QTableWidget*       StoreTable;

    QTableWidgetItem    *labelTitle;
    QTableWidgetItem    *labelAuthor;
    QTableWidgetItem    *labelDescription;

    QWidget*            panelStore;
    QVBoxLayout*        panelLayout;

    QWidget*            root_panelStore;
    QVBoxLayout*        root_panelLayout;
    QScrollArea*        panelScroll;

    QLabel*             headerLabelTitle;
    QLabel*             panelLabelDescription;

    QGridLayout*    gridLayout;
    QTextEdit*      StoreLogger;

    void setupUi( QWidget* Store );
    void retranslateUi(  );
};

#endif
