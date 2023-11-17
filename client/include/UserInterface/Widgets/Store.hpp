#ifndef HAVOC_STORE_HPP
#define HAVOC_STORE_HPP

#include <QtWidgets/QWidget>
#include <QSplitter>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLabel>
#include <QScrollArea>
#include <QDir>

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

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QJsonArray>

class Store
{
public:
    QWidget*            StoreWidget;
    QHBoxLayout*        horizontalLayout;
    QSplitter*          StoreSplitter;
    QTableWidget*       StoreTable;

    QTableWidgetItem    *labelTitle;
    QTableWidgetItem    *labelAuthor;

    QWidget*            panelStore;
    QVBoxLayout*        panelLayout;

    QWidget*            root_panelStore;
    QVBoxLayout*        root_panelLayout;
    QScrollArea*        panelScroll;
    QJsonArray*         dataStore;

    QLabel*             headerLabelTitle;
    QLabel*             panelLabelDescription;
    QLabel*             panelLabelAuthor;
    QPushButton*        installButton;

    QGridLayout*    gridLayout;
    QTextEdit*      StoreLogger;

    void setupUi( QWidget* Store );
    void displayData( int position );
    void installScript( int position );
    bool AddScript( QString Path );
    void retranslateUi(  );
};

#endif
