#ifndef HAVOC_STORE_HPP
#define HAVOC_STORE_HPP

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
#include <QtWidgets/QWidget>

class Store
{
public:
    QGridLayout*    gridLayout;
    QWidget*        StoreWidget;
    QTextEdit*      StoreLogger;

    void setupUi( QWidget* Store );
    void retranslateUi(  );

    void AddLoggerText( const QString& Text ) const;
};

#endif
