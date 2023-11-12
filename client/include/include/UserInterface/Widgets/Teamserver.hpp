#ifndef HAVOC_TEAMSERVER_HPP
#define HAVOC_TEAMSERVER_HPP

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

class Teamserver
{
public:
    QGridLayout*    gridLayout;
    QWidget*        TeamserverWidget;
    QTextEdit*      TeamserverLogger;

    void setupUi( QWidget* Teamserver );
    void retranslateUi(  );

    void AddLoggerText( const QString& Text ) const;
};

#endif
