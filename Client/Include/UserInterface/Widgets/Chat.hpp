#ifndef HAVOC_CHATWIDGET_H
#define HAVOC_CHATWIDGET_H

#include <global.hpp>
#include <QLineEdit>
#include <QTextEdit>

class HavocNamespace::UserInterface::Widgets::Chat : public QWidget
{
    QGridLayout*    gridLayout      = nullptr;
    QLineEdit*      lineEdit        = nullptr;

public:
    QTextEdit*      EventLogText    = nullptr;
    QWidget*        ChatWidget      = nullptr;
    QString         TeamserverName  = nullptr;

    void setupUi( QWidget* widget );
    void AppendText( const QString& Time, const QString& text ) const;

    void AddUserMessage( const QString Time, QString User, QString text ) const;

public slots:
    void AppendFromInput();

};

#endif
