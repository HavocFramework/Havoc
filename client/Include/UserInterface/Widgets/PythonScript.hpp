
#ifndef HAVOC_PYTHONSCRIPTWIDGET_HPP
#define HAVOC_PYTHONSCRIPTWIDGET_HPP

#include <global.hpp>
#include <QPlainTextEdit>

#pragma push_macro("slots")
#undef slots
#include <Python.h>
#pragma pop_macro("slots")

class HavocNamespace::UserInterface::Widgets::PythonScriptInterpreter : public QWidget
{
public:
    QGridLayout*        gridLayout;
    QLineEdit*          PythonScriptInput;
    QPlainTextEdit*     PythonScriptOutput;

    QWidget*            PythonScriptInterpreterWidget;

    std::string         StdOut;

    void setupUi(QWidget *WindowWidget);
    void RunCode(QString code);
    void AppendOutput( QString output );

private slots:
    void AppendFromInput();
};
#endif
