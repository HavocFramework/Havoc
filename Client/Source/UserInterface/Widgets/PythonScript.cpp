#include <UserInterface/Widgets/PythonScript.hpp>
#include <Util/ColorText.h>
#include <QThread>
#include <thread>
#include <QTime>
#include <Havoc/PythonApi/PythonApi.h>


void HavocNamespace::UserInterface::Widgets::PythonScriptInterpreter::setupUi(QWidget *WindowWidget)
{
    PythonScriptInterpreterWidget = WindowWidget;

    if (PythonScriptInterpreterWidget->objectName().isEmpty())
        PythonScriptInterpreterWidget->setObjectName(QString::fromUtf8("PythonScriptWidget"));

    PythonScriptInterpreterWidget->setWindowTitle(QCoreApplication::translate("PythonScriptWidget", "Script Interpreter", nullptr));

    gridLayout = new QGridLayout(PythonScriptInterpreterWidget);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setContentsMargins(4, 4, 4, 4);
    gridLayout->setVerticalSpacing(4);

    PythonScriptInput = new QLineEdit(PythonScriptInterpreterWidget);
    PythonScriptInput->setObjectName(QString::fromUtf8("PythonScriptInput"));

    gridLayout->addWidget(PythonScriptInput, 1, 0, 1, 1);

    PythonScriptOutput = new QPlainTextEdit(PythonScriptInterpreterWidget);
    PythonScriptOutput->setObjectName(QString::fromUtf8("PythonScriptOutput"));
    PythonScriptOutput->setReadOnly(true);
    PythonScriptOutput->setLineWrapMode(QPlainTextEdit::LineWrapMode::NoWrap);
    PythonScriptOutput->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
    );

    gridLayout->addWidget(PythonScriptOutput, 0, 0, 1, 1);

    connect( PythonScriptInput, &QLineEdit::returnPressed, this, &PythonScriptInterpreter::AppendFromInput );

    PythonScriptOutput->appendHtml( ( "Python " + QString( Py_GetVersion() ) ) );
    PythonScriptOutput->appendHtml( ( R"(Type "help", "copyright", "credits" or "license" for more information.)" ) );
    PythonScriptOutput->appendPlainText("");

    QMetaObject::connectSlotsByName( PythonScriptInterpreterWidget );
}

void HavocNamespace::UserInterface::Widgets::PythonScriptInterpreter::RunCode( QString code )
{
    std::string buffer;
    emb::stdout_write_type write = [&] (std::string s) { buffer += s; };
    emb::set_stdout(write);

    PyRun_SimpleStringFlags( code.toStdString().c_str(), NULL );

    if ( buffer.size() > 0 )
        this->PythonScriptOutput->appendPlainText( buffer.c_str() );
}

void HavocNamespace::UserInterface::Widgets::PythonScriptInterpreter::AppendFromInput()
{
    QString Input = PythonScriptInput->text();

    if ( ! Input.isEmpty() )
    {
        PythonScriptOutput->appendHtml( Util::ColorText::Red( ">>>" ) + " " + Input.toHtmlEscaped() );
        PythonScriptInput->clear();
        RunCode( Input );
    }
}

void HavocNamespace::UserInterface::Widgets::PythonScriptInterpreter::AppendOutput( QString output )
{
    PythonScriptOutput->appendPlainText( output );
}