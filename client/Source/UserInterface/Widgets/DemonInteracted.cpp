#include <global.hpp>
#include <UserInterface/Widgets/DemonInteracted.h>
#include <Util/ColorText.h>

#include <QDate>
#include <QTime>
#include <QCompleter>
#include <QKeyEvent>
#include <QEvent>
#include <QStringListModel>
#include <QScrollBar>

using namespace HavocNamespace::UserInterface::Widgets;
using namespace HavocNamespace::Util;

DemonInteracted::DemonInput::DemonInput( QWidget* parent ) : QLineEdit( parent )
{
    CommandHistoryIndex = 0;
}

bool DemonInteracted::DemonInput::handleKeyPress( QKeyEvent* eventKey )
{
    switch (eventKey->key())
    {
    case Qt::Key_Tab:
        handleTabKey();
        return true;
    case Qt::Key_Up:
        handleUpKey();
        return true;
    case Qt::Key_Down:
        handleDownKey();
        return true;
    default:
        return false;
    }
}

void DemonInteracted::DemonInput::handleTabKey()
{
    auto CompletedString = completer()->currentCompletion();
    if ( ! CompletedString.isEmpty() ) {
        setText( CompletedString );
    }
}

void DemonInteracted::DemonInput::handleUpKey()
{
    if ( CommandHistoryIndex == 0 )  {
        setText( "" );
        return;
    }

    CommandHistoryIndex--;

    if ( CommandHistoryIndex >= 1 ) {
        setText( CommandHistory.at( CommandHistoryIndex ) );
    } else {
        if ( ! CommandHistory.empty() ) {
            setText( CommandHistory.at( CommandHistoryIndex ) );
        } else {
            setText( "" );
        }
    }
}

void DemonInteracted::DemonInput::handleDownKey()
{
    if (CommandHistoryIndex < CommandHistory.size())
    {
        CommandHistoryIndex++;
        setText(CommandHistory.at(CommandHistoryIndex - 1));
    }
    else
        setText("");
}

bool DemonInteracted::DemonInput::event( QEvent* e )
{
    if ( e->type() == e->KeyPress ) {
        auto eventKey = dynamic_cast<QKeyEvent*>( e );
        if ( handleKeyPress( eventKey ) ) {
            return true;
        }
    }

    return QLineEdit::event( e );
}

void DemonInteracted::DemonInput::AddCommand( const QString &Command )
{
    CommandHistory << Command;
}

void DemonInteracted::setupUi( QWidget *Form )
{
    this->DemonInteractedWidget = Form;

    if ( Form->objectName().isEmpty() ) {
        Form->setObjectName( QString::fromUtf8( "Form" ) );
    }

    Form->resize( 932, 536 );
    gridLayout = new QGridLayout( Form );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );
    gridLayout->setVerticalSpacing( 4 );
    gridLayout->setContentsMargins( 1, 4, 1, 4 );

    label = new QLabel( Form );
    label->setObjectName( QString::fromUtf8( "label" ) );

    gridLayout->addWidget( label, 3, 0, 1, 1 );

    lineEdit = new DemonInput( Form );
    lineEdit->setObjectName( QString::fromUtf8( "lineEdit" ) );

    gridLayout->addWidget( lineEdit, 3, 1, 1, 1 );

    Console = new QTextEdit(Form);
    Console->setObjectName(QString::fromUtf8("Console"));
    Console->setReadOnly(true);
    Console->setLineWrapMode( QTextEdit::LineWrapMode::NoWrap );
    Console->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
            );

    gridLayout->addWidget(Console, 0, 0, 1, 2);

    label_2 = new QLabel(Form);
    label_2->setObjectName(QString::fromUtf8("label_2"));
    label_2->setTextInteractionFlags(Qt::TextSelectableByMouse);

    gridLayout->addWidget(label_2, 2, 0, 1, 2);

    Form->setWindowTitle(QCoreApplication::translate("Form", "Form", nullptr));
    lineEdit->setText(QString());

    label->setText(QCoreApplication::translate("Form", ">>>", nullptr));
    label->setStyleSheet("padding-bottom: 3px;"
                         "padding-left: 5px;");

    if ( SessionInfo.MagicValue == DemonMagicValue )
    {
        for ( auto& i : HavocSpace::DemonCommands::DemonCommandList )
        {
            CompleterCommands << i.CommandString;

            if ( i.CommandString == "help" )
            {
                for ( auto & j : HavocSpace::DemonCommands::DemonCommandList )
                {
                    if ( j.CommandString == "help" )
                        continue;

                    CompleterCommands << "help " + j.CommandString;

                    if ( ! j.SubCommands.empty() )
                    {
                        for ( auto &subcommand: j.SubCommands )
                            CompleterCommands << "help " + j.CommandString + " " + subcommand.CommandString;
                    }
                }
            }

            if ( ! i.SubCommands.empty() )
            {
                for ( auto& subcommand : i.SubCommands )
                    CompleterCommands << i.CommandString + " " + subcommand.CommandString;
            }
        }

        for ( auto& Command : HavocX::Teamserver.AddedCommands )
        {
            CompleterCommands << "help " + Command;
            CompleterCommands << Command;
        }
    }
    else
    {
        // 3rd party agent...
    }

    CommandCompleter = new QCompleter( CompleterCommands, this );
    CommandCompleter->setCaseSensitivity( Qt::CaseInsensitive );
    CommandCompleter->setCompletionMode( QCompleter::InlineCompletion );

    lineEdit->setCompleter( CommandCompleter );


    if ( this->SessionInfo.Domain.compare( "" ) == 0 )
    {
        label_2->setText( "[" + this->SessionInfo.User + "/" + this->SessionInfo.Computer + "] " + this->SessionInfo.Process + "/" + this->SessionInfo.PID + " " + this->SessionInfo.Arch );
    } else {
        label_2->setText( "[" + this->SessionInfo.User + "/" + this->SessionInfo.Computer + "] " + this->SessionInfo.Process + "/" + this->SessionInfo.PID + " " + this->SessionInfo.Arch + " ("+ this->SessionInfo.Domain + ")" );
    }

    DemonCommands = new HavocSpace::DemonCommands;
    DemonCommands->Teamserver = this->TeamserverName;
    DemonCommands->DemonID    = this->SessionInfo.Name;
    DemonCommands->MagicValue = this->SessionInfo.MagicValue;
    DemonCommands->SetDemonConsole( this );

    connect( lineEdit, &QLineEdit::returnPressed, this, &DemonInteracted::AppendFromInput );

    QMetaObject::connectSlotsByName( Form );
}

void DemonInteracted::AppendFromInput()
{
    AppendText( this->lineEdit->text() );
}

void DemonInteracted::AppendText( const QString& text )
{
    if ( SessionInfo.MagicValue != DemonMagicValue )
    {
        for ( auto& agent : HavocX::Teamserver.ServiceAgents )
        {
            if ( SessionInfo.MagicValue == agent.MagicValue )
                AgentTypeName = agent.Name;
        }
    }

    if ( AgentTypeName.isEmpty() ) {
        AgentTypeName = "Demon";
    }

    DemonCommands->Prompt = QString(
        ColorText::Comment( QDate::currentDate().toString( "dd/MM/yyyy" ) + " "+ QTime::currentTime().toString( "hh:mm:ss" ) +
        " [" + HavocX::Teamserver.User + "] " ) +
        ColorText::UnderlinePink( AgentTypeName ) + ColorText::Cyan(" » ") + text
    );

    if ( ! text.isEmpty() )
    {
        lineEdit->CommandHistory << text;
        lineEdit->CommandHistoryIndex = lineEdit->CommandHistory.size();

        /* check if registered a command called help. if yes then exclude this. */
        auto AgentData   = ServiceAgent();
        auto HelpCommand = false;

        if ( DemonCommands->MagicValue != DemonMagicValue )
        {
            for ( auto& agent : HavocX::Teamserver.ServiceAgents )
            {
                if ( DemonCommands->MagicValue == agent.MagicValue )
                {
                    AgentData = agent;
                    AgentTypeName = agent.Name;
                }
            }
        }

        for ( auto & command : AgentData.Commands )
        {
            if ( command.Name == "help" )
            {
                HelpCommand = true;
                break;
            }
        }

        if ( ! HelpCommand )
        {
            if ( text.split( " " )[ 0 ].compare( "help" ) == 0 )
            {
                AppendRaw();
                AppendRaw( DemonCommands->Prompt );
            }
        }

        DemonCommands->DispatchCommand( true, "", text );

        Console->verticalScrollBar()->setValue( Console->verticalScrollBar()->maximum() );
    }

    this->lineEdit->clear();
}

QString DemonInteracted::TaskInfo( bool Show, QString TaskID, const QString &text ) const
{
    if ( TaskID == nullptr ) {
        TaskID = Util::gen_random( 8 ).c_str();
    }

    if ( ! Show )
    {
        auto TaskMessage = Util::ColorText::Cyan( "[*]" ) + " "+ Util::ColorText::Comment( "[" + TaskID + "]" ) + " " + Util::ColorText::Cyan( text.toHtmlEscaped() );
        this->Console->append( TaskMessage );
    }

    return TaskID;
}

QString DemonInteracted::TaskError( const QString &text ) const
{
    auto TaskMessage = Util::ColorText::Red( "[!]" ) + " " + text.toHtmlEscaped();
    this->Console->append( TaskMessage );
    return TaskMessage;
}

void UserInterface::Widgets::DemonInteracted::AppendRaw(const QString& text)
{
    this->Console->append( text );
}

void DemonInteracted::AppendNoNL( const QString &text )
{
    QTextCursor prev_cursor = this->Console->textCursor();

    this->Console->moveCursor( QTextCursor::End );
    this->Console->insertHtml( text );
    this->Console->setTextCursor( prev_cursor );
}

void DemonInteracted::AutoCompleteAdd( QString text )
{
    /*auto model = ( QStringListModel* ) CommandCompleter->model();

    CompleterCommands << text;
    model->setStringList( CompleterCommands );
    CommandCompleter->setModel( model );*/
}

void DemonInteracted::AutoCompleteClear()
{
    auto model = ( QStringListModel* ) CommandCompleter->model();
    auto list  = QStringList();

    model->setStringList( list );

    CommandCompleter->setModel( model );
}

void DemonInteracted::AutoCompleteAddList( QStringList list )
{
    auto model = ( QStringListModel* ) CommandCompleter->model();

    model->setStringList( list );

    CommandCompleter->setModel( model );
}
