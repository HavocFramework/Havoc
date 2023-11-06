#include <global.hpp>
#include <UserInterface/Widgets/Chat.hpp>
#include <Util/ColorText.h>
#include <QtCore>
#include <QCompleter>
#include <QAbstractItemModel>

#include <Havoc/Packager.hpp>
#include <Havoc/Connector.hpp>

void HavocNamespace::UserInterface::Widgets::Chat::setupUi( QWidget *Form )
{
    ChatWidget = Form;

    if ( Form->objectName().isEmpty() ) {
        Form->setObjectName(QString::fromUtf8("Form"));
    }

    Form->resize( 932, 536 );

    gridLayout = new QGridLayout(Form);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setVerticalSpacing(4);
    gridLayout->setContentsMargins(1, 4, 1, 4);
    lineEdit = new QLineEdit(Form);
    lineEdit->setObjectName(QString::fromUtf8("lineEdit"));

    gridLayout->addWidget(lineEdit, 2, 1, 1, 1);

    auto label = new QLabel(Form);
    label->setObjectName(QString::fromUtf8("label"));

    gridLayout->addWidget(label, 2, 0, 1, 1);

    EventLogText = new QTextEdit(Form);
    EventLogText->setObjectName(QString::fromUtf8("EventLogText"));
    EventLogText->setReadOnly(true);
    EventLogText->setLineWrapMode(QTextEdit::LineWrapMode::NoWrap);

    gridLayout->addWidget(EventLogText, 0, 0, 1, 2);

    Form->setWindowTitle(QCoreApplication::translate("Form", "Form", nullptr));
    lineEdit->setText(QString());

    label->setStyleSheet("padding-bottom: 3px; padding-left: 5px;");

    lineEdit->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
            );

    EventLogText->setStyleSheet(
            "background-color: "+Util::ColorText::Colors::Hex::Background+";"
            + "color: "+Util::ColorText::Colors::Hex::Foreground+";"
            );

    label->setText( HavocX::Teamserver.User );
    connect( lineEdit, &QLineEdit::returnPressed, this, &Chat::AppendFromInput );

    QMetaObject::connectSlotsByName(Form);
}

void HavocNamespace::UserInterface::Widgets::Chat::AppendText(const QString& Time, const QString& text) const
{
    QString t = Util::ColorText::Comment(Time) +" "+ text;

    EventLogText->append( t );
}

void HavocNamespace::UserInterface::Widgets::Chat::AddUserMessage(const QString Time, QString User, QString text) const
{
    if ( HavocX::Teamserver.User.compare( User ) == 0 )
        this->AppendText( Time, "[" + Util::ColorText::UnderlineGreen( User ) + "]" + Util::ColorText::Bold(" :: ") + text );
    else
        this->AppendText( Time, "[" + Util::ColorText::Underline( User ) + "]" + Util::ColorText::Bold(" :: ") + text );
}

void HavocNamespace::UserInterface::Widgets::Chat::AppendFromInput()
{
    auto text = this->lineEdit->text();

    if ( ! text.isEmpty() )
    {
        Util::Packager::Package Package;

        Util::Packager::Head_t Head;
        Util::Packager::Body_t Body;

        auto User = HavocX::Teamserver.User.toStdString();

        Head.Event        = Util::Packager::Chat::Type;
        Head.Time         = QTime::currentTime().toString("hh:mm:ss").toStdString();
        Head.User         = User;
        Body.SubEvent     = Util::Packager::Chat::NewMessage;
        Body.Info[ User ] = text.toHtmlEscaped().toUtf8().toBase64().toStdString();

        Package.Head = Head;
        Package.Body = Body;

        HavocX::Connector->SendPackage( &Package );
    }

    this->lineEdit->clear();
}
