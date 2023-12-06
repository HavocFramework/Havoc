#include <UserInterface/SmallWidgets/EventViewer.hpp>
#include <Util/ColorText.h>

void HavocNamespace::UserInterface::SmallWidgets::EventViewer::setupUi(QWidget *Widget) {
    this->EventViewer = Widget;

    if (Widget->objectName().isEmpty())
        Widget->setObjectName(QString::fromUtf8("EventViewerWidget"));

    gridLayout = new QGridLayout(Widget);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    gridLayout->setContentsMargins(4, 4, 4, 4);

    EventViewerConsole = new QTextEdit(Widget);
    EventViewerConsole->setObjectName(QString::fromUtf8("EventViewer"));
    EventViewerConsole->setReadOnly(true);

    gridLayout->addWidget(EventViewerConsole, 0, 0, 1, 1);

    QMetaObject::connectSlotsByName(Widget);
}

void HavocNamespace::UserInterface::SmallWidgets::EventViewer::AppendText(const QString& Time, const QString& text) const {
    QString t = Util::ColorText::Comment(Time) + " " + text;
    EventViewerConsole->append(t);
}