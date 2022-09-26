#include <global.hpp>
#include <UserInterface/Dialogs/About.hpp>

About::About( QDialog* dialog )
{
    AboutDialog = dialog;

    if ( AboutDialog->objectName().isEmpty() )
        AboutDialog->setObjectName( QString::fromUtf8( "Dialogs" ) );

    AboutDialog->setWindowTitle("About");
    AboutDialog->resize(400, 323);

    gridLayout = new QGridLayout(AboutDialog);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));

    label = new QLabel( AboutDialog );
    label->setObjectName(QString::fromUtf8("label_Name"));
    label->setMinimumSize(QSize(196, 0));

    gridLayout->addWidget(label, 0, 0, 1, 3);

    pushButton = new QPushButton(AboutDialog);
    pushButton->setObjectName(QString::fromUtf8("pushButton_New_Profile"));
    gridLayout->addWidget(pushButton, 3, 2, 1, 1);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 2, 1, 1, 1);

    textBrowser = new QTextBrowser(AboutDialog);
    textBrowser->setObjectName(QString::fromUtf8("textBrowser"));

    gridLayout->addWidget(textBrowser, 1, 0, 1, 3);
    label->setText(QCoreApplication::translate("Dialogs", R"(<html><head/><body><p align="center"><span style=" font-size:22pt;">Havoc</span></p></body></html>)", nullptr));
    pushButton->setText(QCoreApplication::translate("Dialogs", "Close", nullptr));
    textBrowser->setHtml(QCoreApplication::translate("Dialogs", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                               "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                               "p, li { white-space: pre-wrap; }\n"
                                                               "</style></head><body style=\" font-family:'Sans Serif'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
                                                               "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-size:x-large; font-weight:600;\">About Havoc</span> </p>\n"
                                                               "<p align=\"center\" style=\" margin-top:12px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Welcome to Havoc. Havoc is a Software for Adversary Simulations and Red Team Operations by <a href=\"https://www.twitter.com/C5pider\"><span style=\" text-decoration: underline; color:#e100ff;\">5pider</span></a>. </p></body></html>", nullptr));

    QObject::connect( pushButton, &QPushButton::clicked, this, &About::onButtonClose );
    QMetaObject::connectSlotsByName( AboutDialog );
}

void About::setupUi()
{

}

void About::onButtonClose()
{
    AboutDialog->close();
}