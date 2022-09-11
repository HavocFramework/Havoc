#include <global.hpp>
#include <UserInterface/Widgets/CredentialsTable.hpp>

using namespace std;

void HavocNamespace::UserInterface::Widgets::CredentialsTable::setupUi(QWidget *widget)
{
    CredentialsTable = widget;

    if (CredentialsTable->objectName().isEmpty())
        CredentialsTable->setObjectName(QString::fromUtf8("CredentialsTable"));

    gridLayout = new QGridLayout(CredentialsTable);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));

    pushButton_Copy = new QPushButton(CredentialsTable);
    pushButton_Copy->setObjectName(QString::fromUtf8("pushButton_Close"));

    gridLayout->addWidget(pushButton_Copy, 1, 2, 1, 1);

    pushButton_Add = new QPushButton(CredentialsTable);
    pushButton_Add->setObjectName(QString::fromUtf8("pushButton_New_Profile"));

    gridLayout->addWidget(pushButton_Add, 1, 1, 1, 1);

    pushButton_Edit = new QPushButton(CredentialsTable);
    pushButton_Edit->setObjectName(QString::fromUtf8("pushButton_3"));

    gridLayout->addWidget(pushButton_Edit, 1, 3, 1, 1);

    horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_2, 1, 6, 1, 1);

    pushButton_Remove = new QPushButton(CredentialsTable);
    pushButton_Remove->setObjectName(QString::fromUtf8("pushButton_4"));

    gridLayout->addWidget(pushButton_Remove, 1, 5, 1, 1);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 1, 0, 1, 1);

    CredentialsTableWidget = new QTableWidget(widget);

    if (CredentialsTableWidget->columnCount() < 6)
        CredentialsTableWidget->setColumnCount(6);

    QTableWidgetItem *__qtablewidgetitem = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(0, __qtablewidgetitem);
    QTableWidgetItem *__qtablewidgetitem1 = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(1, __qtablewidgetitem1);
    QTableWidgetItem *__qtablewidgetitem2 = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(2, __qtablewidgetitem2);
    QTableWidgetItem *__qtablewidgetitem3 = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(3, __qtablewidgetitem3);
    QTableWidgetItem *__qtablewidgetitem4 = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(4, __qtablewidgetitem4);
    QTableWidgetItem *__qtablewidgetitem5 = new QTableWidgetItem();
    CredentialsTableWidget->setHorizontalHeaderItem(5, __qtablewidgetitem5);

    CredentialsTableWidget->setObjectName( QString::fromUtf8( "CredentialsTableWidget" ) );
    CredentialsTableWidget->setEnabled( true );
    CredentialsTableWidget->setShowGrid( false );
    CredentialsTableWidget->setSortingEnabled( false );
    CredentialsTableWidget->setWordWrap( true );
    CredentialsTableWidget->setCornerButtonEnabled( true );
    CredentialsTableWidget->horizontalHeader()->setVisible( true );
    CredentialsTableWidget->setSelectionBehavior( QAbstractItemView::SelectRows );
    CredentialsTableWidget->setContextMenuPolicy( Qt::CustomContextMenu );
    CredentialsTableWidget->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    CredentialsTableWidget->verticalHeader()->setVisible(false);
    CredentialsTableWidget->verticalHeader()->setStretchLastSection( false );
    CredentialsTableWidget->verticalHeader()->setDefaultSectionSize( 12 );
    CredentialsTableWidget->setFocusPolicy( Qt::NoFocus );

    gridLayout->addWidget(CredentialsTableWidget, 0, 0, 1, 7);

    pushButton_Export = new QPushButton(CredentialsTable);
    pushButton_Export->setObjectName(QString::fromUtf8("pushButton_Export"));

    gridLayout->addWidget(pushButton_Export, 1, 4, 1, 1);

    CredentialsTable->setWindowTitle(QCoreApplication::translate("Credentials", "Credentials", nullptr));

    pushButton_Add->setText(QCoreApplication::translate("Credentials", "Add", nullptr));
    pushButton_Copy->setText(QCoreApplication::translate("Credentials", "Copy", nullptr));
    pushButton_Edit->setText(QCoreApplication::translate("Credentials", "Edit", nullptr));
    pushButton_Remove->setText(QCoreApplication::translate("Credentials", "Remove", nullptr));
    pushButton_Export->setText(QCoreApplication::translate("Credentials", "Export", nullptr));

    QTableWidgetItem *___qtablewidgetitem = CredentialsTableWidget->horizontalHeaderItem(0);
    ___qtablewidgetitem->setText(QCoreApplication::translate("Credentials", "User", nullptr));
    QTableWidgetItem *___qtablewidgetitem1 = CredentialsTableWidget->horizontalHeaderItem(1);
    ___qtablewidgetitem1->setText(QCoreApplication::translate("Credentials", "Password", nullptr));
    QTableWidgetItem *___qtablewidgetitem2 = CredentialsTableWidget->horizontalHeaderItem(2);
    ___qtablewidgetitem2->setText(QCoreApplication::translate("Credentials", "Type", nullptr));
    QTableWidgetItem *___qtablewidgetitem3 = CredentialsTableWidget->horizontalHeaderItem(3);
    ___qtablewidgetitem3->setText(QCoreApplication::translate("Credentials", "Domain", nullptr));
    QTableWidgetItem *___qtablewidgetitem4 = CredentialsTableWidget->horizontalHeaderItem(4);
    ___qtablewidgetitem4->setText(QCoreApplication::translate("Credentials", "Source", nullptr));
    QTableWidgetItem *___qtablewidgetitem5 = CredentialsTableWidget->horizontalHeaderItem(5);
    ___qtablewidgetitem5->setText(QCoreApplication::translate("Credentials", "Added", nullptr));

    Util::CredentialsItem testCreds = {
            .User = "Jim Steven",
            .Password = "h3lloM0m",
            .Type = Util::CredentialsItem::PasswordTypes::Cleartext,
            .Domain = "microsoft.local",
            .Source = Util::CredentialsItem::SourceTypes::Mimikatz,
            .Added = QTime::currentTime().toString("hh:mm:ss").toStdString().c_str(),
    };

    Util::CredentialsItem testCreds2 = {
            .User = "Jeniver Steven",
            .Password = "h3lloMrSteven",
            .Type = Util::CredentialsItem::PasswordTypes::Hashed,
            .Domain = "MYSQL",
            .Source = Util::CredentialsItem::SourceTypes::Hashdump,
            .Added = QTime::currentTime().toString("hh:mm:ss").toStdString().c_str(),
    };

    AddNewCredentials(&testCreds);
    AddNewCredentials(&testCreds2);

    connect(pushButton_Add, &QPushButton::clicked, this, &CredentialsTable::onButton_Add);
    connect(pushButton_Edit, &QPushButton::clicked, this, &CredentialsTable::onButton_Edit);
    connect(pushButton_Remove, &QPushButton::clicked, this, &CredentialsTable::onButton_Remove);

    QMetaObject::connectSlotsByName(CredentialsTable);
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::AddNewCredentials(Util::CredentialsItem *Item)
{
    HavocX::Teamserver.Credentials.push_back(*Item);

    if ( CredentialsTableWidget->rowCount() < 1 )
        CredentialsTableWidget->setRowCount( 1 );
    else
        CredentialsTableWidget->setRowCount( CredentialsTableWidget->rowCount() + 1 );

    const bool isSortingEnabled = CredentialsTableWidget->isSortingEnabled();
    CredentialsTableWidget->setSortingEnabled( false );

    auto *item_User = new QTableWidgetItem();
    item_User->setText(Item->User.c_str());
    item_User->setFlags(item_User->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 0, item_User);

    auto *item_Password = new QTableWidgetItem();
    item_Password->setText(Item->Password.c_str());
    item_Password->setFlags(item_Password->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 1, item_Password);

    auto *item_Type = new QTableWidgetItem();
    item_Type->setText(Item->Type.c_str());
    item_Type->setFlags(item_Type->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 2, item_Type);

    auto *item_Domain = new QTableWidgetItem();
    item_Domain->setText(Item->Domain.c_str());
    // item_Domain->setTextAlignment( Qt::AlignCenter );
    item_Domain->setFlags(item_Domain->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 3, item_Domain);

    auto *item_Source = new QTableWidgetItem();
    item_Source->setText(Item->Source.c_str());
    // item_Source->setTextAlignment( Qt::AlignCenter );
    item_Source->setFlags(item_Source->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 4, item_Source);

    auto *item_Added = new QTableWidgetItem();
    item_Added->setText(Item->Added.c_str());
    // item_Added->setTextAlignment( Qt::AlignCenter );
    item_Added->setFlags(item_Added->flags() ^ Qt::ItemIsEditable);
    CredentialsTableWidget->setItem(CredentialsTableWidget->rowCount()-1, 5, item_Added);

    CredentialsTableWidget->setSortingEnabled(isSortingEnabled);
}

// ------------------------------------------------------
// ------------------------------------------------------
// ------------------------------------------------------

void HavocNamespace::UserInterface::Widgets::CredentialsTable::onButton_Add() {
    if (this->AddCredentialsDialog == nullptr)
    {
        this->AddCredentialsDialog = new CredentialsTable::AddCredentials;
        this->AddCredentialsDialog->setupUi(new QDialog);
        this->AddCredentialsDialog->setMainTable(this->CredentialsTableWidget);
    }

    std::cout << std::hex << this->AddCredentialsDialog->AddDialog << std::endl;

    auto CredentialsMap = this->AddCredentialsDialog->StartDialog();

    if (this->AddCredentialsDialog->addCredentials)
        AddNewCredentials(&CredentialsMap);
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::onButton_Edit() {
    if (this->EditCredentialsDialog == nullptr)
    {
        this->EditCredentialsDialog = new CredentialsTable::EditCredentials;
        this->EditCredentialsDialog->setupUi(new QDialog);
        this->EditCredentialsDialog->AddDialog->setWindowTitle("Edit Credentials");
        this->EditCredentialsDialog->pushButton_Add->setText("Edit");
        this->EditCredentialsDialog->textEdit->setHtml("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                       "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                       "p, li { white-space: pre-wrap; }\n"
                                                       "</style></head><body style=\" font-family:'Monaco'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
                                                       "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Edit Credentials from database</p></body></html>");
        this->EditCredentialsDialog->setMainTable(this->CredentialsTableWidget);
    }

    Util::CredentialsItem editCreds = {
            .User       = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 0)->text().toStdString(),
            .Password   = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 1)->text().toStdString(),
            .Type       = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 2)->text().toStdString(),
            .Domain     = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 3)->text().toStdString(),
            .Source     = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 4)->text().toStdString(),
            .Added      = CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 5)->text().toStdString(),
    };

    this->EditCredentialsDialog->SetCredentialsInDialog(&editCreds);
    auto editedCredentials = this->EditCredentialsDialog->StartDialog();

    if (this->EditCredentialsDialog->addCredentials)
    {
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 0)->setText(editedCredentials.User.c_str());
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 1)->setText(editedCredentials.Password.c_str());
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 2)->setText(editedCredentials.Type.c_str());
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 3)->setText(editedCredentials.Domain.c_str());
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 4)->setText(editedCredentials.Source.c_str());
        CredentialsTableWidget->item(CredentialsTableWidget->currentRow(), 5)->setText(editedCredentials.Added.c_str());
    }
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::onButton_Remove() {
    CredentialsTableWidget->removeRow(CredentialsTableWidget->currentRow());
}

// ------------------------------------------------------
// ------------------------------------------------------
// ------------------------------------------------------

void HavocNamespace::UserInterface::Widgets::CredentialsTable::AddCredentials::setupUi(QDialog *AddDialog)
{
    this->AddDialog = AddDialog;

    if (AddDialog->objectName().isEmpty())
        AddDialog->setObjectName(QString::fromUtf8("AddEditCredentials"));

    AddDialog->resize(408, 246);

    AddDialog->setMinimumSize(QSize(408, 246));
    AddDialog->setMaximumSize(QSize(408, 246));
    gridLayout = new QGridLayout(AddDialog);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    pushButton_Close = new QPushButton(AddDialog);
    pushButton_Close->setObjectName(QString::fromUtf8("pushButton_Close"));

    gridLayout->addWidget(pushButton_Close, 6, 3, 1, 1);

    horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_2, 6, 4, 1, 1);

    label = new QLabel(AddDialog);
    label->setObjectName(QString::fromUtf8("label_Name"));

    gridLayout->addWidget(label, 1, 0, 1, 1);

    label_5 = new QLabel(AddDialog);
    label_5->setObjectName(QString::fromUtf8("label_Password"));

    gridLayout->addWidget(label_5, 5, 0, 1, 1);

    horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_3, 6, 5, 1, 1);

    label_3 = new QLabel(AddDialog);
    label_3->setObjectName(QString::fromUtf8("label_Port"));

    gridLayout->addWidget(label_3, 3, 0, 1, 1);

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer, 6, 1, 1, 1);

    pushButton_Add = new QPushButton(AddDialog);
    pushButton_Add->setObjectName(QString::fromUtf8("pushButton_New_Profile"));

    gridLayout->addWidget(pushButton_Add, 6, 2, 1, 1);

    label_4 = new QLabel(AddDialog);
    label_4->setObjectName(QString::fromUtf8("label_User"));

    gridLayout->addWidget(label_4, 4, 0, 1, 1);

    label_2 = new QLabel(AddDialog);
    label_2->setObjectName(QString::fromUtf8("label_Host"));

    gridLayout->addWidget(label_2, 2, 0, 1, 1);

    horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

    gridLayout->addItem(horizontalSpacer_4, 6, 6, 1, 1);

    lineEdit_User = new QLineEdit(AddDialog);
    lineEdit_User->setObjectName(QString::fromUtf8("lineEdit_PORT"));

    gridLayout->addWidget(lineEdit_User, 1, 1, 1, 6);

    lineEdit_Password = new QLineEdit(AddDialog);
    lineEdit_Password->setObjectName(QString::fromUtf8("lineEdit_Port"));

    gridLayout->addWidget(lineEdit_Password, 2, 1, 1, 6);

    comboBox_PassType = new QComboBox(AddDialog);
    comboBox_PassType->addItem(QString("cleartext"), Util::CredentialsItem::PasswordTypes::Cleartext.c_str());
    comboBox_PassType->addItem(QString("hashed"), Util::CredentialsItem::PasswordTypes::Hashed.c_str());
    comboBox_PassType->setObjectName(QString::fromUtf8("comboBox_PassType"));

    gridLayout->addWidget(comboBox_PassType, 3, 1, 1, 6);

    lineEdit_Domain = new QLineEdit(AddDialog);
    lineEdit_Domain->setObjectName(QString::fromUtf8("lineEdit_Domain"));

    gridLayout->addWidget(lineEdit_Domain, 4, 1, 1, 6);

    comboBox_Source = new QComboBox(AddDialog);
    comboBox_Source->addItem(QString(Util::CredentialsItem::SourceTypes::Mimikatz.c_str()), Util::CredentialsItem::SourceTypes::Mimikatz.c_str());
    comboBox_Source->addItem(QString(Util::CredentialsItem::SourceTypes::Hashdump.c_str()), Util::CredentialsItem::SourceTypes::Hashdump.c_str());
    comboBox_Source->addItem(QString(Util::CredentialsItem::SourceTypes::Manuel.c_str()), Util::CredentialsItem::SourceTypes::Manuel.c_str());
    comboBox_Source->setObjectName(QString::fromUtf8("comboBox_Source"));

    gridLayout->addWidget(comboBox_Source, 5, 1, 1, 6);

    textEdit = new QTextEdit(AddDialog);
    textEdit->setObjectName(QString::fromUtf8("EventLogText"));
    textEdit->setReadOnly(true);

    gridLayout->addWidget(textEdit, 0, 0, 1, 7);

    AddDialog->setWindowTitle(QCoreApplication::translate("AddDialog", "Add Credentials", nullptr));
    pushButton_Close->setText(QCoreApplication::translate("AddDialog", "Close", nullptr));
    label->setText(QCoreApplication::translate("AddDialog", "<html><head/><body><p><span style=\" font-size:12pt;\">User:</span></p></body></html>", nullptr));
    label_5->setText(QCoreApplication::translate("AddDialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Source:</span></p></body></html>", nullptr));
    label_3->setText(QCoreApplication::translate("AddDialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Type:</span></p></body></html>", nullptr));
    pushButton_Add->setText(QCoreApplication::translate("AddDialog", "Add", nullptr));
    label_4->setText(QCoreApplication::translate("AddDialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Domain:</span></p></body></html>", nullptr));
    label_2->setText(QCoreApplication::translate("AddDialog", "<html><head/><body><p><span style=\" font-size:12pt;\">Password:</span></p></body></html>", nullptr));

    comboBox_PassType->setItemText(0, QCoreApplication::translate("AddDialog", "cleartext", nullptr));
    comboBox_PassType->setItemText(1, QCoreApplication::translate("AddDialog", "hashed", nullptr));

    comboBox_Source->setItemText(0, QCoreApplication::translate("AddDialog", "manuel", nullptr));
    comboBox_Source->setItemText(1, QCoreApplication::translate("AddDialog", "mimikatz", nullptr));
    comboBox_Source->setItemText(2, QCoreApplication::translate("AddDialog", "hashdump", nullptr));

    textEdit->setHtml(QCoreApplication::translate("AddDialog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                                        "<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
                                                                        "p, li { white-space: pre-wrap; }\n"
                                                                        "</style></head><body style=\" font-family:'Monaco'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
                                                                        "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Add Credentials to database</p></body></html>", nullptr));

    connect(pushButton_Close, &QPushButton::clicked, this, &AddCredentials::onButton_Close);
    connect(pushButton_Add, &QPushButton::clicked, this, &AddCredentials::onButton_Add);

    QMetaObject::connectSlotsByName(AddDialog);
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::AddCredentials::setMainTable(QTableWidget *Widget) {
    this->tableWidget = Widget;
}

HavocNamespace::Util::CredentialsItem HavocNamespace::UserInterface::Widgets::CredentialsTable::AddCredentials::StartDialog() {
    this->AddDialog->exec();

    HavocNamespace::Util::CredentialsItem NewCreds = {
            .User       = lineEdit_User->text().toStdString(),
            .Password   = lineEdit_Password->text().toStdString(),
            .Type       = comboBox_PassType->currentText().toStdString(),
            .Domain     = lineEdit_Domain->text().toStdString(),
            .Source     = comboBox_Source->currentText().toStdString(),
            .Added      = QTime::currentTime().toString("hh:mm:ss").toStdString(),
    };

    return NewCreds;
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::AddCredentials::onButton_Close() {
    addCredentials = false;
    this->AddDialog->close();
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::AddCredentials::onButton_Add() const {
    this->AddDialog->close();
}

void HavocNamespace::UserInterface::Widgets::CredentialsTable::EditCredentials::SetCredentialsInDialog(
        HavocNamespace::Util::CredentialsItem *Credentials) {

    lineEdit_User->setText(Credentials->User.c_str());
    lineEdit_Password->setText(Credentials->Password.c_str());
    lineEdit_Domain->setText(Credentials->Domain.c_str());

    for (int index = 0; index < comboBox_PassType->count(); index++)
        if (strcmp(Credentials->Type.c_str() , comboBox_PassType->itemText(index).toStdString().c_str()) == 0)
            comboBox_PassType->setCurrentIndex(index);

    for (int index = 0; index < comboBox_Source->count(); index++)
        if (strcmp(Credentials->Source.c_str() , comboBox_Source->itemText(index).toStdString().c_str()) == 0)
            comboBox_Source->setCurrentIndex(index);

}