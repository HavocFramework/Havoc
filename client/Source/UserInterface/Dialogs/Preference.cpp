#include <UserInterface/Dialogs/Preferences.hpp>
#include <QFontDatabase>
#include <QFile>

void HavocNamespace::UserInterface::Dialogs::Preferences::setupUi(QDialog *Dialog) {
    this->PreferencesDialog = Dialog;

    if (Dialog->objectName().isEmpty())
        Dialog->setObjectName(QString::fromUtf8("Dialog"));

    Dialog->resize(560, 385);
    Dialog->setMinimumSize(QSize(560, 385));
    Dialog->setMaximumSize(QSize(560, 385));
    Dialog->setWindowTitle("Preferences");

    Dialog->setStyleSheet( FileRead( ":/stylesheets/Dialogs/Preferences" ) );

    gridLayout = new QGridLayout(Dialog);
    gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
    ListSettingsWidgets = new QListWidget(Dialog);

    // ListSettingsWidgets->addItem();

    auto AppearanceListItem = new QListWidgetItem(ListSettingsWidgets);
    auto TabsListItem       = new QListWidgetItem(ListSettingsWidgets);
    auto MiscListItem       = new QListWidgetItem(ListSettingsWidgets);
    auto KeyboardListItem   = new QListWidgetItem(ListSettingsWidgets);

    ListSettingsWidgets->setObjectName(QString::fromUtf8("ListSettingsWidgets"));
    gridLayout->addWidget(ListSettingsWidgets, 0, 0, 1, 1);

    horizontalSpacer = new QSpacerItem(173, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    gridLayout->addItem(horizontalSpacer, 1, 0, 1, 1);

    horizontalSpacer_2 = new QSpacerItem(365, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    gridLayout->addItem(horizontalSpacer_2, 1, 1, 1, 2);

    pushButton_Save = new QPushButton(Dialog);
    pushButton_Save->setObjectName(QString::fromUtf8("pushButton_Save"));
    gridLayout->addWidget(pushButton_Save, 1, 3, 1, 1);

    pushButton_Close = new QPushButton(Dialog);
    pushButton_Close->setObjectName(QString::fromUtf8("pushButton_Close"));

    gridLayout->addWidget(pushButton_Close, 1, 4, 1, 1);

    stackedWidget = new QStackedWidget(Dialog);
    stackedWidget->setObjectName(QString::fromUtf8("stackedWidget"));

    AppearancePage = new QWidget();
    AppearancePage->setObjectName(QString::fromUtf8("AppearancePage"));

    label_2 = new QLabel(AppearancePage);
    label_2->setObjectName(QString::fromUtf8("label_2"));
    label_2->setGeometry(QRect(10, 20, 61, 21));

    label = new QLabel(AppearancePage);
    label->setObjectName(QString::fromUtf8("label"));
    label->setGeometry(QRect(10, 50, 51, 21));

    comboBox_Themes = new QComboBox(AppearancePage);
    comboBox_Themes->addItem(QString());
    comboBox_Themes->addItem(QString());
    comboBox_Themes->addItem(QString());
    comboBox_Themes->setObjectName(QString::fromUtf8("comboBox_Themes"));
    comboBox_Themes->setGeometry(QRect(70, 50, 291, 23));

    comboBox_UI_Font = new QComboBox(AppearancePage);
    comboBox_UI_Font->setObjectName(QString::fromUtf8("comboBox_UI_Font"));
    comboBox_UI_Font->setGeometry(QRect(70, 20, 181, 23));
    comboBox_UI_Font->setMaxVisibleItems(10);
    comboBox_UI_Font->setStyleSheet("QComboBox { combobox-popup: 0; }");

    std::cout << "comboBox_UI_Font->maxVisibleItems() :: " << comboBox_UI_Font->maxVisibleItems() << std::endl;

    label_3 = new QLabel(AppearancePage);
    label_3->setObjectName(QString::fromUtf8("label_3"));
    label_3->setGeometry(QRect(270, 20, 41, 21));

    comboBox_UI_Size = new QComboBox(AppearancePage);
    comboBox_UI_Size->addItem(QString());
    comboBox_UI_Size->addItem(QString());
    comboBox_UI_Size->addItem(QString());
    comboBox_UI_Size->setObjectName(QString::fromUtf8("comboBox_UI_Size"));
    comboBox_UI_Size->setGeometry(QRect(310, 20, 51, 23));
    comboBox_UI_Size->setAutoFillBackground(false);
    comboBox_UI_Size->setEditable(true);

    groupBox_Statusbar = new QGroupBox(AppearancePage);
    groupBox_Statusbar->setObjectName(QString::fromUtf8("groupBox_Statusbar"));
    groupBox_Statusbar->setGeometry(QRect(10, 110, 351, 191));

    checkBox_EnableStatusbar = new QCheckBox(groupBox_Statusbar);
    checkBox_EnableStatusbar->setObjectName(QString::fromUtf8("checkBox_EnableStatusbar"));
    checkBox_EnableStatusbar->setGeometry(QRect(10, 26, 281, 20));

    label_Background = new QLabel(groupBox_Statusbar);
    label_Background->setObjectName(QString::fromUtf8("label_Background"));
    label_Background->setGeometry(QRect(10, 61, 81, 16));

    lineEdit_Background = new QLineEdit(groupBox_Statusbar);
    lineEdit_Background->setObjectName(QString::fromUtf8("lineEdit_Background"));
    lineEdit_Background->setGeometry(QRect(90, 61, 251, 20));

    lineEdit_Foreground = new QLineEdit(groupBox_Statusbar);
    lineEdit_Foreground->setObjectName(QString::fromUtf8("lineEdit_Foreground"));
    lineEdit_Foreground->setGeometry(QRect(90, 91, 251, 20));

    label_Foreground = new QLabel(groupBox_Statusbar);
    label_Foreground->setObjectName(QString::fromUtf8("label_Foreground"));
    label_Foreground->setGeometry(QRect(10, 91, 81, 16));

    checkBox_activeDemonSession = new QCheckBox(groupBox_Statusbar);
    checkBox_activeDemonSession->setObjectName(QString::fromUtf8("checkBox_activeDemonSession"));
    checkBox_activeDemonSession->setGeometry(QRect(10, 121, 321, 20));

    checkBox_numTeamservers = new QCheckBox(groupBox_Statusbar);
    checkBox_numTeamservers->setObjectName(QString::fromUtf8("checkBox_numTeamservers"));
    checkBox_numTeamservers->setGeometry(QRect(10, 140, 331, 20));

    checkBox_numCreds = new QCheckBox(groupBox_Statusbar);
    checkBox_numCreds->setObjectName(QString::fromUtf8("checkBox_numCreds"));
    checkBox_numCreds->setGeometry(QRect(10, 160, 331, 20));

    checkBox_showTeamserverTitleBar = new QCheckBox(AppearancePage);
    checkBox_showTeamserverTitleBar->setObjectName(QString::fromUtf8("checkBox_showTeamserverTitleBar"));
    checkBox_showTeamserverTitleBar->setGeometry(QRect(10, 80, 351, 20));

    stackedWidget->addWidget(AppearancePage);

    TabsPage = new QWidget();
    TabsPage->setObjectName(QString::fromUtf8("TabsPage"));

    TeamserverTabBox = new QGroupBox(TabsPage);
    TeamserverTabBox->setObjectName(QString::fromUtf8("TeamserverTabBox"));
    TeamserverTabBox->setGeometry(QRect(9, 9, 351, 131));

    label_TeamserverTab_Position = new QLabel(TeamserverTabBox);
    label_TeamserverTab_Position->setObjectName(QString::fromUtf8("label_TeamserverTab_Position"));
    label_TeamserverTab_Position->setGeometry(QRect(10, 30, 71, 21));

    comboBox_TeamserverTab_Position = new QComboBox(TeamserverTabBox);
    comboBox_TeamserverTab_Position->addItem(QString());
    comboBox_TeamserverTab_Position->addItem(QString());
    comboBox_TeamserverTab_Position->setObjectName(QString::fromUtf8("comboBox_TeamserverTab_Position"));
    comboBox_TeamserverTab_Position->setGeometry(QRect(90, 30, 251, 23));

    checkBox_AutoHide_Teamservers = new QCheckBox(TeamserverTabBox);
    checkBox_AutoHide_Teamservers->setObjectName(QString::fromUtf8("checkBox_AutoHide_Teamservers"));
    checkBox_AutoHide_Teamservers->setGeometry(QRect(10, 90, 331, 26));

    label_TeamserverTab_Size = new QLabel(TeamserverTabBox);
    label_TeamserverTab_Size->setObjectName(QString::fromUtf8("label_TeamserverTab_Size"));
    label_TeamserverTab_Size->setGeometry(QRect(240, 60, 41, 21));

    label_TeamserverTab_Font = new QLabel(TeamserverTabBox);
    label_TeamserverTab_Font->setObjectName(QString::fromUtf8("label_TeamserverTab_Font"));
    label_TeamserverTab_Font->setGeometry(QRect(10, 60, 71, 21));

    comboBox_TeamserverTab_Font = new QComboBox(TeamserverTabBox);
    comboBox_TeamserverTab_Font->addItem(QString());
    comboBox_TeamserverTab_Font->setObjectName(QString::fromUtf8("comboBox_TeamserverTab_Font"));
    comboBox_TeamserverTab_Font->setGeometry(QRect(90, 60, 131, 23));
    comboBox_TeamserverTab_Font->setMaxVisibleItems(10);
    comboBox_TeamserverTab_Font->setStyleSheet("QComboBox { combobox-popup: 0; }");


    comboBox_TeamserverTab_Size = new QComboBox(TeamserverTabBox);
    comboBox_TeamserverTab_Size->addItem(QString());
    comboBox_TeamserverTab_Size->addItem(QString());
    comboBox_TeamserverTab_Size->addItem(QString());
    comboBox_TeamserverTab_Size->setObjectName(QString::fromUtf8("comboBox_TeamserverTab_Size"));
    comboBox_TeamserverTab_Size->setGeometry(QRect(280, 60, 61, 23));
    comboBox_TeamserverTab_Size->setAutoFillBackground(false);
    comboBox_TeamserverTab_Size->setEditable(true);

    BottomTabBox = new QGroupBox(TabsPage);
    BottomTabBox->setObjectName(QString::fromUtf8("BottomTabBox"));
    BottomTabBox->setGeometry(QRect(10, 170, 351, 151));

    label_BottomPosition = new QLabel(BottomTabBox);
    label_BottomPosition->setObjectName(QString::fromUtf8("label_BottomPosition"));
    label_BottomPosition->setGeometry(QRect(10, 30, 71, 21));

    comboBox_Bottom_Position = new QComboBox(BottomTabBox);
    comboBox_Bottom_Position->addItem(QString());
    comboBox_Bottom_Position->addItem(QString());
    comboBox_Bottom_Position->setObjectName(QString::fromUtf8("comboBox_Bottom_Position"));
    comboBox_Bottom_Position->setGeometry(QRect(90, 30, 251, 23));

    comboBox_Bottom_Size = new QComboBox(BottomTabBox);
    comboBox_Bottom_Size->addItem(QString());
    comboBox_Bottom_Size->addItem(QString());
    comboBox_Bottom_Size->addItem(QString());
    comboBox_Bottom_Size->setObjectName(QString::fromUtf8("comboBox_Bottom_Size"));
    comboBox_Bottom_Size->setGeometry(QRect(280, 60, 61, 23));
    comboBox_Bottom_Size->setAutoFillBackground(false);
    comboBox_Bottom_Size->setEditable(true);

    label_Bottom_Font = new QLabel(BottomTabBox);
    label_Bottom_Font->setObjectName(QString::fromUtf8("label_Bottom_Font"));
    label_Bottom_Font->setGeometry(QRect(10, 60, 71, 21));

    comboBox_Bottom_Font = new QComboBox(BottomTabBox);
    comboBox_Bottom_Font->addItem(QString());
    comboBox_Bottom_Font->setObjectName(QString::fromUtf8("comboBox_Bottom_Font"));
    comboBox_Bottom_Font->setGeometry(QRect(90, 60, 131, 23));
    comboBox_Bottom_Font->setMaxVisibleItems(10);
    comboBox_Bottom_Font->setStyleSheet("QComboBox { combobox-popup: 0; }");

    label_Bottom_Size = new QLabel(BottomTabBox);
    label_Bottom_Size->setObjectName(QString::fromUtf8("label_Bottom_Size"));
    label_Bottom_Size->setGeometry(QRect(240, 60, 41, 21));

    checkBox_ShowIcons = new QCheckBox(BottomTabBox);
    checkBox_ShowIcons->setObjectName(QString::fromUtf8("checkBox_ShowIcons"));
    checkBox_ShowIcons->setGeometry(QRect(10, 90, 331, 26));
    stackedWidget->addWidget(TabsPage);

    gridLayout->addWidget(stackedWidget, 0, 1, 1, 4);

    // ----------------------------------------------

    ListSettingsWidgets->setSortingEnabled(false);
    AppearanceListItem->setText(QCoreApplication::translate("Dialog", "Appearance", nullptr));
    TabsListItem->setText(QCoreApplication::translate("Dialog", "Tabs", nullptr));
    MiscListItem->setText(QCoreApplication::translate("Dialog", "Misc", nullptr));
    KeyboardListItem->setText(QCoreApplication::translate("Dialog", "Keyboard Shortcuts", nullptr));

    pushButton_Save->setText(QCoreApplication::translate("Dialog", "Save", nullptr));
    pushButton_Close->setText(QCoreApplication::translate("Dialog", "Close", nullptr));
    label_2->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Font:</p></body></html>", nullptr));
    label->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Theme:</p></body></html>", nullptr));
    comboBox_Themes->setItemText(0, QCoreApplication::translate("Dialog", "Dracula", nullptr));
    comboBox_Themes->setItemText(1, QCoreApplication::translate("Dialog", "Dragon Blood", nullptr));
    comboBox_Themes->setItemText(2, QCoreApplication::translate("Dialog", "Dracula Light", nullptr));

    QFontDatabase FontDatabase; 
    for (int i = 0 ; i < FontDatabase.families().size(); i++) {
        comboBox_UI_Font->addItem(FontDatabase.families()[i]);
    }

    label_3->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Size:</p></body></html>", nullptr));

    for (int i = 0; i < 20; i++) {
        comboBox_UI_Size->setItemText(i, QString::number(i+1));
    }

    groupBox_Statusbar->setTitle(QCoreApplication::translate("Dialog", "Statusbar", nullptr));
    checkBox_EnableStatusbar->setText(QCoreApplication::translate("Dialog", "Enable Statusbar", nullptr));
    label_Background->setText(QCoreApplication::translate("Dialog", "Background:", nullptr));
    label_Foreground->setText(QCoreApplication::translate("Dialog", "Foreground:", nullptr));
    checkBox_activeDemonSession->setText(QCoreApplication::translate("Dialog", "Show active demon sessions", nullptr));
    checkBox_numTeamservers->setText(QCoreApplication::translate("Dialog", "Show number of teamserver connected to", nullptr));
    checkBox_numCreds->setText(QCoreApplication::translate("Dialog", "Show number of credentials gathered", nullptr));
    checkBox_showTeamserverTitleBar->setText(QCoreApplication::translate("Dialog", "Show teamserver name in titlebar", nullptr));
    TeamserverTabBox->setTitle(QCoreApplication::translate("Dialog", "Teamserver  Tabs", nullptr));
    label_TeamserverTab_Position->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Position:</p></body></html>", nullptr));
    comboBox_TeamserverTab_Position->setItemText(0, QCoreApplication::translate("Dialog", "Top", nullptr));
    comboBox_TeamserverTab_Position->setItemText(1, QCoreApplication::translate("Dialog", "Bottom", nullptr));

    checkBox_AutoHide_Teamservers->setText(QCoreApplication::translate("Dialog", "AutoHide Teamserver Tabs", nullptr));
    label_TeamserverTab_Size->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Size:</p></body></html>", nullptr));
    label_TeamserverTab_Font->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Font:</p></body></html>", nullptr));

    for (int i = 0 ; i < FontDatabase.families().size(); i++) {
        comboBox_TeamserverTab_Font->addItem(FontDatabase.families()[i]);
        comboBox_TeamserverTab_Font->setItemText(i, FontDatabase.families()[i]);
    }

    for (int i = 0; i < 20; i++) {
        comboBox_TeamserverTab_Size->setItemText(i, QString::number(i+1));
    }

    BottomTabBox->setTitle(QCoreApplication::translate("Dialog", "Bottom Tabs", nullptr));
    label_BottomPosition->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Position:</p></body></html>", nullptr));
    comboBox_Bottom_Position->setItemText(0, QCoreApplication::translate("Dialog", "Top", nullptr));
    comboBox_Bottom_Position->setItemText(1, QCoreApplication::translate("Dialog", "Bottom", nullptr));

    for (int i = 0; i < 20; i++) {
        comboBox_Bottom_Size->setItemText(i, QString::number(i+1));
    }

    label_Bottom_Font->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Font:</p></body></html>", nullptr));

    for (int i = 0 ; i < FontDatabase.families().size(); i++) {
        comboBox_Bottom_Font->addItem(FontDatabase.families()[i]);
    }

    label_Bottom_Size->setText(QCoreApplication::translate("Dialog", "<html><head/><body><p>Size:</p></body></html>", nullptr));
    checkBox_ShowIcons->setText(QCoreApplication::translate("Dialog", "Show Icons", nullptr));
    ListSettingsWidgets->setCurrentRow(0);
    stackedWidget->setCurrentIndex(0);

    connect(pushButton_Save, &QPushButton::clicked, this, &Preferences::onButtonSave);
    connect(pushButton_Close, &QPushButton::clicked, this, &Preferences::onButtonClose);
    connect(ListSettingsWidgets, &QListWidget::itemSelectionChanged, this, &Preferences::onItemSelect);
    connect(ListSettingsWidgets, &QListWidget::itemPressed, this, &Preferences::onItemSelect);

    QMetaObject::connectSlotsByName(Dialog);
}

void HavocNamespace::UserInterface::Dialogs::Preferences::StartDialog() {
    this->PreferencesDialog->exec();
}

void HavocNamespace::UserInterface::Dialogs::Preferences::onButtonSave() {

}

void HavocNamespace::UserInterface::Dialogs::Preferences::onButtonClose() {
    this->PreferencesDialog->close();
}

void HavocNamespace::UserInterface::Dialogs::Preferences::onItemSelect() {
    auto SelectedSettingItem = ListSettingsWidgets->currentItem()->text();

    if (SelectedSettingItem.compare("Appearance") == 0) {
        stackedWidget->setCurrentIndex(0);
    } else if (SelectedSettingItem.compare("Tabs") == 0) {
        stackedWidget->setCurrentIndex(1);
    } else if (SelectedSettingItem.compare("Misc") == 0) {

    } else if (SelectedSettingItem.compare("Keyboard Shortcuts") == 0) {

    }
}
