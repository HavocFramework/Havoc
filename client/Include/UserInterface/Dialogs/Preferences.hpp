#ifndef HAVOC_PREFERENCES_HPP
#define HAVOC_PREFERENCES_HPP

#include <global.hpp>
#include <QListWidget>
#include <QStackedWidget>
#include <QComboBox>
#include <QGroupBox>
#include <QCheckBox>

class HavocNamespace::UserInterface::Dialogs::Preferences : public QDialog {
    QGridLayout *gridLayout;
    QListWidget *ListSettingsWidgets;
    QSpacerItem *horizontalSpacer;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *pushButton_Save;
    QPushButton *pushButton_Close;
    QStackedWidget *stackedWidget;
    QWidget *AppearancePage;
    QLabel *label_2;
    QLabel *label;
    QComboBox *comboBox_Themes;
    QComboBox *comboBox_UI_Font;
    QLabel *label_3;
    QComboBox *comboBox_UI_Size;
    QGroupBox *groupBox_Statusbar;
    QCheckBox *checkBox_EnableStatusbar;
    QLabel *label_Background;
    QLineEdit *lineEdit_Background;
    QLineEdit *lineEdit_Foreground;
    QLabel *label_Foreground;
    QCheckBox *checkBox_activeDemonSession;
    QCheckBox *checkBox_numTeamservers;
    QCheckBox *checkBox_numCreds;
    QCheckBox *checkBox_showTeamserverTitleBar;
    QWidget *TabsPage;
    QGroupBox *TeamserverTabBox;
    QLabel *label_TeamserverTab_Position;
    QComboBox *comboBox_TeamserverTab_Position;
    QCheckBox *checkBox_AutoHide_Teamservers;
    QLabel *label_TeamserverTab_Size;
    QLabel *label_TeamserverTab_Font;
    QComboBox *comboBox_TeamserverTab_Font;
    QComboBox *comboBox_TeamserverTab_Size;
    QGroupBox *BottomTabBox;
    QLabel *label_BottomPosition;
    QComboBox *comboBox_Bottom_Position;
    QComboBox *comboBox_Bottom_Size;
    QLabel *label_Bottom_Font;
    QComboBox *comboBox_Bottom_Font;
    QLabel *label_Bottom_Size;
    QCheckBox *checkBox_ShowIcons;

public:

    QDialog* PreferencesDialog;
    void setupUi(QDialog* Dialog = new QDialog);
    void StartDialog();

protected slots:
    void onItemSelect();
    void onButtonSave();
    void onButtonClose();
};

#endif
