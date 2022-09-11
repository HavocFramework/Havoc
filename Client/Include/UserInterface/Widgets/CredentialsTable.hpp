#ifndef HAVOC_CREDENTIALSTABLE_HPP
#define HAVOC_CREDENTIALSTABLE_HPP

#include <global.hpp>
#include <QTableWidget>
#include <QComboBox>
#include <QTextEdit>
#include <QHeaderView>
#include <QTime>
#include <QLineEdit>

class HavocNamespace::UserInterface::Widgets::CredentialsTable : public QWidget {
public:

    class AddCredentials : public QDialog {
    protected:
        QGridLayout *gridLayout;
        QPushButton *pushButton_Close;
        QSpacerItem *horizontalSpacer_2;
        QLabel *label;
        QLabel *label_5;
        QSpacerItem *horizontalSpacer_3;
        QLabel *label_3;
        QSpacerItem *horizontalSpacer;
        QLabel *label_4;
        QLabel *label_2;
        QSpacerItem *horizontalSpacer_4;
        QLineEdit *lineEdit_User;
        QLineEdit *lineEdit_Password;
        QComboBox *comboBox_PassType;
        QLineEdit *lineEdit_Domain;
        QComboBox *comboBox_Source;
        QTableWidget* tableWidget;

    public:
        bool addCredentials = true;
        QTextEdit *textEdit;
        QPushButton *pushButton_Add;

        QDialog* AddDialog;


        void setupUi(QDialog* AddDialog);

        void setMainTable(QTableWidget* Widget);
        Util::CredentialsItem StartDialog();

    protected slots:
        void onButton_Add() const;
        void onButton_Close();

    };

    class EditCredentials : public AddCredentials {
    public:
        void SetCredentialsInDialog(Util::CredentialsItem* Credentials);
    };

    class ExportCredentials : public QDialog {
    private:

    public:
        void setupUi(QDialog* ExportDialog);
    };

private:
    QGridLayout *gridLayout;
    QPushButton *pushButton_Copy;
    QPushButton *pushButton_Add;
    QPushButton *pushButton_Edit;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *pushButton_Remove;
    QSpacerItem *horizontalSpacer;
    QPushButton *pushButton_Export;
    QTableWidget* CredentialsTableWidget;

    CredentialsTable::AddCredentials*       AddCredentialsDialog    = nullptr;
    CredentialsTable::EditCredentials*      EditCredentialsDialog   = nullptr;
    CredentialsTable::ExportCredentials*    ExportCredentialsDialog = nullptr;

public:
    QWidget* CredentialsTable;

    void setupUi(QWidget*);
    void AddNewCredentials(Util::CredentialsItem* Item);

private slots:
    void onButton_Add();
    void onButton_Edit() ;
    void onButton_Remove();
    void onButton_Exit();
    void onButton_Copy();
};

#endif
