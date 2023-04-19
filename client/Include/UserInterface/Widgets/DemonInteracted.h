#ifndef HAVOC_DEMONINTERACTED_H
#define HAVOC_DEMONINTERACTED_H

#include <global.hpp>
#include <Havoc/DemonCmdDispatch.h>

namespace HavocNamespace::UserInterface::Widgets
{
    class DemonInteracted : public QWidget
    {
    private:
        QGridLayout* gridLayout;
        QLabel*      label;
        QLabel*      label_2;

    public:
        QWidget*                    DemonInteractedWidget;
        HavocSpace::DemonCommands*  DemonCommands;
        QString                     TeamserverName;
        Util::SessionItem           SessionInfo;
        QTextEdit*                  Console;
        QCompleter*                 CommandCompleter;
        QStringList                 CompleterCommands;
        QString                     AgentTypeName = "Demon";

        class DemonInput : public QLineEdit
        {
        public:
            int CommandHistoryIndex;
            QStringList CommandHistory;
            explicit DemonInput(QWidget *parent = nullptr);

            void AddCommand( const QString& Command );

        protected:
            bool event(QEvent *) override;

        private:
            bool handleKeyPress(QKeyEvent* eventKey);
            void handleTabKey();
            void handleUpKey();
            void handleDownKey();
        };
        DemonInput* lineEdit;

        void setupUi( QWidget* Form );
        void AppendText( const QString& text );
        void AppendRaw( const QString& text = "" );
        void AppendNoNL( const QString& test );

        QString TaskInfo( bool Show, QString TaskID, const QString& text ) const;
        QString TaskError( const QString& text ) const;

        void AutoCompleteAdd( QString text );
        void AutoCompleteAddList( QStringList list );
        void AutoCompleteClear();

    private slots:
        void AppendFromInput();

    };
}

#endif
