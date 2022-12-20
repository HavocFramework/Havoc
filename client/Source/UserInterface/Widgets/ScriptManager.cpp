#include <UserInterface/Widgets/ScriptManager.h>
#include <UserInterface/Widgets/TeamserverTabSession.h>

#include <Havoc/DBManager/DBManager.hpp>

#include <QFile>
#include <QHeaderView>
#include <QFileDialog>
#include <QTableWidgetItem>

using namespace HavocNamespace::UserInterface::Widgets;

void ScriptManager::SetupUi( QWidget *Form )
{
    QString MenuStyle = "QMenu {\n"
                        "    background-color: #282a36;\n"
                        "    color: #f8f8f2;\n"
                        "    border: 1px solid #44475a;\n"
                        "}\n"
                        "\n"
                        "QMenu::separator {\n"
                        "    background: #44475a;\n"
                        "}\n"
                        "\n"
                        "QMenu::item:selected {\n"
                        "    background: #44475a;\n"
                        "}\n"
                        "\n"
                        "QAction {\n"
                        "    background-color: #282a36;\n"
                        "    color: #f8f8f2;\n"
                        "}";


    this->ScriptManagerWidget = Form;

    if ( Form->objectName().isEmpty() )
        Form->setObjectName( QString::fromUtf8("Form") );

    Form->resize( 1417, 626 );

    gridLayout = new QGridLayout( Form );
    gridLayout->setObjectName( QString::fromUtf8( "gridLayout" ) );

    buttonLoadScript = new QPushButton( Form );
    buttonLoadScript->setObjectName( QString::fromUtf8( "buttonLoadScript" ) );
    gridLayout->addWidget( buttonLoadScript, 2, 1, 1, 1 );

    horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    gridLayout->addItem( horizontalSpacer, 2, 0, 1, 1 );

    horizontalSpacer_2 = new QSpacerItem( 40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum );
    gridLayout->addItem( horizontalSpacer_2, 2, 2, 1, 1 );

    tableLoadedScripts = new QTableWidget( Form );

    tableLoadedScripts->setObjectName( QString::fromUtf8( "tableLoadedScripts" ) );
    tableLoadedScripts->setEnabled( true );
    tableLoadedScripts->setShowGrid( false );
    tableLoadedScripts->setSortingEnabled( false );
    tableLoadedScripts->setWordWrap( true );
    tableLoadedScripts->setCornerButtonEnabled( true );
    tableLoadedScripts->horizontalHeader()->setVisible( true );
    tableLoadedScripts->setSelectionBehavior( QAbstractItemView::SelectRows );
    tableLoadedScripts->setContextMenuPolicy( Qt::CustomContextMenu );
    tableLoadedScripts->horizontalHeader()->setSectionResizeMode( QHeaderView::Stretch );
    tableLoadedScripts->verticalHeader()->setVisible( false );
    tableLoadedScripts->horizontalHeader()->setStretchLastSection( true );
    tableLoadedScripts->verticalHeader()->setDefaultSectionSize( 12 );
    tableLoadedScripts->setFocusPolicy( Qt::NoFocus );

    actionReload = new QAction( "Reload" );
    actionRemove = new QAction( "Remove" );

    menuScripts = new QMenu( this );
    menuScripts->setStyleSheet( MenuStyle );
    menuScripts->addAction( actionReload );
    menuScripts->addAction( actionRemove );

    if ( tableLoadedScripts->columnCount() < 1 )
        tableLoadedScripts->setColumnCount( 1 );

    tableLoadedScripts->setHorizontalHeaderItem(0, new QTableWidgetItem());

    gridLayout->addWidget( tableLoadedScripts, 0, 0, 1, 3 );
    gridLayout->setMargin( 0 );

    QObject::connect( buttonLoadScript, &QPushButton::clicked, this, &ScriptManager::b_LoadScript );

    QObject::connect( tableLoadedScripts, &QTableWidget::customContextMenuRequested, this, &ScriptManager::menu_ScriptMenu );
    QObject::connect( actionReload, &QAction::triggered, this, &ScriptManager::ReloadScript );
    QObject::connect( actionRemove, &QAction::triggered, this, &ScriptManager::RemoveScript );

    RetranslateUi();

    for ( auto& Script : HavocX::Teamserver.TabSession->dbManager->GetScripts() )
    {
        AddScriptTable( Script );
    }

    QMetaObject::connectSlotsByName(Form);
} // setupUi

void ScriptManager::RetranslateUi( )
{
    ScriptManagerWidget->setWindowTitle(QCoreApplication::translate("Form", "Script Manager", nullptr));
    buttonLoadScript->setText(QCoreApplication::translate("Form", "Load Script", nullptr));
    tableLoadedScripts->horizontalHeaderItem(0)->setText(QCoreApplication::translate("Form", "Path", nullptr));
}

void ScriptManager::AddScript( QString Path )
{
    auto Script = FileRead( Path );

    HavocX::Teamserver.LoadingScript = Path.toStdString();

    if ( Script != nullptr )
    {
        if ( ! Script.isEmpty() )
            PyRun_SimpleStringFlags( Script.toStdString().c_str(), NULL );
        else
            spdlog::error( "Script path not found: {}", Path.toStdString() );
    }
    else
    {
        spdlog::error( "Failed to load script: {}", Path.toStdString() );
    }

    HavocX::Teamserver.LoadingScript = "";
}

void ScriptManager::AddScriptTable( QString Path )
{
    if ( tableLoadedScripts->rowCount() < 1 )
        tableLoadedScripts->setRowCount( 1 );
    else
        tableLoadedScripts->setRowCount( tableLoadedScripts->rowCount() + 1 );

    tableLoadedScripts->setItem( tableLoadedScripts->rowCount() - 1, 0, new QTableWidgetItem( Path ) );

    // add to database
    if ( ! HavocX::Teamserver.TabSession->dbManager->CheckScript( Path ) )
        HavocX::Teamserver.TabSession->dbManager->AddScript( Path );
}


void ScriptManager::b_LoadScript()
{
    auto FileDialog = QFileDialog();
    auto Filename   = QUrl();
    auto Style      = FileRead( ":/stylesheets/Dialogs/FileDialog" ).toStdString();

    Style.erase( std::remove( Style.begin(), Style.end(), '\n'), Style.end() );

    FileDialog.setStyleSheet( Style.c_str() );
    FileDialog.setDirectory( QDir::homePath() );

    if ( FileDialog.exec() == QFileDialog::Accepted )
    {
        Filename = FileDialog.selectedUrls().value( 0 ).toLocalFile();
        if ( ! Filename.toString().isNull() )
        {
            AddScript( Filename.toString() );
            AddScriptTable( Filename.toString() );
        }
    }
}

void ScriptManager::menu_ScriptMenu( const QPoint &pos ) const
{
    auto DemonSelected = tableLoadedScripts->itemAt( pos );
    if ( ! DemonSelected )
        return;

    menuScripts->popup( tableLoadedScripts->horizontalHeader()->viewport()->mapToGlobal( pos ) );
}

void ScriptManager::ReloadScript() const
{
    auto Path = tableLoadedScripts->item( tableLoadedScripts->currentRow(), 0 )->text();

    // Just rerun the script
    AddScript( Path );
}

// TODO: clear python interpreter and reload every script except the one that got removed
void ScriptManager::RemoveScript() const
{
    auto Path = tableLoadedScripts->item( tableLoadedScripts->currentRow(), 0 )->text();

    tableLoadedScripts->removeRow( tableLoadedScripts->currentRow() );

    HavocX::Teamserver.TabSession->dbManager->RemoveScript( Path );
}
