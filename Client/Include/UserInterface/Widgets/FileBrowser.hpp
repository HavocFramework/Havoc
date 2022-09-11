#ifndef HAVOC_FILEBROWSER_HPP
#define HAVOC_FILEBROWSER_HPP

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QWidget>

#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>

#include <vector>

typedef struct
{
    QString Path;

    QString Type;
    QString Name;
    QString Size;
    QString Modified;
} FileData;

typedef struct _FileDirData
{
    QString               Path;
    QJsonDocument         Data;
    std::vector<FileData> Files;
} FileDirData;

class FileBrowserTableItem : public QTableWidgetItem
{
public:
    FileData Data;
};

class FileBrowserTreeItem : public QTreeWidgetItem
{
public:
    FileData Data;
    QString  ParentPath;
};

class FileBrowser : public QWidget
{
public:
    QString                  SessionID;

    QMenu*                   MenuFileBrowserTable;
    QMenu*                   MenuFileBrowserTree;

    // General
    QAction*                 MenuFileBrowserRemove;
    QAction*                 MenuFileBrowserMkdir;
    QAction*                 MenuFileBrowserReload;

    // Tree
    QAction*                 MenuFileBrowserListDrives;

    QGridLayout*             gridLayout;
    QSplitter*               splitter;
    QFormLayout*             formLayout;

    QWidget*                 FileBrowserWidget;
    QTreeWidget*             FileBrowserTree;
    QWidget*                 FileBrowserListWidget;
    QPushButton*             ButtonGoUpDir;
    QLineEdit*               InputFileBrowserPath;
    QTableWidget*            TableFileBrowser;

    std::vector<FileDirData> DirData;

    void setupUi( QWidget* FileBrowser );
    void retranslateUi( );

    void AddData( QJsonDocument JsonData );

private:
    void TreeAddData( FileData Data );
    void TreeUpdate( );
    void TreeClear( );
    auto TreeSearchPath( QString Path ) -> FileBrowserTreeItem*;
    auto TreePathExists( QString Path ) -> bool;
    void TreeAddDisk( QString Disk );
    void TreeAddChildToParent( QString ParentPath, FileBrowserTreeItem* DataItem );


    void TableAddData( FileData Data );
    void TableClear();

    void ChangePathAndSendRequest( QString Path );

private slots:
    void onTableMenuMkdir();
    void onTableMenuReload();
    void onTableMenuRemove();

    void onTableDoubleClick( int row, int column );
    void onTableContextMenu( const QPoint &pos );

    void onTreeMenuListDrives();
    void onTreeMenuMkdir();
    void onTreeMenuReload();
    void onTreeMenuRemove();

    void onTreeDoubleClick();
    void onTreeContextMenu( const QPoint &pos );

    void onButtonUp();
    void onInputPath();
};

#endif
