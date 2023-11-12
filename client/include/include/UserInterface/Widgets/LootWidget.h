#ifndef HAVOC_LOOTWIDGET_H
#define HAVOC_LOOTWIDGET_H

#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QWidget>
#include <QLabel>
#include <QScrollArea>

class ImageLabel : public QWidget
{
public:
    QLabel*      label;
    QScrollArea* scrollArea;
    bool         key_ctrl = false;

    explicit ImageLabel(QWidget *parent = 0);
    const QPixmap* pixmap() const;

public slots:
    void setPixmap(const QPixmap&);

protected:
    void resizeEvent(QResizeEvent *);
    void keyReleaseEvent( QKeyEvent* event );
    bool event(QEvent *) override;
    void wheelEvent(QWheelEvent *ev);

public slots:
    void resizeImage();

};

class LootWidget : public QWidget
{
public:
    enum {
        LOOT_IMAGE,
        LOOT_FILE,
    };

    typedef struct
    {
        int     Type;
        QString AgentID;

        struct
        {

        } File;

        struct
        {
            QString     Name;
            QString     Date;
            QString     Size;
            QByteArray  Data;
        } Data;

    } LootData;
    std::vector<LootData> LootItems;

    QGridLayout*    gridLayout;

    QLabel*         LabelShow;
    QLabel*         LabelAgentID;

    QComboBox*      ComboShow;
    QComboBox*      ComboAgentID;

    QTableWidget*   ScreenshotTable;
    QTableWidget*   DownloadTable;

    QMenu*          ScreenshotMenu;
    QAction*        ScreenshotActionDownload;

    QSpacerItem*    horizontalSpacer;
    QStackedWidget* StackWidget;
    QWidget*        Screenshots;
    QGridLayout*    gridLayout_2;
    QSplitter*      splitter;
    ImageLabel*     ScreenshotImage;
    QWidget*        Downloads;
    QGridLayout*    gridLayout_3;

    QSpacerItem*    horizontalSpacer_2;

    LootWidget();
    void Reload();

    void AddSessionSection( const QString& DemonID );
    void AddScreenshot( const QString& DemonID, const QString& Name, const QString& Date, const QByteArray& Data );
    void AddDownload( const QString &DemonID, const QString &Name, const QString& Size, const QString &Date, const QByteArray &Data );
    void AddText( const QString& DemonID, const QString& Name, const QByteArray& Data );

    void ScreenshotTableAdd( const QString& Name, const QString& Date );
    void DownloadTableAdd( const QString& Name, const QString& Size, const QString& Date );

private Q_SLOTS:
    void onAgentChange( const QString& text );
    void onShowChange( const QString& text );
    void onScreenshotTableClick( const QModelIndex &index );
    void onDownloadTableClick( const QModelIndex &index );
    void onScreenshotTableCtx( const QPoint &pos );
};


#endif
