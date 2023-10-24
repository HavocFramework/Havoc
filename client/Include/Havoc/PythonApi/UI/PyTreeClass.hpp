#ifndef HAVOC_PYTREECLASS_H
#define HAVOC_PYTREECLASS_H

#include <UserInterface/HavocUI.hpp>
#include <global.hpp>

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QScrollArea>
#include <QTextEdit>
#include <QTextBrowser>
#include <QTreeView>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QSplitter>


typedef struct
{

    QWidget*            window;
    QHBoxLayout*        layout;
    QScrollArea*        scroll;
    QWidget*            root;
    QVBoxLayout*        root_layout;

    QStandardItemModel* item_model;
    QStandardItem*      root_item;
    QTreeView*          tree_view;
    QTextBrowser*          panel;
    QSplitter*          splitter;

} PyTreeQWindow, *PPyTreeQWindow;

typedef struct
{
    PyObject_HEAD

    // Demon Info
    char* title;
    PPyTreeQWindow TreeWindow;

} PyTreeClass, *PPyTreeClass;

extern PyTypeObject PyTreeClass_Type;

void        TreeClass_dealloc( PPyTreeClass self );
PyObject*   TreeClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         TreeClass_init( PPyTreeClass self, PyObject *args, PyObject *kwds );

// Methods

PyObject* TreeClass_setBottomTab( PPyTreeClass self, PyObject *args );
PyObject* TreeClass_setSmallTab( PPyTreeClass self, PyObject *args );
PyObject* TreeClass_addRow( PPyTreeClass self, PyObject *args );
PyObject* TreeClass_setItem( PPyTreeClass self, PyObject *args );
PyObject* TreeClass_setPanel( PPyTreeClass self, PyObject *args );

#endif
