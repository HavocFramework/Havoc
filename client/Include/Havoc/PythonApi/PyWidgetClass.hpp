#ifndef HAVOC_PYWIDGETCLASS_H
#define HAVOC_PYWIDGETCLASS_H

#include <UserInterface/HavocUI.hpp>
#include <global.hpp>

#include <QVBoxLayout>
#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>

typedef struct
{
    PyObject_HEAD

    // Demon Info
    char* title;

} PyWidgetClass, *PPyWidgetClass;

typedef struct
{

    QDialog* window;
    QVBoxLayout* layout;

} PyWidgetQWindow, *PPyWidgetQWindow;

extern PyTypeObject PyWidgetClass_Type;

void        WidgetClass_dealloc( PPyWidgetClass self );
PyObject*   WidgetClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         WidgetClass_init( PPyWidgetClass self, PyObject *args, PyObject *kwds );

// Methods

// PyObject* DemonClass_( PPyDemonClass self, PyObject *args );

PyObject* WidgetClass_exec( PPyWidgetClass self, PyObject *args );
PyObject* WidgetClass_close( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addLabel( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addButton( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addCheckbox( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addCombobox( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addLineedit( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_ConsoleWrite( PPyWidgetClass self, PyObject *args );

#endif
