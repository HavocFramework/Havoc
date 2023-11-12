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
#include <QCalendarWidget>
#include <QScrollArea>
#include <QDial>
#include <QSlider>

typedef struct
{

    QWidget*        window;
    QVBoxLayout*    layout;
    QScrollArea*    scroll;
    QWidget*        root;
    QVBoxLayout*    root_layout;

} PyWidgetQWindow, *PPyWidgetQWindow;

typedef struct
{
    PyObject_HEAD

    // Demon Info
    char* title;
    PPyWidgetQWindow WidgetWindow;

} PyWidgetClass, *PPyWidgetClass;

extern PyTypeObject PyWidgetClass_Type;

void        WidgetClass_dealloc( PPyWidgetClass self );
PyObject*   WidgetClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         WidgetClass_init( PPyWidgetClass self, PyObject *args, PyObject *kwds );

// Methods

PyObject* WidgetClass_addLabel( PPyWidgetClass self, PyObject *args );
PyObject* WidgetClass_setBottomTab( PPyWidgetClass self, PyObject *args );
PyObject* WidgetClass_setSmallTab( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addButton( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addCheckbox( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addCombobox( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addLineedit( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addCalendar( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_replaceLabel( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_clear( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addImage( PPyWidgetClass self, PyObject *args );
PyObject*   WidgetClass_addDial( PPyWidgetClass self, PyObject *args );
PyObject* WidgetClass_addSlider( PPyWidgetClass self, PyObject *args );

#endif
