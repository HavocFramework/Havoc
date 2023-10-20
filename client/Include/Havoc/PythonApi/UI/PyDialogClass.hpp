#ifndef HAVOC_PYDIALOGCLASS_H
#define HAVOC_PYDIALOGCLASS_H

#include <UserInterface/HavocUI.hpp>
#include <global.hpp>

#include <QVBoxLayout>
#include <QScrollArea>
#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>
#include <QCalendarWidget>
#include <QDial>
#include <QSlider>

typedef struct
{

    QDialog*        window;
    QVBoxLayout*    layout;
    QScrollArea*    scroll;
    QWidget*        root;
    QVBoxLayout*    root_layout;

} PyDialogQWindow, *PPyDialogQWindow;

typedef struct
{
    PyObject_HEAD

    // Demon Info
    char* title;
    PPyDialogQWindow DialogWindow;

} PyDialogClass, *PPyDialogClass;

extern PyTypeObject PyDialogClass_Type;

void        DialogClass_dealloc( PPyDialogClass self );
PyObject*   DialogClass_new( PyTypeObject *type, PyObject *args, PyObject *kwds );
int         DialogClass_init( PPyDialogClass self, PyObject *args, PyObject *kwds );

// Methods

PyObject*   DialogClass_exec( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_close( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_clear( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addLabel( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addButton( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addCheckbox( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addCombobox( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addLineedit( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addCalendar( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_replaceLabel( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addImage( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addDial( PPyDialogClass self, PyObject *args );
PyObject*   DialogClass_addSlider( PPyDialogClass self, PyObject *args );

#endif
