cmake_minimum_required( VERSION 3.15 )
project( Havoc )

set( CMAKE_CXX_STANDARD 20 )

set( CMAKE_AUTOMOC ON )
set( CMAKE_AUTORCC ON )
set( CMAKE_AUTOUIC ON )

set( CMAKE_CPP_COMPILER /usr/bin/x86_64-w64-mingw32-g++ )
set( CMAKE_C_COMPILER /usr/bin/x86_64-w64-mingw32-gcc )
set( CMAKE_CXX_FLAGS "-fpermissive" )

set( QT_VERSION 5 )
set( REQUIRED_LIBS Core Gui Widgets Network WebSockets Sql )
set( REQUIRED_LIBS_QUALIFIED Qt5::Core Qt5::Gui Qt5::Widgets Qt5::Network Qt5::WebSockets Qt5::Sql )

include_directories( Include )

if(APPLE)
    execute_process(COMMAND brew --prefix OUTPUT_VARIABLE BREW_PREFIX) #this because brew install location differs Intel/Apple Silicon macs
    string(STRIP ${BREW_PREFIX} BREW_PREFIX) #for some reason this happens: https://gitlab.kitware.com/cmake/cmake/-/issues/22404
    include_directories( "${BREW_PREFIX}/bin/python3.10" )
    include_directories( "${BREW_PREFIX}/Frameworks/Python.framework/Headers" )
elseif(UNIX)
    include_directories( "/usr/include/python3.10" )
endif()

set( APP_ICON_RESOURCE_WINDOWS "Data/Havoc.qrc" )

set( CMAKE_RUNTIME_OUTPUT_DIRECTORY .. )
set( CMAKE_INCLUDE_CURRENT_DIR ON )

set(
        HAVOC_INCLUDE

        # Misc
        Include/Havoc/Arguments.hpp
        Include/Havoc/Connector.hpp
        Include/Havoc/DBManager/DBManager.hpp
        Include/Havoc/DemonCmdDispatch.h
        Include/Havoc/Packager.hpp
        Include/Havoc/Havoc.hpp
        Include/Havoc/Service.hpp
        Include/Havoc/CmdLine.hpp

        # Python Api
        Include/Havoc/PythonApi/PythonApi.h
        Include/Havoc/PythonApi/Event.h
        Include/Havoc/PythonApi/HavocUi.h

        # Dialogs
        Include/UserInterface/Dialogs/Payload.hpp
        Include/UserInterface/Dialogs/About.hpp
        Include/UserInterface/Dialogs/Connect.hpp
        Include/UserInterface/Dialogs/Listener.hpp
        Include/UserInterface/Dialogs/Preferences.hpp

        # small wigets
        Include/UserInterface/SmallWidgets/EventViewer.hpp
        Include/UserInterface/SmallWidgets/EventViewer.hpp

        # widgets
        Include/UserInterface/Widgets/Chat.hpp
        Include/UserInterface/Widgets/CredentialsTable.hpp
        Include/UserInterface/Widgets/DemonInteracted.h
        Include/UserInterface/Widgets/ListenerTable.hpp
        Include/UserInterface/Widgets/ProcessList.hpp
        Include/UserInterface/Widgets/PythonScript.hpp
        Include/UserInterface/Widgets/SessionTable.hpp
        Include/UserInterface/Widgets/SessionGraph.hpp
        Include/UserInterface/Widgets/TeamserverTabSession.h
        Include/UserInterface/Widgets/ScriptManager.h
        Include/UserInterface/Widgets/LootWidget.h
        Include/UserInterface/Widgets/FileBrowser.hpp
        Include/UserInterface/Widgets/Teamserver.hpp

        Include/UserInterface/HavocUI.hpp
)

# Source for UI
set(
        HAVOC_UI

        Source/UserInterface/HavocUI.cpp
        Source/global.cpp

        # Dialogs
        Source/UserInterface/Dialogs/About.cpp
        Source/UserInterface/Dialogs/Connect.cpp
        Source/UserInterface/Dialogs/Listener.cpp
        Source/UserInterface/Dialogs/Payload.cpp
        Source/UserInterface/Dialogs/Preference.cpp

        # Widgets
        Source/UserInterface/Widgets/SessionTable.cpp
        Source/UserInterface/Widgets/SessionGraph.cpp
        Source/UserInterface/Widgets/Chat.cpp
        Source/UserInterface/Widgets/ListenersTable.cpp
        Source/UserInterface/Widgets/CredentialsTable.cpp
        Source/UserInterface/Widgets/DemonInteracted.cpp
        Source/UserInterface/Widgets/TeamserverTabSession.cpp
        Source/UserInterface/Widgets/PythonScript.cpp
        Source/UserInterface/Widgets/ScriptManager.cpp
        Source/UserInterface/Widgets/LootWidget.cpp
        Source/UserInterface/Widgets/FileBrowser.cpp
        Source/UserInterface/Widgets/Teamserver.cpp

        # SmallWidgets
        Source/UserInterface/SmallWidgets/EventViewer.cpp
        Source/UserInterface/Widgets/ProcessList.cpp Source/UserInterface/SmallWidgets/TextComplete.cpp
)

set(
        HAVOC_UTIL

        Source/Util/ColorText.cpp
        Source/Util/Base64.cpp
        Source/Util/Base.cpp
)

# Source for Havoc
set(
        HAVOC_SOURCE
        Source/Main.cpp

        # src/Havoc/Arguments/Arguments.cpp

        Source/Havoc/Packager.cpp
        Source/Havoc/Connector.cpp
        Source/Havoc/Service.cpp

        Source/Havoc/DBManger/DBManager.cpp
        Source/Havoc/DBManger/Credentials.cpp
        Source/Havoc/DBManger/Sessions.cpp
        Source/Havoc/DBManger/Teamserver.cpp
        Source/Havoc/DBManger/Scripts.cpp

        Source/Havoc/Demon/ConsoleInput.cpp
        Source/Havoc/Demon/CommandSend.cpp
        Source/Havoc/Demon/CommandOutput.cpp
        Source/Havoc/Demon/Commands.cpp

        Source/Havoc/PythonApi/PythonApi.cpp
        Source/Havoc/PythonApi/Havoc.cpp
        Source/Havoc/PythonApi/HavocUi.cpp
        Source/Havoc/PythonApi/PyDemonClass.cpp
        Source/Havoc/PythonApi/Event.cpp

        Source/Havoc/Havoc.cpp

        ${HAVOC_UI}
        Include/Havoc/PythonApi/PyAgentClass.hpp Source/Havoc/PythonApi/PyAgentClass.cpp Include/json.hpp)

add_executable( ${PROJECT_NAME} ${HAVOC_INCLUDE} ${HAVOC_SOURCE} ${HAVOC_UTIL} ${APP_ICON_RESOURCE_WINDOWS} Data/Havoc.rc )
add_definitions( -DQT_NO_DEBUG_OUTPUT )
# Boost libary
# set(Boost_USE_STATIC_LIBS OFF)
# set(Boost_USE_MULTITHREADED ON)
# set(Boost_USE_STATIC_RUNTIME OFF)
# find_package(Boost COMPONENTS program_options python)
# include_directories(${Boost_INCLUDE_DIRS})

set( Python_ADDITIONAL_VERSIONS )

if(APPLE)
  find_package(Python 3 COMPONENTS Interpreter Development REQUIRED)
  set(PYTHON_MAJOR $ENV{Python_VERSION_MAJOR})
  set(PYTHON_MINOR $ENV{Python_VERSION_MINOR})
  set(PYTHONLIBS_VERSION_STRING ${Python_VERSION})
  set(PYTHON_INCLUDE_DIR ${Python_INCLUDE_DIRS})
  set(PYTHON_LIBRARIES ${Python_LIBRARIES})
  message("Apple - Using Python:${Python_VERSION_MAJOR} - Libraries:${PYTHON_LIBRARIES} - IncludeDirs: ${PYTHON_INCLUDE_DIR}")
elseif(UNIX)
  find_package(PythonLibs 3 REQUIRED)
else()
  set(PYTHONLIBS_VERSION_STRING $ENV{PY_VERSION})
endif()

find_package( spdlog REQUIRED )
find_package( Qt${QT_VERSION} COMPONENTS ${REQUIRED_LIBS} REQUIRED )

target_link_libraries(
        ${PROJECT_NAME}
        ${REQUIRED_LIBS_QUALIFIED}
        ${PYTHON_LIBRARIES}
        # ${Boost_LIBRARIES}
        spdlog::spdlog
        spdlog::spdlog_header_only
)
