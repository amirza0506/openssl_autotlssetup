QT += widgets core gui
CONFIG += c++17 release
TEMPLATE = app
TARGET = crypto_gui

# Source and header files
SOURCES += \
    src/gui_main.cpp \
    src/gui_mainwindow.cpp

HEADERS += \
    src/gui_mainwindow.h

FORMS += \
    src/gui_mainwindow.ui

# Include path
INCLUDEPATH += src \
    /usr/include/x86_64-linux-gnu/qt6 \
    /usr/include/x86_64-linux-gnu/qt6/QtWidgets \
    /usr/include/x86_64-linux-gnu/qt6/QtCore \
    /usr/include/x86_64-linux-gnu/qt6/QtGui

# Libraries
LIBS += -L$$PWD/lib -lcryptoapi -lcrypto -lssl
