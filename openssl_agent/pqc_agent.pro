QT += core gui widgets
CONFIG += c++17 console
CONFIG -= app_bundle

TEMPLATE = app
TARGET = pqc_agent

SOURCES += src/main.cpp \
           src/pqc_agent.cpp

HEADERS += src/pqc_agent.h

FORMS += src/pqc_agent.ui
