QT += core
QT -= gui

CONFIG += c++11 static

TARGET = OpenSSLDemo
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

INCLUDEPATH += ../../Libraries/openssl/include

LIBS += ../Libraries/openssl/libcrypto.a
LIBS += ../Libraries/openssl/libssl.a

SOURCES += main.cpp \
    cipher.cpp

HEADERS += \
    cipher.h
