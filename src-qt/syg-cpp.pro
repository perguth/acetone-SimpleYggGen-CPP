QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
    main.cpp \
    miner.cpp \
    widget.cpp

HEADERS += \
    configure.h \
    miner.h \
    widget.h \

FORMS += \
    widget.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resources.qrc

LIBS += \
    -lsodium \
    -lpthread

win32 {
    LIBS += -lws2_32
    RC_FILE += ../src/windows/resource.rc
    OTHER_FILES += ../src/windows/resource.rc
}

