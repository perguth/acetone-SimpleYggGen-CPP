TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp \

LIBS += \
        -lcrypto \
        -lpthread \
        -lws2_32

QMAKE_CXXFLAGS += \
        -O3

HEADERS += \
    main.h
