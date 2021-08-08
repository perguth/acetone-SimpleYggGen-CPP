#ifndef MINER_H
#define MINER_H

#include <QObject>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <QMutex>
#include <chrono>
#include <regex>
#include <sodium.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

#include "configure.h"
#include "widget.h"
#include "../src/cppcodec/base32_rfc4648.hpp"

const size_t KEYSIZE = 32;
const size_t ADDRIPV6 = 16;
typedef std::array<uint8_t, KEYSIZE> Key;
typedef std::array<uint8_t, ADDRIPV6> Address;

struct KeysBox
{
    Key PublicKey;
    Key PrivateKey;
};

class miner : public QObject
{
    Q_OBJECT

public:
    miner(Widget* w = 0);
    void startThreads();
    option conf;

signals:
    void setLog(QString, quint64, quint64, quint64);
    void setAddr(QString);

private:
    Widget *window;

    void testOutput();
    void logStatistics();
    void logKeys(const Address& raw, const KeysBox keys);
    std::string getBase32(const Address& rawAddr);
    std::string pickupStringForMeshname(std::string str);
    std::string pickupMeshnameForOutput(std::string str);
    std::string keyToString(const Key& key);
    std::string hexArrayToString(const uint8_t* bytes, int length);
    std::string getAddress(const Address& rawAddr);
    KeysBox getKeyPair();
    void getRawAddress(int lErase, Key InvertedPublicKey, Address& rawAddr);
    Key bitwiseInverse(const Key& key);
    int getOnes(const Key& value);
    void process_fortune_key(const KeysBox& keys);
    void miner_thread();

    std::time_t sygstartedin = std::time(NULL); // для вывода времени работы
    int countsize = 0;                          // определяет периодичность вывода счетчика
    quint64 totalcount = 0;                     // общий счетчик
    quint64 countfortune = 0;                   // счетчик нахождений
    std::chrono::steady_clock::duration blocks_duration;

    QMutex mtx;
};

#endif // MINER_H
