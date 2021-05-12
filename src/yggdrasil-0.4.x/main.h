#ifndef MAIN_H
#define MAIN_H

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#ifdef _WIN32            // преобразование в IPv6
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

const size_t KEYSIZE = 32;
const size_t ADDRIPV6 = 16;
typedef std::array<uint8_t, KEYSIZE> Key;
typedef std::array<uint8_t, ADDRIPV6> Address;

struct BoxKeys
{
        Key PublicKey;
        Key PrivateKey;
};

BoxKeys getKeyPair();
void getRawAddress(int lErase, Key PublicKey, Address& rawAddr);
Key bitwiseInverse(const Key& key);
int getOnes(const Key value);
std::string getAddress(const uint8_t * rawAddr);
std::string hexArrayToString(const uint8_t* bytes, int length);
std::string keyToString(const Key key);

#endif // MAIN_H
