#ifndef SYGCPP_H
#define SYGCPP_H

#include <sodium.h> 
#include "x25519.h"
#include "sha512.h"

void Intro();
int getOnes(const unsigned char HashValue[crypto_hash_sha512_BYTES]);
void getRawAddress(int lErase, unsigned char * HashValue, uint8_t * rawAddr);
std::string getAddress(const uint8_t * rawAddr);
std::string getMeshname(const uint8_t * rawAddr);
std::string pickupStringForMeshname(std::string str);
std::string pickupMeshnameForOutput(std::string str);
std::string decodeMeshToIP(const std::string str);
void subnetCheck();
bool convertStrToRaw(std::string str, uint8_t * array);
void logStatistics();
std::string hexArrayToString(const uint8_t* bytes, int length);
std::string keyToString(const key25519 key);
std::string hashToString(const uint8_t hash[crypto_hash_sha512_BYTES]);
void logKeys(uint8_t * raw, const key25519 publicKey, const key25519 privateKey);
void process_fortune_key(const keys_block& block, int index);
void miner_thread();
void startThreads();
void error(int);
void help();

#endif /* SYGCPP_H */
