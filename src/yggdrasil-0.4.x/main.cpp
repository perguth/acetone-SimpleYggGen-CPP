/*
 * Address miner for Yggdrsail 0.4.x and higher.
 * The main part of the code is taken from the previous generation
 * of the miner for the 0.3.x and earlier Yggdrasil's branch.
 *
 * developers team, 2021 (c) GPLv3
 */

#include "main.h"

BoxKeys getKeyPair()
{
    BoxKeys keys;
    size_t len = KEYSIZE;

    // https://github.com/PurpleI2P/i2pd/blob/openssl/libi2pd/Signature.h#L357
    EVP_PKEY * pkey = nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_ED25519, NULL);

    EVP_PKEY_keygen_init (pctx);
    EVP_PKEY_keygen (pctx, &pkey);
    EVP_PKEY_CTX_free (pctx);

    EVP_PKEY_get_raw_public_key (pkey, keys.PublicKey.data(), &len);
    EVP_PKEY_get_raw_private_key (pkey, keys.PrivateKey.data(), &len);

    EVP_PKEY_free (pkey);

    return keys;
}

void getRawAddress(int lErase, Key PublicKey, Address& rawAddr)
{
    ++lErase; // лидирующие единицы + первый ноль

    int bitsToShift = lErase % 8;
    int start = lErase / 8;

    for(int i = start; i < start + 15; ++i)
    {
        PublicKey[i] <<= bitsToShift;
        PublicKey[i] |= (PublicKey[i + 1] >> (8 - bitsToShift));
    }

    rawAddr[0] = 0x02;
    rawAddr[1] = lErase - 1;
    for (int i = 0; i < 14; ++i)
        rawAddr[i + 2] = PublicKey[i+start];
}

Key bitwiseInverse(const Key& key)
{
    Key inverted;
    for(size_t i = 0; i < key.size(); ++i)
        inverted[i] = ~key[i];

    return inverted;
}

int getOnes(const Key value)
{
    const int map[8] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
    int lOnes = 0; // кол-во лидирующих единиц

    for (int i = 0; i < 17; ++i) // 32B(ключ) - 15B(IPv6 без 0x02) = 17B(возможных лидирующих единиц)
    {
        for (int j = 0; j < 8; ++j)
        {
            if (value[i] & map[j]) ++lOnes;
            else return lOnes;
        }
    }
    return 0; // никогда не случится
}

std::string getAddress(const uint8_t * rawAddr)
{
    char ipStrBuf[46];
    inet_ntop(AF_INET6, rawAddr, ipStrBuf, 46);
    return std::string(ipStrBuf);
}

std::string hexArrayToString(const uint8_t* bytes, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[i];
    return ss.str();
}

std::string keyToString(const Key key)
{
    return hexArrayToString(key.data(), KEYSIZE);
}

int main()
{
    BoxKeys keys = getKeyPair();

    std::cout << "Public:  " << std::hex << keyToString(keys.PublicKey) << std::endl;
    std::cout << "Private: " << std::hex << keyToString(keys.PrivateKey) << keyToString(keys.PublicKey) << std::endl
              << std::endl;

    Key invKey = bitwiseInverse(keys.PublicKey);
    int leads = getOnes(invKey);

    Address rawAddr;
    getRawAddress(leads, invKey, rawAddr);

    std::cout << "Address: " << getAddress(rawAddr.data()) << std::endl;

    return 0;
}
