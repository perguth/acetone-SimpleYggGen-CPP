#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <iostream>
#include <sstream>
#include <iomanip>

const size_t KEYSIZE = 32;
const size_t HASHSIZE = 64;

struct BoxKeys
{
        uint8_t PublicKey[KEYSIZE];
        uint8_t PrivateKey[KEYSIZE];
};

BoxKeys getKeyPair()
{
        BoxKeys keys;
        size_t len = KEYSIZE;

        EVP_PKEY * pkey = nullptr;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_ED25519, NULL);

        EVP_PKEY_keygen_init (pctx);
        EVP_PKEY_keygen (pctx, &pkey);

        EVP_PKEY_get_raw_public_key (pkey, keys.PublicKey, &len);
        EVP_PKEY_get_raw_private_key (pkey, keys.PrivateKey, &len);

        EVP_PKEY_CTX_free (pctx);
        EVP_PKEY_free (pkey);

        return keys;
}

std::string hexArrayToString(const uint8_t* bytes, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[i];
    return ss.str();
}

std::string keyToString(const uint8_t key[KEYSIZE])
{
    return hexArrayToString(key, KEYSIZE);
}

std::string hashToString(const uint8_t hash[HASHSIZE])
{
    return hexArrayToString(hash, HASHSIZE);
}

int main()
{
    BoxKeys keys;
    getKeyPair();
    unsigned char HashValue[SHA512_DIGEST_LENGTH];
    SHA512(keys.PublicKey, KEYSIZE, HashValue);
    std::cout << "Public EdDSA: " << std::hex << keyToString(keys.PublicKey) << std::endl;
    std::cout << "Private EdDSA: " << std::hex << hashToString(HashValue) << std::endl;
}
