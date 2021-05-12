#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

void crypto_hash_sha512(uint8_t* out, const uint8_t* in);

#endif
