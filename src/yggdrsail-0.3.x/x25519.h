#ifndef X25519_H
#define X25519_H

#include <stdint.h>
#include <vector>

#define KEYSIZE 32

typedef uint8_t key25519[KEYSIZE];
typedef uint64_t fe25519[5];

struct ge25519
{
	fe25519 X;
	fe25519 Y;
	fe25519 Z;
	fe25519 T;
};

class keys_block
{
public:
	keys_block(int size);
	void calculate_public_keys(const uint8_t random_bytes[KEYSIZE]);
	void get_public_key(key25519 public_key, int index) const;
	void get_private_key(key25519 private_key, int index) const;

private:
	int key_bits[256];
	std::vector<ge25519> points;
	std::vector<fe25519> temp_z;
	std::vector<ge25519> state;
};

class base_powers
{
public:
	base_powers();
	const ge25519& get(int index);

private:
	ge25519 data[255];
};

#endif
