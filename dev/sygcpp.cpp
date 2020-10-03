/**
 *
 * IRC: irc.ilita.i2p port 6667 || 303:60d4:3d32:a2b9::3 port 16667
 * general channels: #ru and #howtoygg
 *
 * acetone (default) git: notabug.org/acetone/SimpleYggGen-CPP
 * Vort (member) git:     notabug.org/Vort/SimpleYggGen-CPP
 *
 * developers: Vort, acetone, R4SAS, lialh4, filarius, orignal
 * developers team, 2020 (c) GPLv3
 *
 */

#include <x86intrin.h>
#include <string.h>      // memcmp
#include <sodium.h>      // библиотека libsodium
#include <iostream>      // вывод на экран
#include <string>
#include <sstream>
#include <fstream>       // файловые потоки
#include <iomanip>       // форматированный вывод строк
#include <bitset>        // побитовое чтение
#include <vector>
#include <thread>        // многопоточность
#include <mutex>         // блокирование данных при многопоточности
#include <chrono>        // для вычисления скорости
#include <ctime>
#include <regex>         // регулярные выражения

#ifdef _WIN32            // преобразование в IPv6
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#include "x25519.h"
#include "sha512.h"
#include "cppcodec/base32_rfc4648.hpp"

#define BLOCKSIZE 10000

//#define SELF_CHECK // debug

void Intro()
{
	std::cout <<
		std::endl <<
		" +--------------------------------------------------------------------------+" << std::endl <<
		" |                   [ SimpleYggGen C++ 3.3+dev.version ]                   |" << std::endl <<
		" |                   X25519 -> SHA512 -> IPv6 -> Meshname                   |" << std::endl <<
		" |                   notabug.org/acetone/SimpleYggGen-CPP                   |" << std::endl <<
		" |                                                                          |" << std::endl <<
		" |                              GPLv3 (c) 2020                              |" << std::endl <<
		" +--------------------------------------------------------------------------+" << std::endl <<
		std::endl;
}

std::mutex mtx;

std::time_t sygstartedin = std::time(NULL); // для вывода времени работы

int countsize = 0;               // определяет периодичность вывода счетчика
uint64_t block_count = 0;        // количество вычисленных блоков
uint64_t totalcountfortune = 0;  // счетчик нахождений
bool newline = false;            // форматирует вывод после нахождения адреса
std::chrono::steady_clock::duration blocks_duration(0);

#include "basefiles.cpp"

int getOnes(const unsigned char HashValue[crypto_hash_sha512_BYTES])
{
	const int map[8] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
	int lOnes = 0; // кол-во лидирующих единиц
	for (int i = 0; i < 32; ++i) // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
	{
		for (int j = 0; j < 8; ++j)
		{
			if (HashValue[i] & map[j]) // сравниваем биты байта с таблицей единичек
				++lOnes;
			else
				return lOnes;
		}
	}
	return -421; // это никогда не случится
}

void getRawAddress(int lErase, unsigned char * HashValue, uint8_t * rawAddr) // ожидается 64 и 16 байт
{
	// функция портит массив хэша, вызывать повторно со старым массивом нельзя
	++lErase; // лидирующие единицы и первый ноль

	int bitshift = lErase % 8;
	int start = lErase / 8;
	
	for(int i = start; i < start+15; ++i)
	{
		HashValue[i] <<= bitshift;
		HashValue[i] |= (HashValue[i+1] >> (8-bitshift));
	}

	rawAddr[0] = 0x02;
	rawAddr[1] = lErase - 1;
	for (int i = 0; i < 14; ++i)
		rawAddr[i + 2] = HashValue[i+start];
}

std::string getAddress(const uint8_t * rawAddr)
{
	char ipStrBuf[46];
	inet_ntop(AF_INET6, rawAddr, ipStrBuf, 46);
	return std::string(ipStrBuf);
}

std::string getMeshname(const uint8_t * rawAddr)
{
	return std::string(cppcodec::base32_rfc4648::encode(rawAddr, 16));
}

void logStatistics()
{
	if (++block_count % countsize == 0)
	{
		auto timedays = (std::time(NULL) - sygstartedin) / 86400;
		auto timehours = ((std::time(NULL) - sygstartedin) - (timedays * 86400)) / 3600;
		auto timeminutes = ((std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600)) / 60;
		auto timeseconds = (std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600) - (timeminutes * 60);

		std::chrono::duration<double, std::milli> df = blocks_duration;
		blocks_duration = std::chrono::steady_clock::duration::zero();
		int khs = conf.proc * countsize * BLOCKSIZE / df.count();
		std::cout <<
			" kH/s: [" << std::setw(7) << std::setfill('_') << khs <<
			"] Total: [" << std::setw(19) << block_count * BLOCKSIZE <<
			"] Found: [" << std::setw(3) << totalcountfortune <<
			"] Time: [" << timedays << ":" << std::setw(2) << std::setfill('0') <<
			timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds << "]" << std::endl;
		newline = true;
	}
}

std::string hexArrayToString(const uint8_t* bytes, int length)
{
	std::stringstream ss;
	for (int i = 0; i < length; i++)
		ss << std::setw(2) << std::setfill('0') << std::hex << (int)bytes[i];
	return ss.str();
}

std::string keyToString(const key25519 key)
{
	return hexArrayToString(key, KEYSIZE);
}

std::string hashToString(const uint8_t hash[crypto_hash_sha512_BYTES])
{
	return hexArrayToString(hash, crypto_hash_sha512_BYTES);
}

void logKeys(uint8_t * raw, const key25519 publicKey, const key25519 privateKey)
{
	if(newline) // добавляем пустую строку на экране между счетчиком и новым адресом
	{
		std::cout << std::endl;
		newline = false;
	}
	if (conf.mesh)
		std::cout << " Domain:     " << getMeshname(raw) + ".meshname" << std::endl;
	std::cout << " Address:    " << getAddress(raw) << std::endl;
	std::cout << " PublicKey:  " << keyToString(publicKey) << std::endl;
	std::cout << " PrivateKey: " << keyToString(privateKey) << std::endl;
	std::cout << std::endl;

	if (conf.log) // запись в файл
	{
		std::ofstream output(conf.outputfile, std::ios::app);
		output << std::endl;
		if (conf.mesh)
			output << "Domain:               " << getMeshname(raw) + ".meshname" << std::endl;
		output << "Address:              " << getAddress(raw) << std::endl;
		output << "EncryptionPublicKey:  " << keyToString(publicKey) << std::endl;
		output << "EncryptionPrivateKey: " << keyToString(privateKey) << std::endl;
		output.close();
	}
}

void process_fortune_key(const keys_block& block, int index)
{
	if (index == -1)
		return;

	key25519 public_key;
	key25519 private_key;
	block.get_public_key(public_key, index);
	block.get_private_key(private_key, index);

	uint8_t sha512_hash[crypto_hash_sha512_BYTES];
	crypto_hash_sha512(sha512_hash, public_key);
	int ones = getOnes(sha512_hash);
	uint8_t raw[16];
	getRawAddress(ones, sha512_hash, raw);
	logKeys(raw, public_key, private_key);
	++totalcountfortune;
}

template <int T>
void miner_thread()
{
	key25519 public_key;
	keys_block block(BLOCKSIZE);
	uint8_t random_bytes[KEYSIZE];
	uint8_t sha512_hash[crypto_hash_sha512_BYTES];
	std::regex regx(conf.rgx_search, std::regex_constants::egrep);
	for (;;)
	{
		auto start_time = std::chrono::steady_clock::now();

		int fortune_key_index = -1;
		randombytes(random_bytes, KEYSIZE);
		block.calculate_public_keys(random_bytes);
		for (int i = 0; i < BLOCKSIZE; i++)
		{
			block.get_public_key(public_key, i);
			crypto_hash_sha512(sha512_hash, public_key);
			int newones = getOnes(sha512_hash);
			uint8_t rawAddr[16]; 
			getRawAddress(newones, sha512_hash, rawAddr);

			if (T == 0) // IPv6 pattern mining
			{
				if (getAddress(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos)
				{
					fortune_key_index = i;
					break; // можно использовать только один ключ из блока
				}
			}
			if (T == 1) // high mining
			{
				if (newones > conf.high)
				{
					conf.high = newones;
					fortune_key_index = i;
				}
			}
			if (T == 2) // pattern & high mining
			{
				if (getAddress(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos &&
					newones > conf.high)
				{
					conf.high = newones;
					fortune_key_index = i;
					break;
				}
			}
			if (T == 3) // IPv6 regexp mining
			{
				if (std::regex_search((getAddress(rawAddr)), regx))
				{
					fortune_key_index = i;
					break;
				}
			}
			if (T == 4) // meshname pattern mining
			{
				if (getMeshname(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos)
				{
					fortune_key_index = i;
					break; // можно использовать только один ключ из блока
				}
			}
			if (T == 5) // meshname regex mining
			{
				if (std::regex_search((getMeshname(rawAddr)), regx))
				{
					fortune_key_index = i;
					break;
				}
			}
		}
		auto stop_time = std::chrono::steady_clock::now();
		mtx.lock();
		blocks_duration += stop_time - start_time;
		process_fortune_key(block, fortune_key_index);
		logStatistics();
		mtx.unlock();
	}
}

#ifdef SELF_CHECK // debug
void selfCheck()
{
	std::cout << "Self-check started." << std::endl;

	for (int i = 0; i < 16; i++)
	{
		int block_size = 1 << i;

		keys_block block(block_size);
		uint8_t random_bytes[KEYSIZE];
		randombytes(random_bytes, KEYSIZE);
		block.calculate_public_keys(random_bytes);

		key25519 public_key1;
		key25519 public_key2;
		key25519 private_key;
		uint8_t sha512_hash1[crypto_hash_sha512_BYTES];
		uint8_t sha512_hash2[crypto_hash_sha512_BYTES];
		for (int j = 0; j < block_size; j++)
		{
			block.get_public_key(public_key1, j);
			block.get_private_key(private_key, j);
			crypto_scalarmult_curve25519_base(public_key2, private_key);
			crypto_hash_sha512(sha512_hash1, public_key2);
			crypto_hash_sha512(sha512_hash2, public_key2, KEYSIZE);
			if (memcmp(public_key1, public_key2, KEYSIZE) != 0 ||
				memcmp(sha512_hash1, sha512_hash2, crypto_hash_sha512_BYTES))
			{
				std::cout << "!!! Self-check failed !!!" << std::endl;
				std::cout << " PrivateKey:  " << keyToString(private_key) << std::endl;
				std::cout << " PublicKey1:  " << keyToString(public_key1) << std::endl;
				std::cout << " PublicKey2:  " << keyToString(public_key2) << std::endl;
				std::cout << " SHA512Hash1: " << hashToString(sha512_hash1) << std::endl;
				std::cout << " SHA512Hash2: " << hashToString(sha512_hash2) << std::endl;
				std::cout << "!!! Self-check failed !!!" << std::endl;
				return;
			}
			else
			{
				//std::cout << "    Self-check ok" << std::endl;
				//std::cout << " PrivateKey: " << keyToString(private_key) << std::endl;
			}
		}
	}
	std::cout << "Self-check finished." << std::endl;
}
#endif // debug

// ------------------------------------------------------
int main()
{
	Intro();

#ifdef SELF_CHECK
	selfCheck();
	return 0;
#endif

	int configcheck = config(); // функция получения конфигурации
	if(configcheck < 0)
	{
		std::cerr << " Error code: " << configcheck;
		std::this_thread::sleep_for(std::chrono::seconds(15));
		return configcheck;
	}
	
	DisplayConfig();
	testoutput();
	
	std::thread* lastThread;
	for (int i = 0; i < conf.proc; i++)
	{
		lastThread = new std::thread(
			conf.mode == 0 ? miner_thread<0> : 
			conf.mode == 1 ? miner_thread<1> : 
			conf.mode == 2 ? miner_thread<2> :
			conf.mode == 3 ? miner_thread<3> :
			conf.mode == 4 ? miner_thread<4> :
			miner_thread<5> 
		);
	}
	lastThread->join();

	std::cerr << "SYG has stopped working unexpectedly! Please, report about this.";
	std::this_thread::sleep_for(std::chrono::seconds(15));
	return -420;
}
