/**
 * Thanks PurpleI2P Project for support to writing that code.
 *
 * IRC: irc.ilita.i2p port 6667 || 303:60d4:3d32:a2b9::3 port 16667
 * general channels: #ru and #howtoygg
 *
 * git: notabug.org/acetone/SimpleYggGen-CPP
 *
 * developers:  acetone, lialh4, orignal, R4SAS, Vort
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
#include <mutex>
#include <chrono>        // для вычисления скорости
#include <ctime>

#ifdef _WIN32            // преобразование в IPv6
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#include "x25519.h"

#define BLOCKSIZE 10000


//#define SELF_CHECK


////////////////////////////////////////////////// Заставка

void intro()
{
	std::cout <<
		std::endl <<
		" +--------------------------------------------------------------------------+" << std::endl <<
		" |                        SimpleYggGen C++  3.0-Vort                        |" << std::endl <<
		" |               magic and libsodium inside: x25519 -> sha512               |" << std::endl <<
		" |                   notabug.org/acetone/SimpleYggGen-CPP                   |" << std::endl <<
		" |                                                                          |" << std::endl <<
		" |             developers:  Vort, acetone, R4SAS, lialh4, orignal           |" << std::endl <<
		" |                               GPLv3 (c) 2020                             |" << std::endl <<
		" +--------------------------------------------------------------------------+" << std::endl <<
		std::endl;
}

////////////////////////////////////////////////// Суть вопроса

std::mutex mtx;

int conf_proc = 0;
int conf_mode = 0;
int conf_log  = 0;
int conf_high = 0;
std::string conf_search;
std::string log_file;

std::time_t sygstartedin = std::time(NULL); // для вывода времени работы

int countsize = 0;               // определяет периодичность вывода счетчика
uint64_t block_count = 0;        // количество вычисленных блоков
uint64_t totalcountfortune = 0;  // счетчик нахождений
std::chrono::steady_clock::duration blocks_duration(0);

int config()
{
	std::ifstream conffile ("sygcpp.conf");

	if(!conffile) // проверка наличия конфига
	{
		std::cout << " Configuration file not found..." << std::endl;
		conffile.close();
		std::ofstream newconf ("sygcpp.conf"); // создание конфига
		if(!newconf)
		{
			std::cerr << " Config (sygcpp.conf) creation failed :(" << std::endl;
			return -1;
		}
		newconf << "1 0 1 9 ::\n"
		        << "| | | | ^Pattern for search by name.\n"
		        << "| | | ^Start position for high addresses search.\n"
		        << "| | ^Logging mode (0 - console output only, 1 - log to file).\n"
		        << "| ^Mining mode (0 - by name, 1 - high address).\n"
		        << "^Count of thread (mining streams).\n\n"
		        << "Parameters are separated by spaces.";
		newconf.close();
		std::ifstream conffile ("sygcpp.conf");
		if(conffile)
			std::cout << " Config successfully created :)" << std::endl;
		config();
		return 0;
	} else {
		conffile >> conf_proc >> conf_mode >> conf_log >> conf_high >> conf_search;
		conffile.close();
		if(conf_mode > 1 || conf_mode < 0 || conf_log > 1 || conf_log < 0 || conf_high < 0) // проверка полученных значений
		{
			std::cerr << " Invalid config found! Check it:\n";

			if(conf_mode > 1 || conf_mode < 0)
				std::cerr << " - field #2 - mining mode: 0 or 1 only\n";
			if(conf_log > 1 || conf_log < 0)
				std::cerr << " - field #3 - logging mode: 0 or 1 only\n";
			if(conf_high < 0)
				std::cerr << " - field #4 - start position for high address search (default 9)\n";

			    std::cerr << " Remove or correct sygcpp.conf and run SYG again."<< std::endl;
			return -2;
		}

		unsigned int processor_count = std::thread::hardware_concurrency(); // кол-во процессоров
		if (conf_proc > (int)processor_count)
			conf_proc = (int)processor_count;
		countsize = 800 << __bsrq(conf_proc);
	}

	// вывод конфигурации на экран
	std::cout << " Threads: " << conf_proc << ", ";

	if(conf_mode)
		std::cout << "search high addresses (" << conf_high << "), ";
	else
		std::cout << "search by name (" << conf_search << "), ";

	if(conf_log)
		std::cout << "logging to text file." << std::endl;
	else
		std::cout << "console log only." << std::endl;

	std::cout << std::endl;
	return 0;
}

void testoutput()
{
	if(conf_log) // проверка включено ли логирование
	{
		if(conf_mode)
			log_file = "syg-high.txt";
		else
			log_file = "syg-byname.txt";

		std::ifstream test(log_file);
		if(!test) // проверка наличия выходного файла
		{
			test.close();
			std::ofstream output(log_file);
			output << "**************************************************************************\n"
			       << "Change EncryptionPublicKey and EncryptionPrivateKey to your yggdrasil.conf\n"
			       << "Windows: C:\\ProgramData\\Yggdrasil\\yggdrasil.conf\n"
			       << "Debian: /etc/yggdrasil.conf\n\n"
			       << "Visit HowTo.Ygg wiki for more information (russian language page):\n"
			       << "http://[300:529f:150c:eafe::6]/doku.php?id=yggdrasil:simpleygggen_cpp\n"
			       << "**************************************************************************\n";
			output.close();
		} else test.close();
	}
}

int getOnes(const unsigned char HashValue[crypto_hash_sha512_BYTES])
{
	int lOnes = 0; // кол-во лидирующих единиц
	for (int i = 0; i < 32; ++i) // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
	{
		std::bitset<8> bits(HashValue[i]);
		for (int i = 7; i >= 0; --i)
		{
			if (bits[i] == 1) // обращение к i-тому элементу битсета
				++lOnes;
			else
				return lOnes;
		}
	}
	return -1; // это никогда не случится
}

std::string getAddress(unsigned char HashValue[crypto_hash_sha512_BYTES])
{
	// функция "портит" массив хэша, т.к. копирование массива не происходит
	int lErase = getOnes(HashValue) + 1; // лидирующие единицы и первый ноль

	bool changeit = false;
	int bigbyte = 0;

	for(int j = 0; j < lErase; ++j) // побитовое смещение
	{
		for(int i = 63; i >= 0; --i)
		{
			if(bigbyte == i+1) // предыдущий байт требует переноса
				changeit = true;

			if(HashValue[i] & 0x80)
				bigbyte = i;

			HashValue[i] <<= 1;

			if(changeit)
			{
				HashValue[i] |= 0x01;
				changeit = false;
			}
		}
	}

	uint8_t ipAddr[16];
	ipAddr[0] = 0x02;
	ipAddr[1] = lErase - 1;
	for (int i = 0; i < 14; ++i)
		ipAddr[i + 2] = HashValue[i];

	char ipStrBuf[46];
	inet_ntop(AF_INET6, ipAddr, ipStrBuf, 46);
	return std::string(ipStrBuf);
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
		int khs = conf_proc * countsize * BLOCKSIZE / df.count();
		std::cout <<
			" kH/s: [" << std::setw(7) << std::setfill('_') << khs <<
			"] Total: [" << std::setw(19) << block_count * BLOCKSIZE <<
			"] Found: [" << std::setw(3) << totalcountfortune <<
			"] Uptime: " << timedays << ":" << std::setw(2) << std::setfill('0') <<
			timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds << std::endl;
	}
}

std::string keyToString(key25519 key)
{
	std::stringstream ss;
	for (int i = 0; i < KEYSIZE; ++i)
		ss << std::setw(2) << std::setfill('0') << std::hex << (int)key[i];
	return ss.str();
}

void logKeys(std::string address, key25519 publicKey, key25519 privateKey)
{
	std::cout << std::endl;
	std::cout << " Address:    " << address << std::endl;
	std::cout << " PublicKey:  " << keyToString(publicKey) << std::endl;
	std::cout << " PrivateKey: " << keyToString(privateKey) << std::endl;
	std::cout << std::endl;

	if (conf_log) // запись в файл
	{
		std::ofstream output(log_file, std::ios::app);
		output << std::endl;
		output << "Address:              " << address << std::endl;
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
	crypto_hash_sha512(sha512_hash, public_key, KEYSIZE);
	std::string address = getAddress(sha512_hash);

	logKeys(address, public_key, private_key);
	++totalcountfortune;
}

template <int T>
void miner_thread()
{
	key25519 public_key;
	keys_block block(BLOCKSIZE);
	uint8_t random_bytes[KEYSIZE];
	uint8_t sha512_hash[crypto_hash_sha512_BYTES];
	for (;;)
	{
		auto start_time = std::chrono::steady_clock::now();

		int fortune_key_index = -1;
		randombytes(random_bytes, KEYSIZE);
		block.calculate_public_keys(random_bytes);
		for (int i = 0; i < BLOCKSIZE; i++)
		{
			block.get_public_key(public_key, i);
			crypto_hash_sha512(sha512_hash, public_key, KEYSIZE);

			if (T == 1) // high mining
			{
				int newones = getOnes(sha512_hash);
				if (newones > conf_high)
				{
					conf_high = newones;
					fortune_key_index = i;
				}
			}
			else // name mining
			{
				if (getAddress(sha512_hash).find(
					conf_search.c_str()) != std::string::npos)
				{
					fortune_key_index = i;
					break; // можно использовать только один ключ из блока
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

#ifdef SELF_CHECK
void selfCheck()
{
	std::cout << "Self-check started." << std::endl;

	for (int i = 0; i < 17; i++)
	{
		int block_size = 1 << i;

		keys_block block(block_size);
		uint8_t random_bytes[KEYSIZE];
		randombytes(random_bytes, KEYSIZE);
		block.calculate_public_keys(random_bytes);

		key25519 public_key1;
		key25519 public_key2;
		key25519 private_key;
		for (int j = 0; j < block_size; j++)
		{
			block.get_public_key(public_key1, j);
			block.get_private_key(private_key, j);
			crypto_scalarmult_curve25519_base(public_key2, private_key);
			if (memcmp(public_key1, public_key2, KEYSIZE) != 0)
			{
				std::cout << "!!! Self-check failed !!!" << std::endl;
				std::cout << " PrivateKey: " << keyToString(private_key) << std::endl;
				std::cout << " PublicKey1: " << keyToString(public_key1) << std::endl;
				std::cout << " PublicKey2: " << keyToString(public_key2) << std::endl;
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
#endif

// ------------------------------------------------------
int main()
{
	intro();

#ifdef SELF_CHECK
	selfCheck();
	return 0;
#endif

	int configcheck = config();
	if(configcheck < 0) // функция получения конфигурации
	{
		std::cerr << " Error code: " << configcheck << std::endl << std::endl;
		system("PAUSE");
		return configcheck;
	}

	testoutput();

	std::thread* lastThread;
	for (int i = 0; i < conf_proc; i++)
		lastThread = new std::thread(conf_mode ? miner_thread<1> : miner_thread<0>);
	lastThread->join();

	std::cerr << "SYG has stopped working unexpectedly! Please, report about this." << std::endl;
	system("PAUSE");
	return -420;
}
