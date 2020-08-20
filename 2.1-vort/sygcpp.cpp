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
#include <chrono>        // для паузы в заставке
#include <ctime>

#ifdef _WIN32            // преобразование в IPv6
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
#endif

#define SODIUM_STATIC
#define KEYSIZE 32

////////////////////////////////////////////////// Заставка

void intro()
{
	std::cout << std::endl
	<< " +--------------------------------------------------------------------------+" << std::endl
	<< " |                        SimpleYggGen C++  2.1-vort                        |" << std::endl
	<< " |                altered libsodium inside: x25519 -> sha512                |" << std::endl
	<< " |                   notabug.org/acetone/SimpleYggGen-CPP                   |" << std::endl
	<< " |                                                                          |" << std::endl
	<< " |            developers:  acetone, lialh4, orignal, R4SAS, Vort            |" << std::endl
	<< " |                              GPLv3 (c) 2020                              |" << std::endl
	<< " +";
	for(int i = 0; i < 74; ++i)
	{
		std::cout << "-";
		std::cout.flush();
		std::this_thread::sleep_for(std::chrono::milliseconds(3));
	}
	std::cout << "+\n" << std::endl;
}

////////////////////////////////////////////////// Глобальные переменные

std::mutex mtx;

int conf_proc = 0;
int conf_mode = 0;
int conf_log  = 0;
int conf_high = 0;
std::string conf_search;
std::string log_file;

std::chrono::time_point<std::chrono::high_resolution_clock> startTime; // для вывода kH/s
double khstemp = 0.0;           // для подсчета килохешей
std::time_t sygstartedin = std::time(NULL); // для вывода времени работы

uint64_t totalcount = 0;        // счетчик основного цикла
uint64_t totalcountfortune = 0; // счетчик нахождений
int countsize = 0;              // определяет периодичность вывода счетчика
bool newline = true;            // используется для вывода счетчика: пустая строка после найденного адреса

////////////////////////////////////////////////// Суть вопроса

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
		if(conf_proc > (int)processor_count)
			conf_proc = (int)processor_count;
		if(conf_proc <= 2)
		{
			countsize = 250000;
			khstemp = 250000000.0;
		} else {
			countsize = 500000;
			khstemp = 500000000.0;
		}
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

struct BoxKeys
{
	uint8_t PublicKey[KEYSIZE];
	uint8_t PrivateKey[KEYSIZE];
};

extern int
crypto_scalarmult_curve25519_base_internal(
	unsigned char *q, const unsigned char *n);

BoxKeys getKeyPair()
{
	BoxKeys keys;
	randombytes(keys.PrivateKey, KEYSIZE);
	keys.PrivateKey[0] &= 248;
	keys.PrivateKey[KEYSIZE - 1] &= 127;
	keys.PrivateKey[KEYSIZE - 1] |= 64;
	crypto_scalarmult_curve25519_base_internal(keys.PublicKey, keys.PrivateKey);
	return keys;
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
	std::cerr << "Strange error in getOnes function!" << std::endl;
	system("PAUSE");
	return -3; // это случится только если будет найдено больше 256 единиц, а это невозможно
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

void getConsoleLog()
{
	mtx.lock();
	++totalcount;
	if(totalcount % countsize == 0)
	{
		if(newline)
		{
			std::cout << std::endl;
			newline = false;
		}

		auto stopTime = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stopTime - startTime);
		startTime = stopTime;
		float khs = khstemp / duration.count();

		auto timedays = (std::time(NULL) - sygstartedin) / 86400;
		auto timehours = ((std::time(NULL) - sygstartedin) - (timedays * 86400)) / 3600;
		auto timeminutes = ((std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600)) / 60;
		auto timeseconds = (std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600) - (timeminutes * 60);

		std::cout << " kH/s: [" << std::setw(7) << std::dec << std::fixed << std::setprecision(3)
		<< std::setfill('_') << khs << "] Total: [" << std::setw(19) << totalcount << "] Found: ["
		<< std::setw(3) << totalcountfortune << "] Uptime: " << timedays << ":" << std::setw(2) << std::setfill('0')
		<< timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds << std::endl;
	}
	mtx.unlock();
}

void highminer()
{
	unsigned char HashValue[crypto_hash_sha512_BYTES];

	uint8_t PublicKeyBest[KEYSIZE];
	uint8_t PrivateKeyBest[KEYSIZE];

	startTime = std::chrono::high_resolution_clock::now();
	while(true)
	{
		BoxKeys myKeys = getKeyPair();
		crypto_hash_sha512(HashValue, myKeys.PublicKey, KEYSIZE);
		int newones = getOnes(HashValue);

		if(newones > conf_high) // сохранение лучших ключей
		{
			std::right;
			conf_high = newones;
			for(int i = 0; i < KEYSIZE; ++i)
			{
				PublicKeyBest[i] = myKeys.PublicKey[i];
				PrivateKeyBest[i] = myKeys.PrivateKey[i];
			}

			std::string address = getAddress(HashValue);
			mtx.lock();
			std::cout << "\n Address:    " << address << std::endl;
			std::cout << " PublicKey:  ";
			for(int i = 0; i < 32; ++i)
			{
				std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PublicKeyBest[i];
			}
			std::cout << std::endl;

			std::cout << " PrivateKey: ";
			for(int i = 0; i < 32; ++i)
			{
				std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PrivateKeyBest[i];
			}
			std::cout << std::endl;

			if(conf_log) // запись в файл
			{
				std::ofstream output(log_file, std::ios::app);
				output << "\nAddress:              " << address << std::endl;
				output << "EncryptionPublicKey:  ";
				for(int i = 0; i < 32; ++i)
				{
					output << std::setw(2) << std::setfill('0') << std::hex << (int)PublicKeyBest[i];
				}
				output << std::endl;

				output << "EncryptionPrivateKey: ";
				for(int i = 0; i < 32; ++i)
				{
					output << std::setw(2) << std::setfill('0') << std::hex << (int)PrivateKeyBest[i];
				}
				output << std::endl;
				output.close();
			}
			++totalcountfortune;
			newline = true;
			mtx.unlock();
		}
		getConsoleLog();
	} // while(true)
}

void nameminer()
{
	unsigned char HashValue[crypto_hash_sha512_BYTES];

	uint8_t PublicKeyBest[KEYSIZE];
	uint8_t PrivateKeyBest[KEYSIZE];
	startTime = std::chrono::high_resolution_clock::now();
	while(true)
	{
		BoxKeys myKeys = getKeyPair();
		crypto_hash_sha512(HashValue, myKeys.PublicKey, KEYSIZE);
		std::string tempstr = getAddress(HashValue);

		if(tempstr.find(conf_search.c_str()) != std::string::npos) // сохранение найденных ключей
		{
			std::right;
			for(int i = 0; i < KEYSIZE; ++i)
			{
				PublicKeyBest[i] = myKeys.PublicKey[i];
				PrivateKeyBest[i] = myKeys.PrivateKey[i];
			}
			mtx.lock();
			std::cout << "\n Address:    " << tempstr << std::endl;
			std::cout << " PublicKey:  ";
			for(int i = 0; i < 32; ++i)
			{
				std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PublicKeyBest[i];
			}
			std::cout << std::endl;

			std::cout << " PrivateKey: ";
			for(int i = 0; i < 32; ++i)
			{
				std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PrivateKeyBest[i];
			}
			std::cout << std::endl;

			if(conf_log) // запись в файл
			{
				std::ofstream output(log_file, std::ios::app);
				output << "\nAddress:              " << tempstr << std::endl;
				output << "EncryptionPublicKey:  ";
				for(int i = 0; i < 32; ++i)
				{
					output << std::setw(2) << std::setfill('0') << std::hex << (int)PublicKeyBest[i];
				}
				output << std::endl;
				output << "EncryptionPrivateKey: ";
				for(int i = 0; i < 32; ++i)
				{
					output << std::setw(2) << std::setfill('0') << std::hex << (int)PrivateKeyBest[i];
				}
				output << std::endl;
				output.close();
			}
			++totalcountfortune;
			newline = true;
			mtx.unlock();
		}
		getConsoleLog();
	}
}

// ------------------------------------------------------
int main()
{
	intro();

	int configcheck = config();
	if(configcheck < 0) // функция получения конфигурации
	{
		std::cerr << " Error code: " << configcheck << std::endl << std::endl;
		system("PAUSE");
		return configcheck;
	}

	testoutput();
	if(conf_mode) // запуск соответствующего режима майнинга
	{
		std::thread * threads[conf_proc];
		for(int i = 0; i < conf_proc; ++i)
			threads[i] = new std::thread(highminer);

		for(int i = 0; i < conf_proc - 1; ++i)
			threads[i]->detach();

		threads[conf_proc-1]->join(); // "ждем" последний трэд, бесконечное ожидание
	} else {
		std::thread * threads[conf_proc];
		for(int i = 0; i < conf_proc; ++i)
			threads[i] = new std::thread(nameminer);

		for(int i = 0; i < conf_proc - 1; ++i)
			threads[i]->detach();

		threads[conf_proc-1]->join();
	}

	std::cerr << "SYG has stopped working unexpectedly! Please, report about this." << std::endl;
	system("PAUSE");
	return -420;
}
