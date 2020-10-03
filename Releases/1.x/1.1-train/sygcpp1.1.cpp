/**
 * Thanks PurpleI2P Project for support to writing that code.
 *
 * IRC: irc.ilita.i2p port 6667 || 303:60d4:3d32:a2b9::3 port 16667
 * general channels: #ru and #howtoygg
 *
 * git: notabug.org/acetone/SimpleYggGen-CPP
 *
 * acetone, 2020 (c) GPLv3
 *
 */

#include <openssl/evp.h> // библиотека OpenSSL
#include <openssl/sha.h>
#include <openssl/bn.h>
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

////////////////////////////////////////////////// Заставка

void intro()
{
	std::cout << std::endl
	<< " +--------------------------------------------------------------------------+" << std::endl
	<< " |                        SimpleYggGen C++ 1.1-train                        |" << std::endl
	<< " |                     OpenSSL inside: x25519 -> sha512                     |" << std::endl
	<< " |                   notabug.org/acetone/SimpleYggGen-CPP                   |" << std::endl
	<< " |                                                                          |" << std::endl
	<< " |               developers:  acetone, orignal, lialh4, R4SAS               |" << std::endl
	<< " |                              GPLv3 (c) 2020                              |" << std::endl
	<< " +";
	for(int i = 0; i < 74; ++i)
	{
		std::cout << "-";
		std::cout.flush();
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	std::cout << "+" << std::endl;
}

////////////////////////////////////////////////// Суть вопроса

#define KEYSIZE 32
std::mutex mtx;

int conf_proc = 100;
int conf_mode = 100;
int conf_log = 100;
int conf_high = 100;
std::string conf_search;
std::string log_file;

uint64_t totalcount = 0;        // счетчик основного цикла
uint64_t totalcountfortune = 0; // счетчик нахождений
bool newline = true;            // используется для вывода счетчика

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
			std::cerr << " Invalid config found!\n"
			          << " Check it:\n"
			          << " - 2 field - mining mode: 0 or 1 only\n"
			          << " - 3 field - logging mode: 0 or 1 only\n"
			          << " - 5 field - string to search by name: a-z, 0-9 and ':' symbols only\n"
			          << " Remove or correct sygcpp.conf and run SYG again."<< std::endl;
			return -2;
		}

		unsigned int processor_count = std::thread::hardware_concurrency(); // кол-во процессоров
		if(conf_proc > (int)processor_count)
			conf_proc = (int)processor_count;
	}

	// вывод конфигурации на экран
	std::cout << " Threads: " << conf_proc << ", ";

	if(conf_mode == 1)
		std::cout << "search high addresses (" << conf_high << "), ";
	else
		std::cout << "search by name (" << conf_search << "), ";

	if(conf_log == 1)
		std::cout << "logging to text file." << std::endl;
	else
		std::cout << "console log only." << std::endl;

	return 0;
}

void testoutput()
{
	if(conf_log == 1) // проверка включено ли логирование
	{
		if(conf_mode == 1)
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

BoxKeys getKeyPair()
{
	BoxKeys keys;
	size_t len = KEYSIZE;

	EVP_PKEY_CTX * Ctx;
	EVP_PKEY * Pkey = nullptr;
	Ctx = EVP_PKEY_CTX_new_id (NID_X25519, NULL);

	EVP_PKEY_keygen_init (Ctx);
	EVP_PKEY_keygen (Ctx, &Pkey);

	EVP_PKEY_get_raw_public_key (Pkey, keys.PublicKey, &len);
	EVP_PKEY_get_raw_private_key (Pkey, keys.PrivateKey, &len);

	EVP_PKEY_CTX_free(Ctx);
	EVP_PKEY_free(Pkey);

	return keys;
}

int getOnes(const unsigned char HashValue[SHA512_DIGEST_LENGTH])
{
	bool done = false;
	int lOnes = 0; // кол-во лидирующих единиц

	std::vector<std::bitset<8>> bytes; // вектор с однобайтовыми битсетами (двумерный массив)
	for(int i = 0; i < 32; ++i)        // всего 32 байта, т.к. лидирующих единиц больше быть не может (32*8 = 256 бит, а ff = 255)
		bytes.push_back(HashValue[i]); // вставка в вектор с битсетами одного i-того байта хэша

	for(auto vector_count = bytes.begin(); vector_count != bytes.end() && !done; vector_count++)
	{
		for(int i = 7; i >= 0 && !done; --i)
		{
			if((*vector_count)[i] == 1) // обращение к i-тому элементу битсета
				++lOnes;
			if((*vector_count)[i] == 0)
				done = true;
		}
	}
	return lOnes;
}

std::string getAddress(unsigned char HashValue[SHA512_DIGEST_LENGTH])
{
	// функция "портит" массив хеша, т.к. копирование массива не происходит
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

	std::string address;
	bool shortadd = false;
	std::stringstream ss(address);
	ss << 0x02 << std::setw(2) << std::setfill('0') << std::hex << lErase - 1 << ":";
	// 2 - константа подсети Yggdrasil, второй байт - кол-во лидирующих единиц в хешэ

	for(int i = 0; i < 14; ++i)
	{
		if(i % 2 == 0) // если работаем с первым байтом секции
		{
			if(HashValue[i] == 0) // если байт нулевой
			{
				if(HashValue[i+1] == 0) // если следующий байт нулевой
				{
					if(HashValue[i+2] == 0 && i+2 < 13 && HashValue[i+3] == 0 && i+3 <= 13 && !shortadd)
					{
						ss << ":";
						i += 3;
						shortadd = true;
						continue;
					} else {
						ss << "0";
						++i;
					}
				}
			} else {
				ss << std::hex << (int)HashValue[i];
			}
		} else { // если работаем со вторым байтом секции
			if(HashValue[i-1] == 0) // если предыдущий первый байт был нулевой, нули сокращаем
				ss << std::hex << (int)HashValue[i];
			else
				ss << std::setw(2) << std::setfill('0') << std::hex << (int)HashValue[i];
		}
		if(i != 13 && i % 2 != 0) // не выводим двоеточие в конце адреса и после первого байта секции
			ss << ":";
	}
	return ss.str();
}

void getConsoleLog()
{
	mtx.lock();
	++totalcount;
	if(totalcount % 250000 == 0)
	{
		if(newline)
		{
			std::cout << std::endl;
			newline = false;
		}
		std::time_t realtime = std::time(NULL);

		std::cout << " # count [ " << std::dec << std::setfill('.') << std::setw(19) << totalcount << " ] [ "
		          << std::setw(15) << totalcountfortune << " ] " << std::asctime(std::localtime(&realtime));
		std::cout.flush();
	}
	mtx.unlock();
}

void highminer()
{
	unsigned char HashValue[SHA512_DIGEST_LENGTH];

	uint8_t PublicKeyBest[KEYSIZE];
	uint8_t PrivateKeyBest[KEYSIZE];

	while(true)
	{
		BoxKeys myKeys = getKeyPair();
		SHA512(myKeys.PublicKey, KEYSIZE, HashValue);
		int newones = getOnes(HashValue);

		if(newones > conf_high) // сохранение лучших ключей
		{
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

			if(conf_log == 1) // запись в файл
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
	unsigned char HashValue[SHA512_DIGEST_LENGTH];

	uint8_t PublicKeyBest[KEYSIZE];
	uint8_t PrivateKeyBest[KEYSIZE];

	while(true)
	{
		BoxKeys myKeys = getKeyPair();
		SHA512(myKeys.PublicKey, KEYSIZE, HashValue);
		std::string tempstr = getAddress(HashValue);

		if(tempstr.find(conf_search.c_str()) != std::string::npos) // сохранение найденных ключей
		{
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

			if(conf_log == 1) // запись в файл
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
		std::cerr << "Error code: " << configcheck << std::endl;
		system("PAUSE");
		return configcheck;
	}

	testoutput();
	if(conf_mode == 1) // запуск соответствующего режима майнинга
	{
		std::thread * threads[conf_proc];
		for(int i = 0; i < conf_proc; ++i)
			threads[i] = new std::thread(highminer);

		for(int i = 0; i < conf_proc - 1; ++i)
			threads[i]->detach();

		threads[conf_proc-1]->join(); // "ждем" последний трэд, бесконечное ожидание
	}
	else
	{
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
