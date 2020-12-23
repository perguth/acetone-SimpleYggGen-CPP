/**
 *
 * IRC: irc.acetone.i2p port 6667 || 324:9de3:fea4:f6ac::41 port 6667
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

// Если раскомментировано, высота адресов при майнинге не будет увеличиваться
#define DISABLE_INCREASE

void Intro()
{
	std::cout <<
		std::endl <<
		" +--------------------------------------------------------------------------+" << std::endl <<
		" |                   [ SimpleYggGen C++ 3.4.1-          ]                   |" << std::endl <<
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

/**
 * Функция getRawAddress получает 
 * 1) количество лидирующих единиц;
 * 2) массив хэша sha512;
 * 3) unit8_t-массив из 16 байт, куда будет записан "сырой" IPv6 адрес.
 * Подсчет единиц, как и другие возможные операции с массивом хэша необходимо 
 * осуществлять до обращения к данной функции, т.к. она не копирует исходный массив 
 * хэша, а портит его во время работы.
 * Под "сырым" адресом понимается байтовая информация, которая затем преобразуется
 * в стринг IPv6 и/или meshname-домен.
 */
void getRawAddress(int lErase, unsigned char * HashValue, uint8_t * rawAddr) // ожидается 64 и 16 байт
{
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

/**
 * pickupStringForMeshname получает человекочитаемую строку
 * типа fsdasdaklasdgdas.meshname и возвращает значение, пригодное
 * для поиска по meshname-строке: удаляет возможную доменную зону
 * (всё после точки и саму точку), а также делает все буквы
 * заглавными.
 */
std::string pickupStringForMeshname(std::string str)
{
	bool dot = false;
	std::string::iterator delend;
	for (auto it = str.begin(); it != str.end(); it++)
	{
		// делаем все буквы заглавными для обработки
		*it = toupper(*it);
		if(*it == '.') {
			delend = it;
			dot = true;
		}
	}
	if(dot)
		for (auto it = str.end(); it != delend; it--)
			str.pop_back(); // удаляем доменную зону
	return str;
}

/**
 * pickupMeshnameForOutput получает сырое base32 значение
 * типа KLASJFHASSA7979====== и возвращает meshname-домен:
 * делает все символы строчными и удаляет паддинги ('='),
 * а также добавляет доменную зону ".meshname".
 */
std::string pickupMeshnameForOutput(std::string str)
{
	for (auto it = str.begin(); it != str.end(); it++) // делаем все буквы строчными для вывода
		*it = tolower(*it);
	for (auto it = str.end(); *(it-1) == '='; it--)
		str.pop_back(); // удаляем символы '=' в конце адреса
	return str + ".meshname";
}

/**
 * decodeMeshToIP получает строковое значение сырого base32
 * кода типа KLASJFHASSA7979====== и возвращает IPv6-стринг.
 */
std::string decodeMeshToIP(const std::string str)
{
	std::string mesh = pickupStringForMeshname(str) + "======"; // 6 паддингов - норма для IPv6 адреса
	std::vector<uint8_t> raw = cppcodec::base32_rfc4648::decode(mesh);
	uint8_t rawAddr[16];
	for(int i = 0; i < 16; ++i)
		rawAddr[i] = raw[i];
	return std::string(getAddress(rawAddr));
}

void subnetCheck()
{
	if(conf.str_search[0] == '3') // замена 300::/64 на целевой 200::/7
		conf.str_search[0] = '2';
}

bool convertStrToRaw(std::string str, uint8_t * array)
{
	bool result = inet_pton(AF_INET6, str.c_str(), (void*)array);
	return result;
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
	if (conf.mesh) {
		std::string mesh = getMeshname(raw);
		std::cout << " Domain:     " << pickupMeshnameForOutput(mesh) << std::endl;
	}
	std::cout << " Address:    " << getAddress(raw) << std::endl;
	std::cout << " PublicKey:  " << keyToString(publicKey) << std::endl;
	std::cout << " PrivateKey: " << keyToString(privateKey) << std::endl;
	std::cout << std::endl;

	if (conf.log) // запись в файл
	{
		std::ofstream output(conf.outputfile, std::ios::app);
		output << std::endl;
		if (conf.mesh) {
		std::string mesh = getMeshname(raw);
		output << "Domain:               " << pickupMeshnameForOutput(mesh) << std::endl;
		}
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

	if (T == 4 || T == 5) // meshname pattern
	{
		std::string tmp = pickupStringForMeshname(conf.str_search);
		conf.str_search = tmp;
		
		for (auto it = conf.rgx_search.begin(); it != conf.rgx_search.end(); it++)
			*it = toupper(*it);
	} 
	std::regex regx(conf.rgx_search, std::regex_constants::egrep);
	if (T == 6) // subnet brute force
	{
		mtx.lock();
		if(!conf.sbt_alarm) // однократный вывод ошибки
		{
			subnetCheck();
			bool result = convertStrToRaw(conf.str_search, conf.raw_search);
			if(!result || (conf.str_search != getAddress(conf.raw_search)))
			{
				std::cerr << " WARNING: Your string [" << conf.str_search << "] converted to IP [" << 
				getAddress(conf.raw_search) << "]" << std::endl << std::endl;
			}
			conf.sbt_alarm = true;
		}
		mtx.unlock();
	}
	
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
			
			if (T == 0) // IPv6 pattern mining
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (getAddress(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos)
				{
					fortune_key_index = i;
					break; 
					/* Можно использовать только один ключ из блока, т.к.
					 * Vort, создавший используемую систему блоков ключей
					 * с мутациями, посчитал, что использование двух адресов
					 * из одного блока на разных серверах небезопасно:
					 * при компрометации одного сервера, второй компьютер
					 * этого администратора с мутированным ключом того же 
					 * блока также попадает под удар.
					 * При поиске высокого адреса несколько другой подход:
					 * блок не прерывается, т.к. с наибольшей вероятностью
					 * администратором будет использован только последний,
					 * самый высокий адрес из полученных.
					 * 	@acetone
					 */
				}
			}
			if (T == 1) // high mining
			{
				if (newones > conf.high)
				{
					#ifndef DISABLE_INCREASE
					conf.high = newones;
					#endif 
					
					fortune_key_index = i;
				}
			}
			if (T == 2) // pattern & high mining
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (newones > conf.high && getAddress(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos)
				{
					#ifndef DISABLE_INCREASE
					conf.high = newones;
					#endif 
					
					fortune_key_index = i;
					break;
				}
			}
			if (T == 3) // IPv6 regexp mining
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (std::regex_search((getAddress(rawAddr)), regx))
				{
					fortune_key_index = i;
					break;
				}
			}
			if (T == 4) // meshname & high
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (newones > conf.high)
				{
					if (std::regex_search((getAddress(rawAddr)), regx))
					{
						#ifndef DISABLE_INCREASE
						conf.high = newones;
						#endif 
						
						fortune_key_index = i;
						break;
					}
				}
			}
			if (T == 5) // meshname pattern mining
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (getMeshname(rawAddr).find(
					conf.str_search.c_str()) != std::string::npos)
				{
					fortune_key_index = i;
					break;
				}
			}
			if (T == 6) // meshname regexp mining
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				if (std::regex_search((getMeshname(rawAddr)), regx))
				{
					fortune_key_index = i;
					break;
				}
			}
			if (T == 7) // subnet brute force
			{
				uint8_t rawAddr[16];
				getRawAddress(newones, sha512_hash, rawAddr); // получаем адрес
				for(int z = 0; conf.raw_search[z] == rawAddr[z]; ++z)
				{
					if (z == conf.sbt_size)
						fortune_key_index = i;
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

void startThreads()
{
	std::thread* lastThread;
	for (int i = 0; i < conf.proc; ++i)
	{
		lastThread = new std::thread(
			conf.mode == 0 ? miner_thread<0> : 
			conf.mode == 1 ? miner_thread<1> : 
			conf.mode == 2 ? miner_thread<2> :
			conf.mode == 3 ? miner_thread<3> :
			conf.mode == 4 ? miner_thread<4> :
			conf.mode == 5 ? miner_thread<5> :
			conf.mode == 6 ? miner_thread<6> :
			miner_thread<7>
		);
	}
	lastThread->join();
}

void error()
{
	std::cerr << std::endl <<
	" +--------------------------------------------------------------------------+\n" <<
	" | Incorrect input, my dear friend. Use -help or -h for usage information.  |\n" <<
	" +--------------------------------------------------------------------------+\n";
}

void help()
{
	std::cout << std::endl << 
	" +--------------------------------------------------------------------------+\n"   <<
	" |                   Simple Yggdrasil address miner usage                   |\n"   <<
	" +--------------------------------------------------------------------------+\n"   <<
	" High addresses mining                 -high <start position> <threads count>\n"   <<
	"   example: -high 1f 1                       (start position 21f:*, 1 thread)\n"   <<
	" IPv6 pattern mining                     -ippattern <pattern> <threads count>\n"   <<
	"   example: -ippattern ace 2                        (search \"ace\", 2 threads)\n" <<
	" IPv6 pattern & high mining  -pahi <pattern> <start position> <threads count>\n"   <<
	"   example: -pahi ace 1a 4             (search \"ace\", start 21a:*, 4 threads)\n" <<
	" IPv6 regexp mining                         -ipreg \"<regexp>\" <threads count>\n" <<
	"   example: -ipreg \"^20[10-15].*.:a$\" 16                 (search, 16 threads)\n" <<
	" Meshname pattern mining               -meshpattern <pattern> <threads count>\n"   <<
	"   example: -meshpattern acetone 8              (search \"acetone\", 8 threads)\n" <<
	" Meshname regexp mining                   -meshreg \"<regexp>\" <threads count>\n" <<
	"   example: -meshreg \"^aimbot\" 1                           (search, 1 thread)\n" <<
	" Subnet brute force mining                      -brute <IPv6> <threads count>\n"   <<
	"   example: -brute 300:b24b:: 4                    (search subnet, 4 threads)\n"   <<
	" +--------------------------------------------------------------------------+\n"   <<
	" Convert IP to Meshname                                        -tomesh <IPv6>\n"   <<
	" Convert Meshname to IP                                        -toip <domain>\n"   <<
	" +--------------------------------------------------------------------------+\n"   <<
	" [!] Meshname domains use base32 (RFC4648) alphabet symbols.                 \n"   <<
	" [!] In meshname domain use \"=\" or \"===\" instead \".meshname\".          \n"   <<
	" [!] Subnet brute force mode understand \"3xx:\" and \"2xx:\" patterns.      \n"   <<
	" +--------------------------------------------------------------------------+\n"   <<
	" ALSO YOU CAN USE CONFIGURATION FILE INSTEAD PASSED PARAMETERS. JUST RUN SYG.\n";
	
}

int main(int argc, char *argv[])
{
	std::string p1;
	if(argv[1] != nullptr) 
	{
		///////////////////////////////// Доп. функции конвертации адресов
		p1 = argv[1];
		if (p1 == "-help" || p1 == "-h") {
			help();
			return 0;
		} else if (p1 == "-tomesh") { // преобразование IP -> Meshname
			if (argv[2] != nullptr) {
				convertStrToRaw(argv[2], conf.raw_search);
				std::string mesh = getMeshname(conf.raw_search);
				std::cout << std::endl <<
				pickupMeshnameForOutput(mesh) << std::endl;
				return 0;
			} else { error(); return -501; }
		} else if (p1 == "-toip") { // преобразование Meshname -> IP
			if (argv[2] != nullptr) {
				std::cout << std::endl <<
				decodeMeshToIP(argv[2]) << std::endl;
				return 0;
			} else { error(); return -502; }
		} 
		
		///////////////////////////////// Штатные функции
		  else if (p1 == "-high") { // high mining
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 1;
				std::istringstream ss(argv[2]);
				ss >> std::hex >> conf.high;
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -503; }
		} else if (p1 == "-ippattern") { // IPv6 pattern mining
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 0;
				conf.str_search = argv[2];
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -504; }
		} else if (p1 == "-pahi") { // pattern & high mining
			if (argv[2] != nullptr && argv[3] != nullptr && argv[4] != nullptr) {
				conf.mode = 2;
				conf.str_search = argv[2];
				std::istringstream ss(argv[3]);
				ss >> std::hex >> conf.high;
				conf.proc = std::stoi(argv[4]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -505; }
		} else if (p1 == "-ipreg") { // IPv6 regexp mining
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 3;
				conf.rgx_search = argv[2];
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -506; }
		} else if (p1 == "-meshpattern") { // meshname pattern mining
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 5;
				conf.str_search = argv[2];
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -507; }
		} else if (p1 == "-meshreg") { // meshname regexp mining
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 6;
				conf.rgx_search = argv[2];
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -508; }
		} else if (p1 == "-brute") { // subnet brute force
			if (argv[2] != nullptr && argv[3] != nullptr) {
				conf.mode = 7;
				conf.str_search = argv[2];
				conf.proc = std::stoi(argv[3]);
				Intro();
				DisplayConfig();
				testoutput();
				startThreads();
			} else { error(); return -509; }
		} else {error(); return -510;} // Первый параметр - неверный
		
	} else { // Запуск без параметров, работа с конфигом
	
		Intro();
		int configcheck = config(); // функция получения конфигурации
		if(configcheck < 0)
		{
			std::cerr << " Error code: " << configcheck;
			std::this_thread::sleep_for(std::chrono::seconds(15));
			return configcheck;
		}
		DisplayConfig();
		testoutput();
		startThreads();
	}
	
	std::cerr << "SYG has stopped working unexpectedly! Please, report about this.";
	std::this_thread::sleep_for(std::chrono::seconds(15));
	return -420;
}
