/*
 * Спасибо PurpleI2P Project за активное содействие в написании этого кода.
 * notabug.org/acetone/SimpleYggGen-CPP
 *
 * acetone (c) GPLv3
 *
 */

#include <openssl/evp.h> // библиотека OpenSSL
#include <openssl/sha.h>
#include <iostream>      // вывод на экран
#include <iomanip>       // форматированный вывод строк
#include <ctime>         // системное время
#include <bitset>        // побитовое чтение
#include <cstring>		 // memcmp - побайтовое сравнение

#define KEYSIZE 32
#define SHA512SIZE 128

////////////////////////////////////////////////// Заставка и прочая вода

		const char randomtable[90] =
		{
		  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
		  'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		  'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
		  'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
		  'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		  'Y', 'Z', '!', '@', '(', ')', '/', '-', '#', '+',
		  '$', '%', '^', '&', '*', '`', '~', '>', '<', '?',
		  '{', '}', '[', ']', ';', ':', '_', '=', '|', '\''
		};

		std::string getrandom(int entropy, unsigned int size_of_line)
		{
			std::string random_value;
			while(random_value.size() < size_of_line)
			{
				random_value += randomtable[(std::rand() % entropy)];
			}
			random_value.shrink_to_fit();
			return random_value;
		}

		void intro()
		{
			srand(time(NULL));
			int rv = 60;
			std::cout << std::endl
			<< "|                                      |" << getrandom(2,44)   << std::endl
			<< "| SimpleYggGen C++ 1.0-headhunter 2020 |" << getrandom(rv, 2)  << "          "  << getrandom(rv, 5) << "  " << getrandom(rv, 6) << "  " << getrandom(rv, 5)  << "          " << getrandom(rv, 2)	<< std::endl
			<< "|   OpenSSL inside: x25519 -> sha512   |" << getrandom(rv, 2)  << "  "          << getrandom(rv,13) << "  " << getrandom(rv, 6) << "  " << getrandom(rv, 5)  << "  "         << getrandom(rv, 10)	<< std::endl
			<< "| notabug.org/acetone/SimpleYggGen-CPP |" << getrandom(rv, 2)  << "          "  << getrandom(rv, 5) << "          "                     << getrandom(rv, 5)  << "  "         << getrandom(rv, 3)	<< "     " << getrandom(rv, 2) << std::endl
			<< "|           acetone (c) GPLv3          |" << getrandom(rv, 10) <<         "  "  << getrandom(rv,13) <<         "  "                     << getrandom(rv, 5)  << "  "         << getrandom(rv, 6)	<<    "  " << getrandom(rv, 2) << std::endl
			<< "|                                      |" << getrandom(rv, 2)  << "          "  << getrandom(rv, 5) << "          "                     << getrandom(rv, 5)  << "          " << getrandom(rv, 2)	<< std::endl
			<< "|     "  << __DATE__ << "         "  << __TIME__ <<  "     |"	    << getrandom(2,44) << std::endl;
		}

////////////////////////////////////////////////// Суть вопроса

struct BoxKeys
{
    uint8_t PublicKey[KEYSIZE];
    uint8_t PrivateKey[KEYSIZE];
};

BoxKeys getKeyPair(void)
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

void miner()
{
	unsigned char HashValue[SHA512SIZE];

	uint8_t PublicKeyBest[KEYSIZE];
	uint8_t PrivateKeyBest[KEYSIZE];

	const unsigned char CheckByte[8] = {1, 3, 7, 15, 31, 63, 127, 255};

	int totalcount= 0;	// счетчик циклов
	int bitcount = 9; 	// переменная для хранения наибольшего количества единиц

	// ------------------------ ОСНОВНОЙ ЦИКЛ

	bool count50 = false;
	bool count100 = true;
	bool count500 = true;

	while(true)
	{
		int bufmemcmp = 300;		// принимает возвращаемое значение memcmp, инициализированно случайным значением (шутка про тракториста)
		int bit = 0;				// счетчик для подсчета единиц


		std::string s_first4bytes;	// !!! переменная для хранения хэша
		bool done = false;			// сигнал о завершении анализа хэша

		BoxKeys myKeys = getKeyPair();
		SHA512(myKeys.PublicKey, KEYSIZE, HashValue);

		// ---------- bitset
		std::bitset<8> bits_header(HashValue[0]);		// получаем биты первого байта хэша
		s_first4bytes = bits_header.to_string(); 		// сохраняем их в стринг

		for(int y = 1; y < 4; ++y)						// добавляем еще 3 байта
		{
		std::bitset<8> bits_header_temp(HashValue[y]);
		s_first4bytes += bits_header_temp.to_string();
		}

	// bits ----------------------------------

		bit = 0;
		while(s_first4bytes[bit] != '0' && s_first4bytes[bit] == '1' ) // цикл побитового анализа
		{
		++bit;
			if(bit > bitcount) // сохраняем связку лучших ключей
			{
				bitcount = bit;
				for(int z = 0; z < KEYSIZE; ++z)
				{
					PublicKeyBest[z] = myKeys.PublicKey[z];
				}
				for(int z = 0; z < KEYSIZE; ++z)
				{
					PrivateKeyBest[z] = myKeys.PrivateKey[z];
				}

				// outout -------------------------------
				if(s_first4bytes[bit] == '0')
				{
					std::cout << "\nAddress:    [2" << std::setw(2) << std::setfill('0') << std::hex << bitcount << ":...]" << std::endl;
					std::cout << "PublicKey:  ";
					for(int i = 0; i < 32; ++i)
					{
						std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PublicKeyBest[i];
					}
					std::cout << std::endl;

					std::cout << "PrivateKey: ";
					for(int i = 0; i < 32; ++i)
					{
						std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)PrivateKeyBest[i];
					}
					std::cout << std::endl;
					count50 = false;
					count100 = true;
					count500 = true;
					totalcount = 0;
				}
			}
		}

		++totalcount;
		if(totalcount % 50000 == 0 && !count50)
		{
			std::cerr << "50k ";
			std::cerr.flush();
			count50 = true;
			count100 = false;
			continue;
		}
		if(totalcount % 100000 == 0  && !count100)
		{
			std::cerr << "100k ";
			std::cerr.flush();
			count100 = true;
			count500 = false;
			continue;
		}
		if(totalcount % 500000 == 0  && !count500)
		{
			std::cerr << "500k ";
			std::cerr.flush();
			count500 = true;
			continue;
		}
		if(totalcount % 500000 == 0)
		{
			std::cerr << "# ";
			std::cerr.flush();
		}
	}
}

// ------------------------------------------------------

int main()
{
	intro();
	miner();
}