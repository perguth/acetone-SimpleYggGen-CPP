/**
 *
 * Функция генерирует и парсит конфигурационный файл.
 * Вынесена в отдельный *.cpp с версии 3.2 для удобства.
 *
 */
#include <x86intrin.h>
#include <iostream>     
#include <string>
#include <sstream>
#include <fstream>
#include <thread>
#include <regex>

struct option 
{
	int proc = 0;
	int mode = 0;
	int log  = 0;
	int high = 0;
	std::string str_search;
	std::string rgx_search;
	std::string outputfile;
};

option conf;

int config()
{
	std::ifstream conffile ("sygcpp.conf");

	if(!conffile) // проверка наличия конфига
	{
		std::cout << " Configuration file not found... ";
		conffile.close();
		std::ofstream newconf ("sygcpp.conf"); // создание конфига
		if(!newconf)
		{
			std::cerr << "CREATION FAILED" << std::endl;
			return -1;
		}
		newconf << "####################################################################\n"
				<< "#                SimpleYggGen C++ configuraton file                #\n"
				<< "# If you have some errors, try delete this file and run SYG again. #\n"
				<< "####################################################################\n\n"
				<< "* Count of thread: 1\n\n"
				<< "  0 - by pattern, 1 - high address, 2 - search by pattern & high\n"
				<< "  3 - regexp, 4 - search by regexp & high.\n"
				<< "* Mining option: 0\n\n"
				<< "  0 - console output only, 1 - log to file.\n"
				<< "* Logging mode: 1\n\n"
				<< "  Attention: parameter is set in decimal notation (0 - 9),\n"
				<< "  displayed in the address in hexadecimal (0 - 9, a -f).\n"
				<< "* Start position (for high address search): 15\n\n"
				<< "  Used when \"Mining mode\" set as 0 or 3\n"
				<< "* Pattern: ::\n\n"
				<< "  Used when \"Mining mode\" set as 4 or 5\n"
				<< "  If you don't know regexp see it: https://regexr.com/\n"
				<< "* Regexp: ^2.*ffff.*$";
		newconf.close();
		
		std::ifstream conffile ("sygcpp.conf");
		if(conffile)
			std::cout << "CREATED" << std::endl;
		config();
		return 0;
	} else { // чтение конфигурации
		std::string str_temp_read;
		std::string str_read;
		while(getline(conffile, str_temp_read))
			str_read += str_temp_read;
		conffile.close();
		
		std::istringstream ss_input(str_read); // чтение конфига
		while(!ss_input.eof())
		{
			ss_input >> str_temp_read;
			if(str_temp_read == "thread:") // поиск параметра по предыдущему слову
			{
				ss_input >> conf.proc; // запись в соответствующую переменную
				if(ss_input.fail())
				{
					std::cerr << " Count of thread value incorrect." << std::endl;
					return -2;
				}
			}
			if(str_temp_read == "option:")
			{
				ss_input >> conf.mode;
				if(ss_input.fail() || (conf.mode > 4 || conf.mode < 0))
				{
					std::cerr << " Mining option value incorrect." << std::endl;
					return -3;
				}
			}
			if(str_temp_read == "mode:")
			{
				ss_input >> conf.log;
				if(ss_input.fail() || (conf.log != 0 && conf.log != 1))
				{
					std::cerr << " Logging mode value incorrect." << std::endl;
					return -4;
				}
			}
			if(str_temp_read == "search):")
			{
				ss_input >> conf.high;
				if(ss_input.fail())
				{
					std::cerr << " Start position value incorrect." << std::endl;
					return -5;
				}
			}
			if(str_temp_read == "Pattern:")
			{
				ss_input >> conf.str_search;
				if(ss_input.fail())
				{
					std::cerr << " Pattern value incorrect." << std::endl;
					return -6;
				}
			}
			if(str_temp_read == "Regexp:")
			{
				ss_input >> conf.rgx_search;
				if(ss_input.fail())
				{
					std::cerr << " Regexp value incorrect." << std::endl;
					return -7;
				}
			}
		}
		return 0;
	}
}

void config_print()
{
	// вывод конфигурации на экран
	std::cout << " Threads: " << conf.proc << ", ";

	if(conf.mode == 0)
		std::cout << "search by pattern (" << conf.str_search << "), ";
	else if(conf.mode == 1)
		std::cout << "search high addresses (" << conf.high << "), ";
	else if(conf.mode == 2)
		std::cout << "search by pattern & high (" << conf.str_search << " & " << conf.high << "), ";
	else if(conf.mode == 3)
		std::cout << "search by regexp (" << conf.rgx_search << "), ";
	else if(conf.mode == 4)
		std::cout << "search by regexp & high (" << conf.rgx_search << " & " << conf.high << "), ";

	if(conf.log)
		std::cout << "logging to text file.";
	else
		std::cout << "console log only.";

	std::cout << std::endl << std::endl;
	
}

void testoutput()
{
	if(conf.log) // проверка включено ли логирование
	{
		if(conf.mode)
			conf.outputfile = "syg-high.txt";
		else
			conf.outputfile = "syg-byname.txt";

		std::ifstream test(conf.outputfile);
		if(!test) // проверка наличия выходного файла
		{
			test.close();
			std::ofstream output(conf.outputfile);
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
