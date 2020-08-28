/**
 *
 * Функция генерирует и парсит конфигурационный файл.
 * Вынесена в отдельный *.cpp с версии 3.2 для удобства.
 *
 */

#pragma once

#include <iostream>     
#include <string>
#include <sstream>
#include <regex>

#include "config.h"

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
				<< "  0 - by name, 1 - high address, 2 - high & by name\n"
				<< "  3 - regex, 4 - high & regex.\n"
				<< "* Mining option: 3\n\n"
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
	} else {
		
		// ЧТЕНИЕ КОНФИГА ТУТ
		
		
		conffile.close();

		unsigned int processor_count = std::thread::hardware_concurrency(); // кол-во процессоров
		if (conf.proc > (int)processor_count)
			conf.proc = (int)processor_count;
		countsize = 800 << __bsrq(conf.proc);
	}

	// вывод конфигурации на экран
	std::cout << " Threads: " << conf.proc << ", ";

	if(conf.mode == 0)
		std::cout << "search by pattern (" << conf.str_search << "), ";
	else if(conf.mode == 1)
		std::cout << "search high addresses (" << conf.high << "), ";
	else if(conf.mode == 2)
		std::cout << "search by pattern & high (" << conf.str_search << " & " << conf.high << "), ";
	else if(conf.mode == 3)
		std::cout << "search by regexp (" << conf.exp_search << "), ";
	else if(conf.mode == 4)
		std::cout << "search by regexp & high (" << conf.high << " & " << conf.high << "), ";
	else {
		std::cerr << std::endl << "Bad mining option." << std::endl; 
		return -1;
	}

	if(conf.log == 1)
		std::cout << "logging to text file, ";
	else if(conf.log == 0)
		std::cout << "console log only, ";
	else {
		std::cerr << std::endl << "Bad logging mode value." << std::endl; 
		return -2;
	}
    std::cout << "heartbeat " << countsize * BLOCKSIZE << "." << std::endl; // FIXME - heartbeat output
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
