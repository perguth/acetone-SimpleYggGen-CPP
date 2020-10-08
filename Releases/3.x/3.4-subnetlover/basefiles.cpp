struct option 
{
	int proc = 0;
	int mode = 0;
	int log  = 1;
	int high = 0;
	int mesh = 0;
	std::string str_search;
	std::string rgx_search;
	std::string outputfile;
	
	uint8_t raw_search[16];
	int sbt_size = 7; // 64 бита / 8 = 8 байт, нумерация с нуля => -1
	bool sbt_alarm = false; // для симпатичного вывода предупреждения
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
				<< "#               SimpleYggGen C++ configuration file.               #\n"
				<< "# If you have some errors, try delete this file and run SYG again. #\n"
				<< "####################################################################\n\n"
				<< "  Parameter limited by processors count on PC.\n"
				<< "* Count of thread: 16\n\n"
				<< "  0 - IPv6 pattern, 1 - high address, 2 - search by pattern & high,\n"
				<< "  3 - IPv6 regexp, 4 - meshname pattern, 5 - meshname regexp,\n"
				<< "  6 - IPv6 subnet brute force mode :^)\n"
				<< "* Mining option: 1\n\n"
				<< "  0 - console output only, 1 - log to file.\n"
				<< "* Logging mode: 1\n\n"
				<< "  High address search. Parameter is set in hexadecimal (0-9, a-f).\n"
				<< "* Start position (2xx): 14\n\n"
				<< "  Used when \"Mining option\" set as 0, 2, 4 or 6.\n"
				<< "  - Meshname domains use base32 (RFC4648) alphabet symbols.\n"
				<< "  - In meshname domain use \"===\" instead \".meshname\".\n"
				<< "  - Subnet brute force understand \"3xx:\" and \"2xx:\" patterns.\n"
				<< "* Pattern: ::\n\n"
				<< "  Used when \"Mining option\" set as 3 or 5. Extended grep type.\n"
				<< "  - Meshname domains use base32 (RFC4648) alphabet symbols.\n"
				<< "  - In meshname domain use \"===\" instead \".meshname\".\n"
				<< "* Regexp: ^2.*.f{1,4}.*.ace:(6|9)$\n\n"
				<< "  0 - disable, 1 - enable.\n"
				<< "* Display meshname domains: 0";
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
		
		struct check 
		{
			bool proc = false;
			bool mode = false;
			bool log  = false;
			bool high = false;
			bool mesh = false;
			bool str_search = false;
			bool rgx_search = false;
			
			bool ok()
			{
				return(proc & mode & log & high & mesh & str_search & rgx_search);
			}
		};
		check complete;
		
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
				complete.proc = true;
			}
			if(str_temp_read == "option:")
			{
				ss_input >> conf.mode;
				if(ss_input.fail() || (conf.mode > 6 || conf.mode < 0))
				{
					std::cerr << " Mining option value incorrect." << std::endl;
					return -3;
				}
				complete.mode = true;
			}
			if(str_temp_read == "mode:")
			{
				ss_input >> conf.log;
				if(ss_input.fail() || (conf.log != 0 && conf.log != 1))
				{
					std::cerr << " Logging mode value incorrect." << std::endl;
					return -4;
				}
				complete.log = true;
			}
			if(str_temp_read == "(2xx):")
			{
				ss_input >> std::hex >> conf.high;
				if(ss_input.fail())
				{
					std::cerr << " Start position value incorrect." << std::endl;
					return -5;
				}
				complete.high = true;
			}
			if(str_temp_read == "Pattern:")
			{
				ss_input >> conf.str_search;
				if(ss_input.fail())
				{
					std::cerr << " Pattern value incorrect." << std::endl;
					return -6;
				}
				complete.str_search = true;
			}
			if(str_temp_read == "Regexp:")
			{
				ss_input >> conf.rgx_search;
				if(ss_input.fail())
				{
					std::cerr << " Regexp value incorrect." << std::endl;
					return -7;
				}
				complete.rgx_search = true;
			}
			if(str_temp_read == "domains:")
			{
				ss_input >> conf.mesh;
				if(ss_input.fail() || (conf.mesh != 0 && conf.mesh != 1))
				{
					std::cerr << " Meshname display value incorrect." << std::endl;
					return -8;
				}
				complete.mesh = true;
			}
		}
		if(!complete.ok())
		{
			std::cerr << " Corrupted configuration file. Some parameters not found." << std::endl;
			return -9;
		}
	}
	return 0;
}

void DisplayConfig()
{
	// из-за регулирования количества потоков и countsize вызов функции обязателен
	unsigned int processor_count = std::thread::hardware_concurrency(); // кол-во процессоров
	if (conf.proc > (int)processor_count)
		conf.proc = (int)processor_count;
	countsize = 800 << __bsrq(conf.proc);
	
	std::cout << " Threads: " << conf.proc << ", ";

	if(conf.mode == 0)
		std::cout << "IPv6 pattern (" << conf.str_search << "), ";
	else if(conf.mode == 1)
		std::cout << "search high addresses (2" << std::setw(2) << std::setfill('0') << 
			std::hex << conf.high << std::dec << "+), ";
	else if(conf.mode == 2)
		std::cout << "search by pattern & high (" << conf.str_search << " & 2" << 
 			std::setw(2) << std::setfill('0') << std::hex << conf.high << std::dec << "+), ";
	else if(conf.mode == 3)
		std::cout << "IPv6 regexp (" << conf.rgx_search << "), ";
	else if(conf.mode == 4)
		std::cout << "meshname pattern (" << conf.str_search << "), ";
	else if(conf.mode == 5)
		std::cout << "meshname regexp (" << conf.rgx_search << "), ";
	else if(conf.mode == 6)
		std::cout << "subnet brute force (" << conf.str_search << "/64), ";
	
	if(conf.log)
		std::cout << "logging to text file.";
	else
		std::cout << "console log only.";

	if((conf.mode == 4 || conf.mode == 5) && conf.mesh == 0)
		conf.mesh = 1; // принудительно включаем отображение мешнейм-доменов при их майнинге
	std::cout << std::endl << std::endl;
}

void testoutput()
{
	if(conf.log) // проверка включено ли логирование
	{
		if(conf.mode == 0)
			conf.outputfile = "syg-ipv6-pattern.txt";
		else if(conf.mode == 1)
			conf.outputfile = "syg-ipv6-high.txt";
		else if(conf.mode == 2)
			conf.outputfile = "syg-ipv6-pattern-high.txt";
		else if(conf.mode == 3)
			conf.outputfile = "syg-ipv6-regexp.txt";
		else if(conf.mode == 4)
			conf.outputfile = "syg-meshname-pattern.txt";
		else if(conf.mode == 5)
			conf.outputfile = "syg-meshname-regexp.txt";
		else if(conf.mode == 6)
			conf.outputfile = "syg-subnet-brute-force.txt";

		std::ifstream test(conf.outputfile);
		if(!test) // проверка наличия выходного файла
		{
			test.close();
			std::ofstream output(conf.outputfile);
			output << "**************************************************************************\n"
			       << "Change EncryptionPublicKey and EncryptionPrivateKey to your yggdrasil.conf\n"
			       << "Windows: C:\\ProgramData\\Yggdrasil\\yggdrasil.conf\n"
			       << "Debian: /etc/yggdrasil.conf\n"
			       << "**************************************************************************\n";
			output.close();
		} else test.close();
	}
}
