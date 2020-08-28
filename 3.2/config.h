#pragma once
#include <string>
#include "config.cpp"

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
