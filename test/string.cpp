#include <iostream>
#include <sstream>
#include <string>

int main()
{
	std::string s = "value fail";
	int p = s.find(" ");
	std::istringstream ss( s.substr(p+1) );
	std::string s2;
	ss >> s2;
	std::cout << s2;
}
