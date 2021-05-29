#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>

struct option
{
    unsigned int proc = 0;      // количество потоков
    int  mode         = 1;      // режим майнинга
    int  high         = 20;     // начальная высота при майнинге: dec(20) == hex(14)
    bool letsup       = true;   // повышение высоты при нахождении
    std::string str   = "aaaa";
    bool stop         = false;  // флаг остановки

    std::string outputfile;
};

#endif // CONFIG_HPP
