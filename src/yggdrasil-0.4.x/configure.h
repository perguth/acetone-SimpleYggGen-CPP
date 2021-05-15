#ifndef CONFIGURE_H
#define CONFIGURE_H

#include <string>
#include "main.h"

struct option 
{
    unsigned int proc = 999999; // количество потоков по умолчанию, урежется до реального количества ядер
    int  mode         = 1;      // режим майнинга
    bool log          = true;   // логгирование
    int high          = 20;     // начальная высота при майнинге: dec(20) == hex(14)
    bool letsup       = true;   // повышение высоты при нахождении
    bool mesh         = false;  // отображение meshname-доменов
    std::string str   = "aaaa";

	std::string outputfile;
    int sbt_size = 7;           // 64 бита / 8 = 8 байт, нумерация с нуля
    bool sbt_alarm = false;     // для симпатичного вывода предупреждения
};

#endif
