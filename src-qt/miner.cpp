#include "miner.h"
#include <iostream>

miner::miner(Widget *parent): window(parent), blocks_duration(0)
{
    conf = window->conf;
    conf.stop = false;
    countsize = 30000 * conf.proc; // Периодичность обновления счетчиков

    conf.mode == 0 ? conf.outputfile = "syg-ipv6-pattern.txt" :
    conf.mode == 1 ? conf.outputfile = "syg-ipv6-high.txt" :
    conf.mode == 2 ? conf.outputfile = "syg-ipv6-pattern-high.txt" :
    conf.mode == 3 ? conf.outputfile = "syg-ipv6-regexp.txt":
    conf.mode == 4 ? conf.outputfile = "syg-ipv6-regexp-high.txt" :
    conf.mode == 5 ? conf.outputfile = "syg-meshname-pattern.txt" :
        /* 6 */      conf.outputfile = "syg-meshname-regexp.txt" ;

    testOutput();

    if (conf.mode == 6) { // поиск по сырому base32, где конец - это паддинг "====".
        for (auto it = conf.str.begin(); it != conf.str.end(); ++it)
            if (*it == '$') *it = '=';
    }

    if (conf.mode == 5) // meshname pattern
    {
        conf.str = pickupStringForMeshname(conf.str);
    }

    window->setLog("00:00:00:00", 0, 0, 0);
}

void miner::testOutput()
{
    std::ifstream test(conf.outputfile);
    if(!test)
    {
        test.close();
        std::ofstream output(conf.outputfile);
        output << "******************************************************\n"
               << "Change PublicKey and PrivateKey to your yggdrasil.conf\n"
               << "Windows: C:\\ProgramData\\Yggdrasil\\yggdrasil.conf\n"
               << "Debian: /etc/yggdrasil.conf\n"
               << "******************************************************\n";
        output.close();
    } else test.close();
}

void miner::logStatistics()
{
    if (totalcount % countsize == 0)
    {
        auto timedays = (std::time(NULL) - sygstartedin) / 86400;
        auto timehours = ((std::time(NULL) - sygstartedin) - (timedays * 86400)) / 3600;
        auto timeminutes = ((std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600)) / 60;
        auto timeseconds = (std::time(NULL) - sygstartedin) - (timedays * 86400) - (timehours * 3600) - (timeminutes * 60);

        std::chrono::duration<double, std::milli> df = blocks_duration;
        blocks_duration = std::chrono::steady_clock::duration::zero();
        uint64_t khs = conf.proc * countsize / df.count();

        std::stringstream ss;
        ss << std::setw(2) << std::setfill('0') << timedays << ":" << std::setw(2) << std::setfill('0')
           << timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds;

        mtx.lock();
        window->setLog(ss.str(), totalcount, countfortune, khs);
        mtx.unlock();
    }
}

void miner::logKeys(Address raw, const KeysBox keys)
{
    mtx.lock();

    std::string base32 = getBase32(raw);
    if (conf.mode == 5 || conf.mode == 6) window->setAddr(pickupMeshnameForOutput(base32));
    else                                  window->setAddr(getAddress(raw));

    std::ofstream output(conf.outputfile, std::ios::app);
    output << std::endl;
    output << "Domain:     " << pickupMeshnameForOutput(base32) << std::endl;
    output << "Address:    " << getAddress(raw) << std::endl;
    output << "PublicKey:  " << keyToString(keys.PublicKey) << std::endl;
    output << "PrivateKey: " << keyToString(keys.PrivateKey) << keyToString(keys.PublicKey) << std::endl;
    output.close();

    mtx.unlock();
}

std::string miner::getBase32(const Address& rawAddr)
{
    return static_cast<std::string>(cppcodec::base32_rfc4648::encode(rawAddr.data(), 16));
}

/**
 * pickupStringForMeshname получает человекочитаемую строку
 * типа fsdasdaklasdgdas.meshname и возвращает значение, пригодное
 * для поиска по meshname-строке: удаляет возможную доменную зону
 * (всё после точки и саму точку), а также делает все буквы
 * заглавными.
 */
std::string miner::pickupStringForMeshname(std::string str)
{
    bool dot = false;
    std::string::iterator delend;
    for (auto it = str.begin(); it != str.end(); it++)
    {
        *it = toupper(*it); // делаем все буквы заглавными для обработки
        if(*it == '.') {
            delend = it;
            dot = true;
        }
    }
    if (dot)
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
std::string miner::pickupMeshnameForOutput(std::string str)
{
    for (auto it = str.begin(); it != str.end(); it++) // делаем все буквы строчными для вывода
        *it = tolower(*it);
    for (auto it = str.end(); *(it-1) == '='; it--)
        str.pop_back(); // удаляем символы '=' в конце адреса
    return str + ".meshname";
}

std::string miner::keyToString(const Key key)
{
    return hexArrayToString(key.data(), KEYSIZE);
}

std::string miner::hexArrayToString(const uint8_t* bytes, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]);
    return ss.str();
}

std::string miner::getAddress(const Address& rawAddr)
{
    char ipStrBuf[46];
    inet_ntop(AF_INET6, rawAddr.data(), ipStrBuf, 46);
    return std::string(ipStrBuf);
}

KeysBox miner::getKeyPair()
{
    KeysBox keys;

    uint8_t sk[64];
    crypto_sign_ed25519_keypair(keys.PublicKey.data(), sk);
    memcpy(keys.PrivateKey.data(), sk, 32);

    return keys;
}

void miner::getRawAddress(int lErase, Key InvertedPublicKey, Address& rawAddr)
{
    ++lErase; // лидирующие единицы + первый ноль

    int bitsToShift = lErase % 8;
    int start = lErase / 8;

    for(int i = start; i < start + 15; ++i)
    {
        InvertedPublicKey[i] <<= bitsToShift;
        InvertedPublicKey[i] |= (InvertedPublicKey[i + 1] >> (8 - bitsToShift));
    }

    rawAddr[0] = 0x02;
    rawAddr[1] = lErase - 1;
    for (int i = 0; i < 14; ++i)
        rawAddr[i + 2] = InvertedPublicKey[i+start];
}

Key miner::bitwiseInverse(const Key key)
{
    Key inverted;
    for(size_t i = 0; i < key.size(); ++i)
        inverted[i] = ~key[i];

    return inverted;
}

int miner::getOnes(const Key value)
{
    const int zeroBytesMap[8] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
    int leadOnes = 0; // кол-во лидирующих единиц

    for (int i = 0; i < 17; ++i) // 32B(ключ) - 15B(IPv6 без 0x02) = 17B(возможных лидирующих единиц)
    {
        for (int j = 0; j < 8; ++j)
        {
            if (value[i] & zeroBytesMap[j]) ++leadOnes;
            else return leadOnes;
        }
    }
    return 0; // никогда не случится
}

void miner::process_fortune_key(const KeysBox& keys)
{
    Key invKey = bitwiseInverse(keys.PublicKey);
    int ones = getOnes(invKey);
    Address rawAddr;
    getRawAddress(ones, invKey, rawAddr);
    ++countfortune;
    logKeys(rawAddr, keys);
    logStatistics();
}

void miner::miner_thread()
{
    Address rawAddr;
    std::regex regx(conf.str, std::regex_constants::egrep | std::regex_constants::icase);
    int ones = 0;

    for (;;) // основной цикл майнинга
    {
        if (conf.stop) break;

        auto start_time = std::chrono::steady_clock::now();
        KeysBox keys = getKeyPair();
        Key invKey = bitwiseInverse(keys.PublicKey);
        ones = getOnes(invKey);

        if (conf.mode == 0) // IPv6 pattern mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (getAddress(rawAddr).find(conf.str.c_str()) != std::string::npos)
            {
                process_fortune_key(keys);
            }
        }
        if (conf.mode == 1) // high mining
        {
            if (ones > conf.high)
            {
                if (conf.letsup) conf.high = ones;
                process_fortune_key(keys);
            }
        }
        if (conf.mode == 2) // pattern & high mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (ones > conf.high && getAddress(rawAddr).find(conf.str.c_str()) != std::string::npos)
            {
                if (conf.letsup) conf.high = ones;
                process_fortune_key(keys);
            }
        }
        if (conf.mode == 3) // IPv6 regexp mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (std::regex_search((getAddress(rawAddr)), regx))
            {
                process_fortune_key(keys);
            }
        }
        if (conf.mode == 4) // IPv6 regexp & high mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (ones > conf.high)
            {
                if (std::regex_search((getAddress(rawAddr)), regx))
                {
                    if (conf.letsup) conf.high = ones;
                    process_fortune_key(keys);
                }
            }
        }
        if (conf.mode == 5) // meshname pattern mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (getBase32(rawAddr).find(conf.str.c_str()) != std::string::npos)
            {
                process_fortune_key(keys);
            }
        }
        if (conf.mode == 6) // meshname regexp mining
        {
            getRawAddress(ones, invKey, rawAddr);
            if (std::regex_search((getBase32(rawAddr)), regx))
            {
                process_fortune_key(keys);
            }
        }

        auto stop_time = std::chrono::steady_clock::now();
        ++totalcount;
        blocks_duration += stop_time - start_time;
        logStatistics();
    }
}

void miner::startThreads()
{
    for (unsigned int i = 0; i < conf.proc; ++i)
    {
        std::thread * thread = new std::thread(&miner::miner_thread, this);
        if (i+1 < conf.proc) thread->detach();
        else thread->join();
    }
}
