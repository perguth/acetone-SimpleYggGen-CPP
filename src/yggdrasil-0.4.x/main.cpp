/*
 * Address miner for Yggdrsail 0.4.x and higher.
 * The main part of the code is taken from the previous generation
 * of the miner for the 0.3.x and earlier Yggdrasil's branch.
 *
 * developers team, 2021 (c) GPLv3
 */

#include "main.h"

std::time_t sygstartedin = std::time(NULL); // для вывода времени работы
int countsize = 0;                          // определяет периодичность вывода счетчика
uint64_t totalcount = 0;                    // общий счетчик
uint64_t countfortune = 0;                  // счетчик нахождений
bool newline = false;                       // форматирует вывод после нахождения адреса
std::chrono::steady_clock::duration blocks_duration(0);
std::mutex mtx;
static option conf;

void intro()
{
    std::cout << std::endl << "\
 +--------------------------------------------------------------------------+ \n\
 |                   [ SimpleYggGen C++    5.0-irontree ]                   | \n\
 |                   EdDSA public key -> IPv6 -> Meshname                   | \n\
 |                   notabug.org/acetone/SimpleYggGen-CPP                   | \n\
 |                                                                          | \n\
 |                              GPLv3 (c) 2021                              | \n\
 +--------------------------------------------------------------------------+ "
 << std::endl;
}

void displayConfig()
{
    // из-за регулирования количества потоков и countsize вызов функции обязателен
    unsigned int processor_count = std::thread::hardware_concurrency(); // кол-во процессоров
    if (conf.proc == 0 || conf.proc > static_cast<unsigned int>(processor_count))
        conf.proc = static_cast<unsigned int>(processor_count);

    countsize = 80000 * conf.proc;

    std::cout << " Threads: " << conf.proc << ", ";

    if(conf.mode == 0)
        std::cout << "IPv6 pattern (" << conf.str << "), ";
    else if(conf.mode == 1)
    {
        std::cout << "high addresses (2" << std::setw(2) << std::setfill('0') <<
            std::hex << conf.high << std::dec;
            (conf.letsup != 0) ? std::cout << "++), " : std::cout << "+), ";
    }
    else if(conf.mode == 2)
    {
        std::cout << "by pattern (" << conf.str << ") & high (2" <<
            std::setw(2) << std::setfill('0') << std::hex << conf.high << std::dec;
            (conf.letsup != 0) ? std::cout << "++), " : std::cout << "+), ";
    }
    else if(conf.mode == 3)
        std::cout << "IPv6 regexp (" << conf.str << "), ";
    else if(conf.mode == 4)
    {
        std::cout << "IPv6 regexp (" << conf.str << ") & high (2" <<
            std::setw(2) << std::setfill('0') << std::hex << conf.high << std::dec;
            (conf.letsup != 0) ? std::cout << "++), " : std::cout << "+), ";
    }
    else if(conf.mode == 5)
        std::cout << "meshname pattern (" << conf.str << "), ";
    else if(conf.mode == 6)
        std::cout << "meshname regexp (" << conf.str << "), ";
    else if(conf.mode == 7)
        std::cout << "subnet brute force (" << conf.str << "/64), ";

    if(conf.log)
        std::cout << "logging to text file.";
    else
        std::cout << "console log only.";

    if((conf.mode == 5 || conf.mode == 6) && conf.mesh == 0)
        conf.mesh = 1; // принудительно включаем отображение мешнейм-доменов при их майнинге
    std::cout << std::endl << std::endl;
}

void testOutput()
{
    if(conf.log)
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
            conf.outputfile = "syg-ipv6-regexp-high.txt";
        else if(conf.mode == 5)
            conf.outputfile = "syg-meshname-pattern.txt";
        else if(conf.mode == 6)
            conf.outputfile = "syg-meshname-regexp.txt";
        else if(conf.mode == 7)
            conf.outputfile = "syg-subnet-brute-force.txt";

        std::ifstream test(conf.outputfile);
        if(!test)
        {
            test.close();
            std::ofstream output(conf.outputfile);
            output << "********************************************************************\n"
                   << "Change SigningPublicKey and SigningPrivateKey to your yggdrasil.conf\n"
                   << "Windows: C:\\ProgramData\\Yggdrasil\\yggdrasil.conf\n"
                   << "Debian: /etc/yggdrasil.conf\n"
                   << "********************************************************************\n";
            output.close();
        } else test.close();
    }
}

void logStatistics()
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
        std::cout <<
            " kH/s: [" << std::setw(7) << std::setfill('_') << khs <<
            "] Total: [" << std::setw(19) << totalcount <<
            "] Found: [" << std::setw(3) << countfortune <<
            "] Time: [" << timedays << ":" << std::setw(2) << std::setfill('0') <<
            timehours << ":" << std::setw(2) << timeminutes << ":" << std::setw(2) << timeseconds << "]" << std::endl;
        newline = true;
    }
}

void logKeys(Address raw, const KeysBox keys)
{
    mtx.lock();
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
    std::cout << " PublicKey:  " << keyToString(keys.PublicKey) << std::endl;
    std::cout << " PrivateKey: " << keyToString(keys.PrivateKey) << keyToString(keys.PublicKey) << std::endl;
    std::cout << std::endl;

    if (conf.log) // запись в файл
    {
        std::ofstream output(conf.outputfile, std::ios::app);
        output << std::endl;
        if (conf.mesh) {
            std::string mesh = getMeshname(raw);
            output << "Domain:            " << pickupMeshnameForOutput(mesh) << std::endl;
        }
        output << "Address:           " << getAddress(raw) << std::endl;
        output << "SigningPublicKey:  " << keyToString(keys.PublicKey) << std::endl;
        output << "SigningPrivateKey: " << keyToString(keys.PrivateKey) << keyToString(keys.PublicKey) << std::endl;
        output.close();
    }
    mtx.unlock();
}

std::string getMeshname(const Address& rawAddr)
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
std::string pickupStringForMeshname(std::string str)
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
    Address rawAddr;
    for(int i = 0; i < 16; ++i)
        rawAddr[i] = raw[i];
    return std::string(getAddress(rawAddr));
}

void subnetCheck()
{
    if(conf.str[0] == '3') // замена 300::/64 на целевой 200::/7
        conf.str[0] = '2';
}

bool convertStrToRaw(const std::string str, Address array)
{
    bool result = inet_pton(AF_INET6, str.c_str(), (void*)array.data());
    return result;
}

KeysBox getKeyPair()
{
    KeysBox keys;
    size_t len = KEYSIZE;

    // https://github.com/PurpleI2P/i2pd/blob/openssl/libi2pd/Signature.h#L357
    EVP_PKEY * pkey = nullptr;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_ED25519, NULL);

    EVP_PKEY_keygen_init (pctx);
    EVP_PKEY_keygen (pctx, &pkey);
    EVP_PKEY_CTX_free (pctx);

    EVP_PKEY_get_raw_public_key (pkey, keys.PublicKey.data(), &len);
    EVP_PKEY_get_raw_private_key (pkey, keys.PrivateKey.data(), &len);

    EVP_PKEY_free (pkey);

    return keys;
}

void getRawAddress(int lErase, Key InvertedPublicKey, Address& rawAddr)
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

Key bitwiseInverse(const Key key)
{
    Key inverted;
    for(size_t i = 0; i < key.size(); ++i)
        inverted[i] = ~key[i];

    return inverted;
}

int getOnes(const Key value)
{
    const int map[8] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
    int lOnes = 0; // кол-во лидирующих единиц

    for (int i = 0; i < 17; ++i) // 32B(ключ) - 15B(IPv6 без 0x02) = 17B(возможных лидирующих единиц)
    {
        for (int j = 0; j < 8; ++j)
        {
            if (value[i] & map[j]) ++lOnes;
            else return lOnes;
        }
    }
    return 0; // никогда не случится
}

std::string getAddress(const Address rawAddr)
{
    char ipStrBuf[46];
    inet_ntop(AF_INET6, rawAddr.data(), ipStrBuf, 46);
    return std::string(ipStrBuf);
}

std::string hexArrayToString(const uint8_t* bytes, int length)
{
    std::stringstream ss;
    for (int i = 0; i < length; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]);
    return ss.str();
}

std::string keyToString(const Key key)
{
    return hexArrayToString(key.data(), KEYSIZE);
}

void process_fortune_key(const KeysBox& keys)
{
    Key invKey = bitwiseInverse(keys.PublicKey);
    int ones = getOnes(invKey);
    Address rawAddr;
    getRawAddress(ones, invKey, rawAddr);
    logKeys(rawAddr, keys);
    ++countfortune;
}

template <int T>
void miner_thread()
{
    //Address rawAddr;
    int ones = 0;

    for (;;)
    {
        auto start_time = std::chrono::steady_clock::now();
        KeysBox keys = getKeyPair();
        Key invKey = bitwiseInverse(keys.PublicKey);
        ones = getOnes(invKey);

        if (T == 1) // high mining
        {
            if (ones > conf.high)
            {
                if (conf.letsup != 0) conf.high = ones;
                process_fortune_key(keys);
            }
        } else { std::cout << "Only high mode implemented yet" << std::endl; break; } // FIXME

        auto stop_time = std::chrono::steady_clock::now();
        ++totalcount;
        mtx.lock();
        blocks_duration += stop_time - start_time;
        logStatistics();
        mtx.unlock();
    }
}

void startThreads()
{
    std::thread* lastThread;
    for (unsigned int i = 0; i < conf.proc; ++i)
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

void error(int code)
{
    std::cerr << std::endl << "\
 +--------------------------------------------------------------------------+\n\
 | Incorrect input, my dear friend. Use --help for usage information.       |\n\
 +--------------------------------------------------------------------------+\n\
 Error code: " << code << std::endl;
}

void help()
{
    std::cout << std::endl << "\
 +--------------------------------------------------------------------------+\n\
 |            Simple Yggdrasil address miner usage:  --help or -h           |\n\
 +--------------------------------------------------------------------------+\n\
 [Mining modes]                                                              \n\
   High addresses (BY DEFAULT)                                               \n\
   IPv6 by pattern                                         --ip |  -i        \n\
   IPv6 by pattern + height                           --ip-high | -ih        \n\
   IPv6 by regular expression                          --regexp |  -r        \n\
   IPv6 by regular expression + height            --regexp-high | -rh        \n\
   Meshname by pattern                                   --mesh |  -m        \n\
   Meshname by regular expression                 --mesh-regexp | -mr        \n\
   Subnet brute force (300::/64)                  --brute-force |  -b        \n\
 [Main parameters]                                                           \n\
   Threads count (maximum by default)                 --threads |  -t <value>\n\
   String for pattern or regular expression           --pattern |  -p <value>\n\
   Start position for high addresses (14 by default) --altitude |  -a <value>\n\
 [Extra options]                                                             \n\
   Disable auto-increase in high mode           --increase-none |            \n\
   Disable logging to text file, stdout only     --logging-none |            \n\
   Force display meshname domains                --display-mesh |            \n\
   Displays the version of the miner                  --version |  -v        \n\
 [Meshname convertation]                                                     \n\
   Convert IP to Meshname                              --tomesh | -tm <value>\n\
   Convert Meshname to IP                                --toip | -ti <value>\n\
 [Notes]                                                                     \n\
   Meshname domains use base32 (RFC4648) alphabet symbols.                   \n\
   In meshname domain mining should use \"=\" instead \".meshname\".         \n\
   Subnet brute force mode understand \"3xx:\" and \"2xx:\" patterns.        \n\
 +--------------------------------------------------------------------------+\n";
}

void without()
{
    std::cout << "\
 SimpleYggGen was started without parameters.\n\
 The mining mode for high addresses will be launched automatically.\n\
 Use --help for usage information."
 << std::flush;
}

int main(int argc, char *argv[])
{
    if(argc >= 2)
    {
        std::string p1;
        ///////////////////////////////// Вспомогательные функции
        p1 = argv[1];
        if (p1 == "--help" || p1 == "-help" || p1 == "-h") {
            help();
            return 0;
        } else if (p1 == "--version" || p1 == "-v") {
            intro();
        } else if (p1 == "--tomesh" || p1 == "-tm") { // преобразование IP -> Meshname
            if (argc >= 3) {
                Address rawAddr;
                convertStrToRaw(argv[2], rawAddr);
                std::string mesh = getMeshname(rawAddr);
                std::cout << std::endl << pickupMeshnameForOutput(mesh) << std::endl;
                return 0;
            } else { error(-501); return -501; }
        } else if (p1 == "--toip" || p1 == "-ti") { // преобразование Meshname -> IP
            if (argc >= 3) {
                std::cout << std::endl << decodeMeshToIP(argv[2]) << std::endl;
                return 0;
            } else { error(-502); return -502; }

        ///////////////////////////////// Основные функции
        } else {
            int res = -1;
            for(int i = 1;; ++i) {
                if (argv[i] == nullptr) break;

                res = parameters(conf, std::string(argv[i]));
                if (res == 777) { // Нужно передать параметр
                    ++i;
                    if (argv[i] == nullptr) { // Значение параметра не передано
                        error(776);
                        std::cerr << " Empty value for parameter \"" << argv[i-1] << "\"" << std::endl;
                        return 776;
                    }

                    int res2 = parameters(conf, std::string( std::string(argv[i-1]) + " " + std::string(argv[i])) );
                    if (res2 != 0) { // Значение передано, но является некорректным
                        error(res);
                        std::cerr << " Wrong value \"" << argv[i] <<"\" for parameter \"" << argv[i-1] << "\"" << std::endl;
                        return res;
                    }
                }
            }
        }
    }
    else { without(); std::this_thread::sleep_for(std::chrono::seconds(1)); }

    intro();
    displayConfig();
    testOutput();
    startThreads();
}
