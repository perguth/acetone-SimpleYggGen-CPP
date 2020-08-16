# SYG-CPP 1.1 "TRAIN"

### How build on windows under MSYS2 shell

* Run MSYS2 MinGW 64-bit shell
* Install required packages
```
pacman -S make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```
* Compile application
```
make -f Makefile.mingw
```
* Run it using `sygcpp.exe`

### How build on Linux

* Install required packages
```
sudo apt-get install make g++ libssl-dev
```
* Compile application
```
make -f Makefile.linux
```
* Run it using `./sygcpp`
