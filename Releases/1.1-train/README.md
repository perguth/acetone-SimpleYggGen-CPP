# SYG-CPP

### How build on windows under MSYS2 shell

* Run MSYS2 MinGW 64-bit shell
* Install required packages
```bash
pacman -S make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```
* Compile application
```bash
make -f Makefile.mingw
```
* Run it using `sygcpp.exe`