# SYGCPP

### How build on windows under MSYS2 shell

* Run MSYS2 MinGW 64-bit shell
* Install required packages

```bash
pacman -S make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

* Compile application

```bash
make
```

* Run it using `sygcpp.exe`

### How build on Linux

* Install required packages

```
sudo apt-get install make g++ libssl-dev
```

* Compile application

```
make
```

* Run it using `./sygcpp`

*Note*: If you want compile static binary, add `STATIC=yes` or `STATIC=full` to `make` command. That works only on Linux.
