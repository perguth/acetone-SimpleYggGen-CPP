## Address miner for Yggdrasil 0.4.x and higher
Starting with version 0.4.0 Yggdrasil Network uses the new IPv6 address generation algorithm. Since version **5.0**, SimpleYggGen only supports the new algorithm. 

### How to build
- `sudo apt-get install make qt5-qmake g++ libssl-dev`
- `qmake && make`
- `./sygcpp`