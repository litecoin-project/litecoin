## Build Instructions

### Pre-requisites
* CMake 3.8+
* Compiler with C++ 17 support (we recommend g++ 8 or later)
* Ubuntu/Debian: `sudo apt-get update && sudo apt-get install build-essential tar curl zip unzip pkg-config`

### Building (Linux)

1. `git clone https://github.com/ltc-mweb/libmw.git --recursive`
2. `cd libmw/vcpkg/vcpkg && ./bootstrap-vcpkg.sh`
3. `./vcpkg install --triplet x64-linux @../packages.txt`
4. `cd ../.. && mkdir -p build && cd build`
5. `cmake -DCMAKE_BUILD_TYPE=Release .. && sudo cmake --build . --target install`

This should install the libmw headers in `/usr/local/include/libmw`, and the dylib in `/usr/local/lib`, allowing them to be found during when building the litecoin project.
