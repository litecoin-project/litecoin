## Building with MinGW

These instructions are for cross-compiling for Windows from a Linux environment (Ubuntu 20.04).
This also works from WSL.

### Pre-requisites

* CMake 3.8+
* Compiler with C++ 17 support (we recommend g++ 8 or later)
* Microsoft Powershell
* Ubuntu/Debian:

       sudo apt update
       sudo apt install build-essential tar curl zip unzip pkg-config
       sudo apt install g++-mingw-w64-x86-64 llvm

### Building (Linux)

1.     sudo update-alternatives --config x86_64-w64-mingw32-g++ # Set the default mingw32 g++ compiler option to posix.
2.     PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
3.     git clone https://github.com/ltc-mweb/libmw.git --recursive
4.     cd libmw/vcpkg/vcpkg && ./bootstrap-vcpkg.sh
5.     ./vcpkg install --triplet x64-mingw-static @../packages.txt
6.     cd ../.. && mkdir -p build && cd build
7.     cmake -DCMAKE_BUILD_TYPE=Release \
             -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=`pwd`/../cmake/mingw-w64-x86_64.cmake \
             -DVCPKG_TARGET_TRIPLET=x64-mingw-static \
             -DCMAKE_INSTALL_PREFIX=/path/to/litecoin/depends/x86_64-w64-mingw32 ..
8.     cmake --build . --target install

This should install the libmw headers in `/path/to/litecoin/depends/x86_64-w64-mingw32/include/libmw`, and the link library in `/path/to/litecoin/depends/x86_64-w64-mingw32/lib`, allowing them to be found when building the litecoin project.
