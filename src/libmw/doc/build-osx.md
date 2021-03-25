## Build Instructions

### Building (macOS)

1. `xcode-select --install`
2. `brew install cmake`
3. `git clone https://github.com/ltc-mweb/libmw.git --recursive`
4. `cd libmw/vcpkg/vcpkg && ./bootstrap-vcpkg.sh`
5. `./vcpkg install --triplet x64-osx @../packages.txt`
6. `cd ../.. && mkdir -p build && cd build`
7. `cmake -DCMAKE_BUILD_TYPE=Release .. && sudo cmake --build . --target install`

This should install the libmw headers in `/usr/local/include/libmw`, and the dylib in `/usr/local/lib`, allowing them to be found during when building the litecoin project.
