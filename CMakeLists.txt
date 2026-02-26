cmake_minimum_required(VERSION 3.10)
project(litecoin24)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(fmt CONFIG REQUIRED)
#target_link_libraries(main PRIVATE fmt::fmt fmt::fmt-header-only)
#find_package(Catch2 CONFIG REQUIRED)
#find_package(Boost REQUIRED COMPONENTS filesystem thread)
#find_package(OpenSSL REQUIRED)
find_package(leveldb REQUIRED)

#set(Qt5Core_DIR "C:\\Qt_static\\lib\\cmake\\Qt5Core")
#set(Qt5Gui_DIR "C:\\Qt_static\\lib\\cmake\\Qt5Gui")
#set(Qt5Widgets_DIR "C:\\Qt_static\\lib\\cmake\\Qt5Widgets")

find_package(Qt5Core REQUIRED)
find_package(Qt5Gui REQUIRED)
find_package(Qt5Widgets REQUIRED)
find_package(Threads REQUIRED)

file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/consensus *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/index *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/init *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/interfaces *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/ipc *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/kernel *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/libmw/src *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/libmw/test *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/mweb *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/node *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/policy *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/primitives *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/qt *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/rpc *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/script *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/support *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/util *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/wallet *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/wallet/spkman *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/wallet/rpc *.cpp *.c *.cc *.h *.hpp)
file(GLOB_RECURSE SOURCES_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/zmq *.cpp *.c *.cc *.h *.hpp)

message("VCPKG_ROOT: ${VCPKG_ROOT}")
message("CMAKE_TOOLCHAIN_FILE: ${CMAKE_TOOLCHAIN_FILE}")

add_executable(litecoin24 ${SOURCES_FILES})
target_include_directories(litecoin24 PRIVATE
    src
    src/crc32c/include
    src/libmw/deps/caches/include
    src/libmw/deps/mio/include
    src/libmw/include
    src/libmw/test/framework/include
    src/qt
    src/secp256k1/include
    src/univalue/include
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(litecoin24 PUBLIC libdb48 leveldb::leveldb fmt::fmt Qt5::Core Qt5::Gui Qt5::Widgets) # Catch2::Catch2 ${Boost_LIBRARIES} Qt5::Core Qt5::Gui Qt5::Widgets #OpenSSL::SSL OpenSSL::Crypto
target_compile_definitions(litecoin24 PRIVATE PACKAGE_NAME="Litecoin Core" COPYRIGHT_YEAR="2018" NOMINMAX=1 HAVE_CONFIG_H=1)
