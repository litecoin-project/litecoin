cmake_minimum_required(VERSION 3.8)
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12" CACHE STRING "Minimum OS X deployment version")
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/vcpkg/scripts/buildsystems/vcpkg.cmake CACHE STRING "Vcpkg toolchain file")

project(LIBMW-LTC)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ListAppendParent.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetWarningLevel.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetOutputDir.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetOptimizations.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetCpp17.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetRuntimeLibrary.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetUsePthread.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SetVisibilityHidden.cmake)

set(CMAKE_MAP_IMPORTED_CONFIG_MINSIZEREL MinSizeRel Release)
set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO RelWithDebInfo Release)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(WITH_GFLAGS OFF)

# vcpkg deps
find_package(mio CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS filesystem thread)

# vendored deps
set_warning_level(2)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/deps/litecoin)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/deps/secp256k1-zkp)

# src
add_subdirectory(src)

# tests
option(MW_TESTS "Build tests" true)
if (MW_TESTS)
	add_subdirectory(test)
endif()