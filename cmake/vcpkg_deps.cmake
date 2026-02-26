#set(VCPKG_CRT_LINKAGE dynamic)
#set(VCPKG_LIBRARY_LINKAGE static)

if (WIN32)
    #add_definitions(-DSPDLOG_WCHAR_FILENAMES)
    #add_definitions(-DSPDLOG_WCHAR_TO_UTF8_SUPPORT)
endif()
#find_package(spdlog CONFIG REQUIRED)
# target_link_libraries(main PRIVATE spdlog::spdlog spdlog::spdlog_header_only

find_package(nlohmann_json CONFIG REQUIRED)
#target_link_libraries(main PRIVATE nlohmann_json nlohmann_json::nlohmann_json)

#find_package(mio CONFIG REQUIRED)
#target_link_libraries(main PRIVATE mio::mio mio::mio_base mio::mio_full_winapi)

#add_definitions(-DUNICODE)
find_package(fmt CONFIG REQUIRED)
#target_link_libraries(main PRIVATE fmt::fmt fmt::fmt-header-only)

find_package(Catch2 CONFIG REQUIRED)
#target_link_libraries(main PRIVATE Catch2::Catch2)

find_package(Boost REQUIRED COMPONENTS filesystem thread)

#find_package(OpenSSL REQUIRED)

find_package(leveldb REQUIRED)

find_package(Qt5Core REQUIRED)
find_package(Qt5Gui REQUIRED)
find_package(Qt5Widgets REQUIRED)

if (MSVC)
    # VCPKG directories on Windows
    #include_directories(${VCPKG_ROOT}/installed/x64-windows/include/)
endif (MSVC)
