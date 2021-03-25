find_package(Catch2 CONFIG REQUIRED)

string(REGEX REPLACE "-Werror" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
set_warning_level(2)

set(test_sources "TestMain.cpp")
add_subdirectory(framework)
add_subdirectory(tests/consensus)
add_subdirectory(tests/crypto)
add_subdirectory(tests/db)
add_subdirectory(tests/mmr)
add_subdirectory(tests/models)
add_subdirectory(tests/node)
add_subdirectory(tests/serialization)
add_subdirectory(tests/wallet)

add_executable(Tests ${test_sources})
target_link_libraries(Tests MW Catch2::Catch2 libmw)
target_include_directories(Tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/framework/include)

include(CTest)
include(Catch)
catch_discover_tests(Tests)

add_custom_command(
    TARGET Tests POST_BUILD
    COMMAND ctest -C $<CONFIGURATION> --output-on-failure
)