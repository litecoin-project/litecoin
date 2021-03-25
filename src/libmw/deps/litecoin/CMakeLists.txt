set(TARGET_NAME litecoin)

file(GLOB SOURCE_CODE
    fs.cpp
    hash.cpp
    logging.cpp
    sync.cpp
    uint256.cpp
    crypto/bech32.cpp
    crypto/hmac_sha256.cpp
    crypto/hmac_sha512.cpp
    crypto/ripemd160.cpp
    crypto/sha256.cpp
    crypto/sha512.cpp
    crypto/scrypt/crypto_scrypt-ref.cpp
    crypto/scrypt/sha256.cpp
    support/cleanse.cpp
    support/lockedpool.cpp
    util/strencodings.cpp
    util/time.cpp
)

add_library(${TARGET_NAME} STATIC ${SOURCE_CODE})

if (WIN32)
    target_link_libraries(${TARGET_NAME} PUBLIC ws2_32)
endif()


target_include_directories(${TARGET_NAME} PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(${TARGET_NAME} PUBLIC ${Boost_LIBRARIES})

target_compile_definitions(${TARGET_NAME} PUBLIC
    CLIENT_VERSION_MAJOR=1
    CLIENT_VERSION_MINOR=17
    CLIENT_VERSION_REVISION=99
    CLIENT_VERSION_BUILD=0
    CLIENT_VERSION_IS_RELEASE=false
    COPYRIGHT_YEAR=2018
    HAVE_WORKING_BOOST_SLEEP_FOR
)
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR})# ${CMAKE_CURRENT_LIST_DIR}/leveldb/helpers/memenv ${CMAKE_CURRENT_LIST_DIR}/leveldb)
