set(TARGET_NAME crypto_deps)

set(CRYPTO_SOURCES
    src/blake2b.cpp
)

add_library(${TARGET_NAME} STATIC ${CRYPTO_SOURCES})
target_include_directories(${TARGET_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/crypto)
target_compile_definitions(${TARGET_NAME} PRIVATE HAVE_SCRYPT_CONFIG_H)