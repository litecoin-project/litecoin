if(WIN32)
    configure_file(${CMAKE_CURRENT_LIST_DIR}/libsecp256k1-config.h ${CMAKE_CURRENT_LIST_DIR}/src/libsecp256k1-config.h COPYONLY)
else()
    include_directories(${GOBJECT_INCLUDE_DIR})
    configure_file(${CMAKE_CURRENT_LIST_DIR}/libsecp256k1-config-nix.h ${CMAKE_CURRENT_LIST_DIR}/src/libsecp256k1-config.h COPYONLY)
endif()

add_library(secp256k1-zkp STATIC ${CMAKE_CURRENT_LIST_DIR}/src/secp256k1.c)
target_compile_definitions(secp256k1-zkp PRIVATE HAVE_CONFIG_H)
target_include_directories(secp256k1-zkp
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)