set_warning_level(4)

set(mw_sources "")
add_subdirectory(common)
add_subdirectory(traits)
add_subdirectory(models)
add_subdirectory(file)
add_subdirectory(crypto)
add_subdirectory(db)
add_subdirectory(mmr)
add_subdirectory(node)
add_subdirectory(wallet)
add_library(MW STATIC ${mw_sources})

target_link_libraries(MW PUBLIC
    litecoin
    fmt::fmt-header-only
    secp256k1-zkp
    mio::mio
    ${Boost_LIBRARIES}
)
target_include_directories(MW PUBLIC
	${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/deps/caches/include
    ${PROJECT_SOURCE_DIR}/deps/ghc/include
    ${Boost_INCLUDE_DIRS}
)

if (WIN32)
    target_compile_definitions(MW PUBLIC -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
endif()

if (WIN32)
    target_link_libraries(MW PUBLIC bcrypt)
endif()

add_subdirectory(libmw)