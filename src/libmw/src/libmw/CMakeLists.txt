add_library(libmw SHARED "libmw.cpp"  "Transformers.h" "libmw_node.cpp" "libmw_wallet.cpp" "defs.cpp" "libmw_miner.cpp")

target_link_libraries(libmw PRIVATE MW)
target_compile_definitions(libmw PRIVATE LIBMW)
set_target_properties(libmw PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN 1
    PREFIX ""
)

# install includes
install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include/libmw/
    DESTINATION include/libmw
)
    
# Install library
install(
    TARGETS libmw
    LIBRARY DESTINATION lib
)