add_library(symbols STATIC
  elf_parser.cpp
  kernel.cpp
  user.cpp
  )

target_compile_definitions(symbols PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")

target_link_libraries(symbols util btf ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
