add_library(btf STATIC
  btf.cpp
  compat.cpp
  helper_protos.cpp
  helper_protos_table.cpp
  helpers.cpp
  irbuilder.cpp
)
add_dependencies(btf util)
target_link_libraries(btf util)
