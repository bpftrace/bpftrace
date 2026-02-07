add_library(btf STATIC
  btf.cpp
  compat.cpp
  helpers.cpp
  irbuilder.cpp
)
add_dependencies(btf parser util)
target_link_libraries(btf util)
