add_library(btf STATIC
  btf.cpp
  compat.cpp
  helpers.cpp
  irbuilder.cpp
)
add_dependencies(btf parser)
