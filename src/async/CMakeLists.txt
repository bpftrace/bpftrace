add_library(async STATIC
  functions.cpp
  memory.cpp
  relocations.cpp
  )

target_link_libraries(async arch util)
