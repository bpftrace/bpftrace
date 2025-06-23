add_library(output STATIC
  json.cpp
  output.cpp
  text.cpp
  )
target_link_libraries(output util)
