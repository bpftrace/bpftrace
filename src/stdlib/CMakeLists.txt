include(Embed)

embed(
  base_c
  ${CMAKE_CURRENT_SOURCE_DIR}/base.c
  OUTPUT  base_c.h
  VAR     base_c
)

embed(
  base_bt
  ${CMAKE_CURRENT_SOURCE_DIR}/base.bt
  OUTPUT  base_bt.h
  VAR     base_bt
)

foreach(header in float limits stdarg stdbool stddef __stddef_max_align_t stdint)
  embed(
    "${header}_header"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/${header}.h"
    OUTPUT "${header}.h"
    VAR    "${header}_h"
  )
endforeach()

# The standard library holds these definitions internally via the headers
# above. This can be made more dynamic in the future (e.g. using dynamic
# initializers and registration), but given the size and scope the simpler
# solution is more desirable for now.

add_library(stdlib STATIC stdlib.cpp)
add_dependencies(stdlib
  base_c
  base_bt
  float_header
  limits_header
  stdarg_header
  stdbool_header
  stddef_header
  __stddef_max_align_t_header
  stdint_header
)
