include(BuildBPF)
include(Embed)

bpf(base
  SOURCE  base.c
  BITCODE base.bc
  OBJECT  base.o
  BTF     base.btf
)

embed(
  base_btf
  base.btf
  OUTPUT  base_btf.h
  VAR     base_btf
  DEPENDS base
)

embed(
  base_bitcode
  base.bc
  OUTPUT  base_bc.h
  VAR     base_bc
  DEPENDS base
)

# The standard library holds these definitions internally via the headers
# above. This can be made more dynamic in the future (e.g. using dynamic
# initializers and registration), but given the size and scope the simpler
# solution is more desirable for now.

add_library(stdlib STATIC stdlib.cpp)
add_dependencies(stdlib base_bitcode base_btf)
