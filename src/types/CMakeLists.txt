add_library(types STATIC
  types.cpp
  helpers.cpp
  irbuilder.cpp
)

llvm_map_components_to_libnames(llvm_libs codegen)
target_link_libraries(types ${LIBBPF_LIBRARIES} ${llvm_libs})
