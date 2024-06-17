set(testprog_cflags "-g -O0 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer")
if(LLVM_VERSION_MAJOR VERSION_LESS 13)
  # CI's GCC compile the testprogs using DWARF version 5
  # LLDB doesn't support DWARF5 before version 13, so we force DWARF4
  set(testprog_cflags "${testprog_cflags} -gdwarf-4")
endif()

file(GLOB testprog_sources CONFIGURE_DEPENDS *.c)
set(testprogtargets "")
foreach(testprog_source ${testprog_sources})
  get_filename_component(testprog_name ${testprog_source} NAME_WE)
  add_executable(${testprog_name} ${testprog_source})
  set_target_properties(${testprog_name}
    PROPERTIES
      LINK_SEARCH_START_STATIC FALSE
      LINK_SEARCH_END_STATIC FALSE
      COMPILE_FLAGS "${testprog_cflags}"
      LINK_FLAGS "-no-pie")
  if(HAVE_SYSTEMTAP_SYS_SDT_H)
    target_compile_definitions(${testprog_name} PRIVATE HAVE_SYSTEMTAP_SYS_SDT_H)
  endif(HAVE_SYSTEMTAP_SYS_SDT_H)
  list(APPEND testprogtargets ${testprog_name})
endforeach()
add_custom_target(testprogs DEPENDS ${testprogtargets})

target_include_directories(usdt_lib PUBLIC ${CMAKE_SOURCE_DIR}/tests/testlibs/)
target_compile_options(usdt_lib PRIVATE -fPIC)
target_link_libraries(usdt_lib usdt_tp)
