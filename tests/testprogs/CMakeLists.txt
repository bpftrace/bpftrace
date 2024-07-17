set_property(GLOBAL APPEND_STRING PROPERTY testprog_cflags "-g -O0")

# Check and add CFLAG to testprog_cflags
function(test_and_add_testprog_cflag flag)
  try_compile(FLAG_AVAILABLE
    ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/simple_struct.c
    LINK_OPTIONS ${flag}
  )
  if(${FLAG_AVAILABLE})
    set_property(GLOBAL APPEND_STRING PROPERTY testprog_cflags " ${flag}")
  else()
    message(STATUS "${CMAKE_C_COMPILER} does not support ${flag}")
  endif()
endfunction()

test_and_add_testprog_cflag("-fno-omit-frame-pointer")
test_and_add_testprog_cflag("-mno-omit-leaf-frame-pointer")
get_property(testprog_cflags GLOBAL PROPERTY testprog_cflags)

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
