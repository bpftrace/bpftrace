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

file(GLOB testprog_sources CONFIGURE_DEPENDS *.c *.cpp)
set(testprogtargets "")
function(testprog_compile is_pie)
  foreach(testprog_source ${testprog_sources})
    get_filename_component(testprog_name ${testprog_source} NAME_WE)
    set(extra_cflags "")
    set(ldflags "-no-pie")
    if(is_pie)
      set(testprog_name "${testprog_name}-pie")
      set(extra_cflags "-fpie")
      set(ldflags "-pie")
    endif()
    add_executable(${testprog_name} ${testprog_source})
    set_target_properties(${testprog_name}
      PROPERTIES
        LINK_SEARCH_START_STATIC FALSE
        LINK_SEARCH_END_STATIC FALSE
        COMPILE_FLAGS "${testprog_cflags} ${extra_cflags}"
        LINK_FLAGS "${ldflags}")
    target_include_directories(${testprog_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
    list(APPEND testprogtargets ${testprog_name})
  endforeach()
endfunction()
# Compile all test programs into PIE and non-PIE ELF executables.
testprog_compile(FALSE)
testprog_compile(TRUE)

# uprobe_nofp must be compiled without frame pointers so that only
# DWARF-based stack unwinding can produce a full stack trace.
foreach(prog uprobe_nofp uprobe_nofp-pie)
  set_target_properties(${prog} PROPERTIES COMPILE_FLAGS "-g -O1 -fomit-frame-pointer -fno-optimize-sibling-calls")
endforeach()

find_program(GO_EXECUTABLE go)
if(GO_EXECUTABLE)
  file(GLOB testprog_go_sources CONFIGURE_DEPENDS *.go)
  foreach(testprog_source ${testprog_go_sources})
    get_filename_component(testprog_name ${testprog_source} NAME_WE)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${testprog_name}
      COMMAND ${GO_EXECUTABLE} build -o ${CMAKE_CURRENT_BINARY_DIR}/${testprog_name} ${testprog_source}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      DEPENDS ${testprog_source}
    )
    list(APPEND testprogtargets ${testprog_name})
  endforeach()
endif()

find_program(RUSTC_EXECUTABLE rustc)
if(RUSTC_EXECUTABLE)
  file(GLOB testprog_rust_sources CONFIGURE_DEPENDS *.rs)
  foreach(testprog_source ${testprog_rust_sources})
    get_filename_component(testprog_name ${testprog_source} NAME_WE)
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${testprog_name}
      COMMAND ${RUSTC_EXECUTABLE} -C symbol_mangling_version=v0 -o ${CMAKE_CURRENT_BINARY_DIR}/${testprog_name} ${testprog_source}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      DEPENDS ${testprog_source}
    )
    list(APPEND testprogtargets ${testprog_name})
  endforeach()
endif()

add_custom_target(testprogs ALL DEPENDS ${testprogtargets})

foreach(prog usdt_lib usdt_lib-pie)
  target_include_directories(${prog} PRIVATE ${CMAKE_SOURCE_DIR}/tests/testlibs/)
  target_compile_options(${prog} PRIVATE -fPIC)
  target_link_libraries(${prog} usdt_tp)
endforeach()
