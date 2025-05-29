# Functions to build intermediate BPF modules.
#
# The `bpf` function will produce bitcode, an object as well as the BTF type
# information for a given file. The `btf_header` function can be used to
# produce a C header for a given BTF source file (often the kernel, but it
# can be the output from any `bpf` rule, for example).

find_program(GCC gcc REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)
find_program(PAHOLE pahole REQUIRED)
find_program(NM nm REQUIRED)
find_program(AWK awk REQUIRED)
find_program(LLVM_OBJCOPY
  NAMES llvm-objcopy llvm-objcopy-${LLVM_VERSION_MAJOR} llvm${LLVM_VERSION_MAJOR}-objcopy
  REQUIRED)
find_program(CLANG
  NAMES clang-${LLVM_VERSION_MAJOR}
  REQUIRED)

function(btf_header NAME SOURCE)
  cmake_parse_arguments(
    ARG
    ""
    "OUTPUT"
    ""
    ${ARGN}
  )
  if (NOT DEFINED ARG_OUTPUT)
    set(ARG_OUTPUT "${NAME}.h")
  endif ()
  add_custom_command(
    OUTPUT ${ARG_OUTPUT}
    COMMAND ${BPFTOOL} btf dump file "${ARG_SOURCE}" format c > ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OUTPUT}
    VERBATIM
  )
  add_custom_target(${NAME}
    DEPENDS ${ARG_OUTPUT}
  )
endfunction()

function(bpf NAME)
  cmake_parse_arguments(
    ARG
    ""
    "BITCODE;OBJECT;BINARY;BTF;SOURCE;BTF_BASE;FUNCTIONS"
    "DEPENDS"
    ${ARGN}
  )
  if (NOT DEFINED ARG_SOURCE)
    set(ARG_SOURCE "${NAME}.c")
  endif ()
  if (NOT DEFINED ARG_OBJECT)
    set(ARG_OBJECT "${NAME}.o")
  endif ()
  add_custom_target(${NAME})
  # The joys of BPF & debug tooling 101.
  #
  # The purpose for this function is to generate various types of output for a
  # given source file, for testing and embedding purposes:
  #  * LLVM bitcode file compatible with our major version of LLVM.
  #  * A binary annotated with DWARF type information.
  #  * Encoded BTF type information for this source unit.
  #  * A list of functions defined in the file.
  #
  # Naturally, you'd assume that this could be implementated mostly as a chain
  # of steps, save the intermediate results along the way. Wrong! Unfortunately,
  # each of these steps has their own happy path.
  #
  # First, the bitcode. This is actually straight-forward! We need to ensure
  # that this gets built with the correct version of LLVM (not whatever
  # compiler CMAKE has selected) so that it is compatible with the LLVM
  # libraries that we are linking against. We can even correctly select bpf as
  # our target, to get the extent that there is any early specialization.
  #
  # Next, you might assume that taking this bitcode and turning it into a BPF
  # object is the logical thing to do, in order to ensure that all the types
  # are compatible and consistent. In fact, this even *seems* to work. But
  # after banging your head on the keyboard for a while, you'll realize that
  # something is broken. As you contort clang, and try building from scratch,
  # you'll realize that clang seems to generate proper annotations and
  # relocations for loadable programs (the happy path for that!), but fails to
  # generate the same types for base types. In fact, in doesn't even generate
  # named arguments without an explicit `-O2`.  Oh well, I suppose that the
  # common path for the kernel is to build with `gcc` and then rely on the
  # `pahole` conversion. Let's do that.
  #
  # But hold on a second, we said that we wanted to build a BPF target? Turns
  # out that `gcc` can't do that very well. So `clang` can't build our BPF
  # target because of incorrect BTF, and `gcc` can't build the BPF target. So
  # we need to build the source natively, use `pahole` to generate the BTF
  # data, and then extract that separately. This makes some sense, as it is the
  # kernel happy path.
  #
  # But at least what we built above has the DWARF data, right? Wrong! If we
  # were to link the full binary, too much gets stripped out to generate the
  # full set of BTF information. So we need to generate just the object, add
  # BTF information, and separately link that single object into a binary to
  # have the DWARF data in a ELF binary that we're looking for.
  #
  # Finally, we can breath a sight of relief and generate our list of
  # functions. Like the bitcode, this works as expected.
  if (DEFINED ARG_BITCODE)
    add_custom_command(
      OUTPUT ${ARG_BITCODE}
      DEPENDS ${ARG_SOURCE} ${ARG_DEPENDS}
      # Note that we specifically run this in the source directory because the
      # source filename will be encoded in the bitcode, and we want it to only
      # contain the relative filename.
      COMMAND ${CLANG} -ffile-prefix-map=${CMAKE_SOURCE_DIR}/=/ -emit-llvm -g -target bpf -D__TARGET_ARCH_x86 -I ${CMAKE_CURRENT_BINARY_DIR} -c ${ARG_SOURCE} -o ${CMAKE_CURRENT_BINARY_DIR}/${ARG_BITCODE}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      VERBATIM
    )
    add_custom_target(${NAME}_gen_bitcode DEPENDS ${ARG_BITCODE})
    add_dependencies(${NAME} ${NAME}_gen_bitcode)
  endif()
  add_custom_command(
    OUTPUT ${ARG_OBJECT}
    DEPENDS ${ARG_SOURCE} ${ARG_DEPENDS}
    # See above: fresh compilation and the use of `gcc`.
    COMMAND ${GCC} -Wno-attributes -g -I ${CMAKE_CURRENT_BINARY_DIR} -c ${CMAKE_CURRENT_SOURCE_DIR}/${ARG_SOURCE} -o ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OBJECT}
    COMMAND cmake -E env LLVM_OBJCOPY=${LLVM_OBJCOPY} ${PAHOLE} -J ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OBJECT}
    VERBATIM
  )
  # You should never depend on the output of a custom command more than once.
  # Therefore, we define an intermediate target for the object, and depend on
  # this instead. See [1].
  # [1] https://discourse.cmake.org/t/how-to-avoid-parallel-build-race-conditions/727
  add_custom_target(
    ${NAME}_gen_object
    DEPENDS ${ARG_OBJECT}
  )
  add_dependencies(${NAME} ${NAME}_gen_object)
  if (DEFINED ARG_BINARY)
    add_custom_command(
      OUTPUT ${ARG_BINARY}
      DEPENDS ${ARG_SOURCE} ${NAME}_gen_object
      COMMAND ${GCC} -g -o ${CMAKE_CURRENT_BINARY_DIR}/${ARG_BINARY} ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OBJECT}
      COMMAND cmake -E env LLVM_OBJCOPY=${LLVM_OBJCOPY} ${PAHOLE} -J ${CMAKE_CURRENT_BINARY_DIR}/${ARG_BINARY}
      VERBATIM
    )
    add_custom_target(${NAME}_gen_binary DEPENDS ${ARG_BINARY})
    add_dependencies(${NAME} ${NAME}_gen_binary)
  endif()
  if (DEFINED ARG_BTF)
    add_custom_command(
      OUTPUT ${ARG_BTF}
      DEPENDS ${ARG_SOURCE} ${NAME}_gen_object
      # See above re: the use of the `gcc`-compiled object, ignoring the binary.
      COMMAND ${LLVM_OBJCOPY} --dump-section .BTF=${CMAKE_CURRENT_BINARY_DIR}/${ARG_BTF} ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OBJECT}
      VERBATIM
    )
    add_custom_target(${NAME}_gen_btf DEPENDS ${ARG_BTF})
    add_dependencies(${NAME} ${NAME}_gen_btf)
  endif ()
  if (DEFINED ARG_FUNCTIONS)
    add_custom_command(
      OUTPUT ${ARG_FUNCTIONS}
      DEPENDS ${ARG_SOURCE} ${NAME}_gen_object
      COMMAND ${NM} ${CMAKE_CURRENT_BINARY_DIR}/${ARG_OBJECT} | ${AWK} -v ORS=\\\\n "$2 == \"T\" { print $3 }" > ${CMAKE_CURRENT_BINARY_DIR}/${ARG_FUNCTIONS}
      VERBATIM
    )
    add_custom_target(${NAME}_gen_functions DEPENDS ${ARG_FUNCTIONS})
    add_dependencies(${NAME} ${NAME}_gen_functions)
  endif ()
endfunction()
