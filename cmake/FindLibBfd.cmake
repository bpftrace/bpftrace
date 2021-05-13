# - Try to find libbfd
# Once done this will define
#
#  LIBBFD_FOUND - system has libbfd
#  LIBBFD_INCLUDE_DIRS - the libbfd include directory
#  LIBBFD_LIBRARIES - Link these to use libbfd
#  LIBBFD_DEFINITIONS - Compiler switches required for using libbfd
#  LIBIBERTY_LIBRARIES - libiberty static library (for static compilation)
#  LIBZ_LIBRARIES - libz static library (for static compilation)

#if (LIBBFD_LIBRARIES AND LIBBFD_INCLUDE_DIRS)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBFD_LIBRARIES AND LIBBFD_INCLUDE_DIRS)

find_path (LIBBFD_INCLUDE_DIRS
  NAMES
    bfd.h
  PATHS
    ENV CPATH)

find_library (LIBBFD_LIBRARIES
  NAMES
    bfd
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

# libbfd.so is statically linked with libiberty.a but libbfd.a
# is not. So if we do a static bpftrace build, we must link in
# libiberty.a
find_library (LIBIBERTY_LIBRARIES
  NAMES
    libiberty.a
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBBFD_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBfd "Please install the libbfd development package"
  LIBBFD_LIBRARIES
  LIBBFD_INCLUDE_DIRS)

mark_as_advanced(LIBBFD_INCLUDE_DIRS LIBBFD_LIBRARIES)

if(${LIBBFD_FOUND})
find_package(LibOpcodes)
SET(CMAKE_REQUIRED_LIBRARIES ${LIBBFD_LIBRARIES} ${LIBOPCODES_LIBRARIES})
# libbfd.a is not statically linked with libiberty.a or libz.a so we must manually
# do it. Furthermore, libbfd uses some libc symbols that we must manually
# link against if we're not using static libc (which includes such symbols).
if(STATIC_LINKING)
  find_package(LibZ)
  list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBIBERTY_LIBRARIES} ${LIBZ_LIBRARIES})
  if(NOT STATIC_LIBC)
    set(CMAKE_REQUIRED_FLAGS
      "-Wl,--start-group -Wl,-Bdynamic -Wl,-Bdynamic -lpthread -Wl,-Bdynamic -ldl")
  endif()
endif()
INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES("
#include <string.h>
// See comment in bfd-disasm.cpp for why this needs to exist
#define PACKAGE \"bpftrace-test\"
#include <bfd.h>
#include <dis-asm.h>
int main(void) {
  bfd *abfd = bfd_openr(NULL, NULL);

  disassembler(bfd_get_arch(abfd),
               bfd_big_endian(abfd),
               bfd_get_mach(abfd),
               abfd);
  return 0;
}" LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
SET(CMAKE_REQUIRED_LIBRARIES)
endif()
