# - Try to find libbfd
# Once done this will define
#
#  LIBBFD_FOUND - system has libbfd
#  LIBBFD_INCLUDE_DIRS - the libbfd include directory
#  LIBBFD_LIBRARIES - Link these to use libbfd
#  LIBBFD_DEFINITIONS - Compiler switches required for using libbfd

#if (LIBBFD_LIBRARIES AND LIBBFD_INCLUDE_DIRS)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBFD_LIBRARIES AND LIBBFD_INCLUDE_DIRS)

find_path (LIBBFD_INCLUDE_DIRS
  NAMES
    bfd.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBBFD_LIBRARIES
  NAMES
    bfd
  PATHS
    /lib
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBBFD_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBfd "Please install the libbfd development package"
  LIBBFD_LIBRARIES
  LIBBFD_INCLUDE_DIRS)

mark_as_advanced(LIBBFD_INCLUDE_DIRS LIBBFD_LIBRARIES)

SET(CMAKE_REQUIRED_LIBRARIES bfd opcodes)
INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES("
#include <string.h>
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
