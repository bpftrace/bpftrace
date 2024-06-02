# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND - system has libbpf
#  LIBBPF_INCLUDE_DIRS - the libbpf include directory
#  LIBBPF_LIBRARIES - Link these to use libbpf
#  LIBBPF_DEFINITIONS - Compiler switches required for using libbpf
#  LIBBPF_VERSION_MAJOR - Libbpf major version
#  LIBBPF_VERSION_MINOR - Libbpf minor version

#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)

find_path (LIBBPF_INCLUDE_DIRS
  NAMES
    bpf/bpf.h
    bpf/btf.h
    bpf/libbpf.h
  PATHS
    ENV CPATH)

find_library (LIBBPF_LIBRARIES
  NAMES
    bpf
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)
set(LIBBPF_ERROR_MESSAGE "Please install the libbpf development package")

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf ${LIBBPF_ERROR_MESSAGE}
  LIBBPF_LIBRARIES
  LIBBPF_INCLUDE_DIRS)

# Parse version information out of libbpf_version.h
if(EXISTS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h")
  file(READ "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" version_header)
  string(REGEX MATCH "LIBBPF_MAJOR_VERSION[ \t]+([0-9]+)" major_match "${version_header}")
  string(REGEX MATCH "LIBBPF_MINOR_VERSION[ \t]+([0-9]+)" minor_match "${version_header}")
  string(REGEX REPLACE "LIBBPF_MAJOR_VERSION[ \t]+" "" LIBBPF_VERSION_MAJOR "${major_match}")
  string(REGEX REPLACE "LIBBPF_MINOR_VERSION[ \t]+" "" LIBBPF_VERSION_MINOR "${minor_match}")
else()
  set(LIBBPF_VERSION_MAJOR 0)
  set(LIBBPF_VERSION_MINOR 0)
  message(SEND_ERROR "Libbpf version is too old and does not have libbpf_version.h, which was introduced in v0.6")
endif()

mark_as_advanced(LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES LIBBPF_VERSION_MAJOR LIBBPF_VERSION_MINOR)

INCLUDE(CheckCXXSourceCompiles)
SET(CMAKE_REQUIRED_INCLUDES ${LIBBPF_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_LIBRARIES ${LIBBPF_LIBRARIES} elf z)

CHECK_CXX_SOURCE_COMPILES("
#include <bpf/bpf.h>

int main(void) {
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);

  opts.uprobe_multi.flags = 0;
  return 0;
}
" HAVE_LIBBPF_UPROBE_MULTI)
SET(CMAKE_REQUIRED_INCLUDES)
SET(CMAKE_REQUIRED_LIBRARIES)
