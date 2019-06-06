# - Try to find libbpf
# Once done this will define
#
#  LIBBPF_FOUND - system has libbpf
#  LIBBPF_INCLUDE_DIRS - the libbpf include directory
#  LIBBPF_LIBRARIES - Link these to use libbpf
#  LIBBPF_DEFINITIONS - Compiler switches required for using libbpf

#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)

find_path (LIBBPF_INCLUDE_DIRS
  NAMES
    bpf/bpf.h
    bpf/btf.h
    bpf/libbpf.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH)

find_library (LIBBPF_LIBRARIES
  NAMES
    bpf
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf "Please install the libbpf development package"
  LIBBPF_LIBRARIES
  LIBBPF_INCLUDE_DIRS)

mark_as_advanced(LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES)
