# - Try to find libbcc
# Once done this will define
#
#  LIBBCC_FOUND - system has libbcc
#  LIBBCC_INCLUDE_DIRS - the libbcc include directory
#  LIBBCC_LIBRARIES - Link these to use libbcc
#  LIBBCC_DEFINITIONS - Compiler switches required for using libbcc

if (LIBBCC_LIBRARIES AND LIBBCC_INCLUDE_DIRS)
  set (LibBcc_FIND_QUIETLY TRUE)
endif (LIBBCC_LIBRARIES AND LIBBCC_INCLUDE_DIRS)

find_path (LIBBCC_INCLUDE_DIRS
  NAMES
    libbpf.h
  PATHS
    /usr/include
    /usr/include/bcc
    /usr/local/include
    /usr/local/include/libbcc
    /opt/local/include
    /opt/local/include/libbcc
    /sw/include
    /sw/include/libbcc
    ENV CPATH)

find_library (LIBBCC_LIBRARIES
  NAMES
    bcc
  PATHS
    /usr/lib
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBBCC_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBcc "Please install the bcc library package, which is required. Depending on your distro, it may be called bpfcclib or bcclib (Ubuntu), bcc-devel (Fedora), or something else. If unavailable, install bcc from source (github.com/iovisor/bcc)."
  LIBBCC_LIBRARIES
  LIBBCC_INCLUDE_DIRS)
