# - Try to find libebl static library
# Once done this will define
#
#  LIBEBL_FOUND - system has libebl
#  LIBEBL_LIBRARIES - Link these to use libebl

find_library(LIBEBL_LIBRARIES
  NAMES
    ebl
  PATH_SUFFIXES
    libebl
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibEbl "Please install the libebl static library"
  LIBEBL_LIBRARIES)

mark_as_advanced(LIBEBL_LIBRARIES)
