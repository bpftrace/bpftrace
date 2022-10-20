# - Try to find libbz2
# Once done this will define
#
#  LIBBZ2_FOUND - system has libbz2
#  LIBBZ2_LIBRARIES - Link these to use libbz2

find_library(LIBBZ2_LIBRARIES
  NAMES
    libbz2.a
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBz2 "Please install the libbz2 package"
  LIBBZ2_LIBRARIES)

mark_as_advanced(LIBBZ2_LIBRARIES)
