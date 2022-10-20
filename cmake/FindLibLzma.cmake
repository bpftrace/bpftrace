# - Try to find liblzma
# Once done this will define
#
#  LIBLZMA_FOUND - system has liblzma
#  LIBLZMA_LIBRARIES - Link these to use liblzma

find_library(LIBLZMA_LIBRARIES
  NAMES
    liblzma.a
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibLzma "Please install the liblzma package"
  LIBLZMA_LIBRARIES)

mark_as_advanced(LIBLZMA_LIBRARIES)
