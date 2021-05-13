# - Try to find libz
# Once done this will define
#
#  LIBZ_FOUND - system has libz
#  LIBZ_LIBRARIES - Link these to use libz

find_library(LIBZ_LIBRARIES
  NAMES
    libz.a
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBZ_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibZ "Please install the libz package"
  LIBZ_LIBRARIES)

mark_as_advanced(LIBZ_LIBRARIES)
