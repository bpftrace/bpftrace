# - Try to find libdw
# Once done this will define
#
#  LIBDW_FOUND - system has libdw
#  LIBDW_INCLUDE_DIRS - the libdw include directory
#  LIBDW_LIBRARIES - Link these to use libdw
#  LIBDW_DEFINITIONS - Compiler switches required for using libdw
#

if (LIBDW_LIBRARIES AND LIBDW_INCLUDE_DIRS)
  set (LibDw_FIND_QUIETLY TRUE)
endif (LIBDW_LIBRARIES AND LIBDW_INCLUDE_DIRS)

find_path (LIBDW_INCLUDE_DIRS
  NAMES
    libdw.h
    libdwfl.h
  PATH_SUFFIXES
    elfutils
    libdw
  PATHS
    ENV CPATH)

find_library (LIBDW_LIBRARIES
  NAMES
    dw
  PATH_SUFFIXES
    elfutils
    libdw
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBDW_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibDw "Please install the libdw development package"
  LIBDW_LIBRARIES
  LIBDW_INCLUDE_DIRS)

mark_as_advanced(LIBDW_INCLUDE_DIRS LIBDW_LIBRARIES)
