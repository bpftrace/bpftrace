# - Try to find libblazesym
# Once done this will define
#
#  LIBBLAZESYM_FOUND - system has libblazesym
#  LIBBLAZESYM_INCLUDE_DIRS - the libblazesym include directory
#  LIBBLAZESYM_LIBRARIES - Link these to use libblazesym
#


find_path (LIBBLAZESYM_INCLUDE_DIRS
  NAMES
    blazesym.h
  PATHS
    ENV CPATH)

find_library (LIBBLAZESYM_LIBRARIES
  NAMES
    blazesym_c
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBlazesym "Please install the libblazesym development package"
  LIBBLAZESYM_LIBRARIES
  LIBBLAZESYM_INCLUDE_DIRS)

mark_as_advanced(LIBBLAZESYM_INCLUDE_DIRS LIBBLAZESYM_LIBRARIES)
