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

# Parse version information from blazesym.h header file.
file(READ "${LIBBLAZESYM_INCLUDE_DIRS}/blazesym.h" header_top LIMIT 256)
string(REGEX MATCH "https://docs\.rs/blazesym-c/([0-9]+)\\.([0-9]+)\\.([0-9]+)\n" docsrs_match "${header_top}")
set(LIBBLAZESYM_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(LIBBLAZESYM_VERSION_MINOR "${CMAKE_MATCH_2}")
set(LIBBLAZESYM_VERSION_PATCH "${CMAKE_MATCH_3}")
set(LIBBLAZESYM_VERSION "${LIBBLAZESYM_VERSION_MAJOR}.${LIBBLAZESYM_VERSION_MINOR}.${LIBBLAZESYM_VERSION_PATCH}")

message(STATUS "Found libblazesym version ${LIBBLAZESYM_VERSION}")

mark_as_advanced(LIBBLAZESYM_INCLUDE_DIRS LIBBLAZESYM_LIBRARIES)
