# - Try to find libopcodes
# Once done this will define
#
#  LIBOPCODES_FOUND - system has libopcodes
#  LIBOPCODES_INCLUDE_DIRS - the libopcodes include directory
#  LIBOPCODES_LIBRARIES - Link these to use libopcodes
#  LIBOPCODES_DEFINITIONS - Compiler switches required for using libopcodes

#if (LIBOPCODES_LIBRARIES AND LIBOPCODES_INCLUDE_DIRS)
#  set (LibBpf_FIND_QUIETLY TRUE)
#endif (LIBOPCODES_LIBRARIES AND LIBOPCODES_INCLUDE_DIRS)

find_path (LIBOPCODES_INCLUDE_DIRS
  NAMES
    dis-asm.h
  PATHS
    ENV CPATH)

find_library (LIBOPCODES_LIBRARIES
  NAMES
    opcodes
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBOPCODES_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibOpcodes "Please install the libopcodes development package"
  LIBOPCODES_LIBRARIES
  LIBOPCODES_INCLUDE_DIRS)

mark_as_advanced(LIBOPCODES_INCLUDE_DIRS LIBOPCODES_LIBRARIES)
