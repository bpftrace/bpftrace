# - Try to find LLDB
# Once done this will define
#
#  LLDB_FOUND - system has lldb
#  LLDB_INCLUDE_DIRS - the lldb include directory
#  LLDB_LIBRARIES - Link these to use lldb
#
#  Copyright (c) 2008 Bernhard Walle <bernhard.walle@gmx.de>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

if (LLDB_LIBRARIES AND LLDB_INCLUDE_DIRS)
  set (LLDB_FIND_QUIETLY TRUE)
endif (LLDB_LIBRARIES AND LLDB_INCLUDE_DIRS)

find_path (LLDB_INCLUDE_DIRS
  NAMES
    lldb/API/LLDB.h
  PATHS
    ENV CPATH)

find_library (LLDB_LIBRARIES
  NAMES
    lldb
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)


# handle the QUIETLY and REQUIRED arguments and set LLDB_FOUND to TRUE if all listed variables are TRUE
include (FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LLDB "Please install the lldb development package"
  LLDB_LIBRARIES
  LLDB_INCLUDE_DIRS)

if (LLDB_FOUND)
  add_library(LLDB SHARED IMPORTED)
  set_target_properties(LLDB PROPERTIES
    INCLUDE_DIRECTORIES "${LLDB_INCLUDE_DIRS}"
    IMPORTED_LOCATION "${LLDB_LIBRARIES}")

  if (LLVM_VERSION_MAJOR VERSION_GREATER 10)
    set_target_properties(LLDB PROPERTIES
      IMPORTED_LINK_INTERFACE_LIBRARIES clang-cpp)
  else ()
    set_target_properties(LLDB PROPERTIES
      IMPORTED_LINK_INTERFACE_LIBRARIES libclang)
  endif ()
endif (LLDB_FOUND)

mark_as_advanced(LLDB_INCLUDE_DIRS LLDB_LIBRARIES)
