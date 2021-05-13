# - Try to find libelf
# Once done this will define
#
#  LIBELF_FOUND - system has libelf
#  LIBELF_INCLUDE_DIRS - the libelf include directory
#  LIBELF_LIBRARIES - Link these to use libelf
#  LIBELF_DEFINITIONS - Compiler switches required for using libelf
#
#  Copyright (c) 2008 Bernhard Walle <bernhard.walle@gmx.de>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#


if (LIBELF_LIBRARIES AND LIBELF_INCLUDE_DIRS)
  set (LibElf_FIND_QUIETLY TRUE)
endif (LIBELF_LIBRARIES AND LIBELF_INCLUDE_DIRS)

find_path (LIBELF_INCLUDE_DIRS
  NAMES
    libelf.h
  PATH_SUFFIXES
    libelf
  PATHS
    ENV CPATH)

find_library (LIBELF_LIBRARIES
  NAMES
    elf
  PATH_SUFFIXES
    libelf
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBELF_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibElf "Please install the libelf development package"
  LIBELF_LIBRARIES
  LIBELF_INCLUDE_DIRS)

SET(CMAKE_REQUIRED_LIBRARIES elf)
INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES("#include <libelf.h>
int main() {
  Elf *e = (Elf*)0;
  size_t sz;
  elf_getshdrstrndx(e, &sz);
  return 0;
}" ELF_GETSHDRSTRNDX)
SET(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(LIBELF_INCLUDE_DIRS LIBELF_LIBRARIES ELF_GETSHDRSTRNDX)
