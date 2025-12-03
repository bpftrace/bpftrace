# - Try to find libcereal
# Once done this will define
#
#  LIBCEREAL_FOUND - system has libcereal
#  LIBCEREAL_INCLUDE_DIRS - the libcereal include directory
#  LIBCEREAL_VERSION - the libcereal version

find_path (LIBCEREAL_INCLUDE_DIRS
  NAMES
    cereal/cereal.hpp
  PATHS
    ENV CPATH)

# Extract cereal version from cereal.hpp
if(LIBCEREAL_INCLUDE_DIRS)
  file(READ "${LIBCEREAL_INCLUDE_DIRS}/cereal/cereal.hpp" CEREAL_HPP_CONTENT)
  string(REGEX MATCH "#define CEREAL_VERSION_MAJOR ([0-9]+)" _ "${CEREAL_HPP_CONTENT}")
  set(CEREAL_VERSION_MAJOR "${CMAKE_MATCH_1}")
  string(REGEX MATCH "#define CEREAL_VERSION_MINOR ([0-9]+)" _ "${CEREAL_HPP_CONTENT}")
  set(CEREAL_VERSION_MINOR "${CMAKE_MATCH_1}")
  string(REGEX MATCH "#define CEREAL_VERSION_PATCH ([0-9]+)" _ "${CEREAL_HPP_CONTENT}")
  set(CEREAL_VERSION_PATCH "${CMAKE_MATCH_1}")
  
  if(CEREAL_VERSION_MAJOR AND CEREAL_VERSION_MINOR AND CEREAL_VERSION_PATCH)
    set(LIBCEREAL_VERSION "${CEREAL_VERSION_MAJOR}.${CEREAL_VERSION_MINOR}.${CEREAL_VERSION_PATCH}")
  endif()
endif()

include (FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibCereal
  REQUIRED_VARS LIBCEREAL_INCLUDE_DIRS
  VERSION_VAR LIBCEREAL_VERSION
  FAIL_MESSAGE "Please install the libcereal development package (version >= 1.3.1 required for C++20 compatibility)")

mark_as_advanced(LIBCEREAL_INCLUDE_DIRS LIBCEREAL_VERSION)
