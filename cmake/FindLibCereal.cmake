# - Try to find libcereal
# Once done this will define
#
#  LIBCEREAL_FOUND - system has libcereal
#  LIBCEREAL_INCLUDE_DIRS - the libcereal include directory

find_path (LIBCEREAL_INCLUDE_DIRS
  NAMES
    cereal/cereal.hpp
  PATHS
    ENV CPATH)

include (FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibCereal
  "Please install the libcereal development package"
  LIBCEREAL_INCLUDE_DIRS)

mark_as_advanced(LIBCEREAL_INCLUDE_DIRS)
