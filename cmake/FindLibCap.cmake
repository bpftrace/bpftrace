find_path (LIBCAP_INCLUDE_DIRS
  NAMES
    capability.h
  PATH_SUFFIXES
    sys
)

find_library (LIBCAP_LIBRARIES
  NAMES
    cap
)

find_package_handle_standard_args(LibCap "Please install libcap and it's development package"
  LIBCAP_LIBRARIES
  LIBCAP_INCLUDE_DIRS)
