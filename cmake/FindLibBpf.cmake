#  LIBBPF_FOUND - system has libbpf
#  LIBBPF_INCLUDE_DIRS - the libbpf include directory
#  LIBBPF_LIBRARIES - Link these to use libbpf
#  LIBBPF_DEFINITIONS - Compiler switches required for using libbpf
#  LIBBPF_VERSION_MAJOR - Libbpf major version
#  LIBBPF_VERSION_MINOR - Libbpf minor version

if (USE_SYSTEM_LIBBPF)
  find_path (LIBBPF_INCLUDE_DIRS
    NAMES
      bpf/bpf.h
      bpf/btf.h
      bpf/libbpf.h
    PATHS
      ENV CPATH)

  # We require that `libbpf` be linked statically, as we will implicitly vendor
  # the header into embedded code. See #4151 for more information.
  find_library (LIBBPF_LIBRARIES
    NAMES
      libbpf.a
    PATHS
      ENV LIBRARY_PATH
      ENV LD_LIBRARY_PATH)
  set(LIBBPF_ERROR_MESSAGE
    "Please set -DUSE_SYSTEM_LIBBPF=Off to use the libbpf stored as a submodule
    (preferred) or install the libbpf.a static library")
else()
  set(LIBBPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src)
  file(GLOB LIBBPF_SRCS ${LIBBPF_SOURCE}/*)
  set(LIBBPF_BUILD ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
  set(LIBBPF_LIBRARY ${LIBBPF_BUILD}/lib64/libbpf.a)

  # We need to install headers during configure phase for two reasons:
  # 1. To parse libbpf version from libbpf_version.h below.
  # 2. For bpftrace's stdlib since libbpf headers are included in stdlib bpf.c
  #    files (and the rules to embed them are generated in configure phase).
  execute_process(
    COMMAND make PREFIX=${LIBBPF_BUILD} install_headers
    WORKING_DIRECTORY ${LIBBPF_SOURCE}
    OUTPUT_QUIET)

  # Build and install libbpf from source. This needs to be done in a rather
  # complicated way to ensure proper dependency between the exported
  # LIBBPF_LIBRARIES and the built libbpf.a. Note that we cannot use
  # add_custom_target with COMMAND since CMake considers the target as always
  # outdated, forcing rebuild of libbpf (and transitively of the entire bpftrace
  # every time).
  add_custom_command(
    OUTPUT ${LIBBPF_LIBRARY}
    # -fPIE here is needed by latest binutils when building with Clang
    COMMAND make PREFIX=${LIBBPF_BUILD} EXTRA_CFLAGS="-fPIE" install > /dev/null
    WORKING_DIRECTORY ${LIBBPF_SOURCE}
    DEPENDS ${LIBBPF_SRCS}
    COMMENT "Building libbpf"
    VERBATIM)
  add_custom_target(libbpf_build DEPENDS ${LIBBPF_LIBRARY})
  add_library(libbpf_static STATIC IMPORTED GLOBAL)
  set_target_properties(libbpf_static PROPERTIES
    IMPORTED_LOCATION ${LIBBPF_LIBRARY})
  add_dependencies(libbpf_static libbpf_build)

  # Set the output variables directly
  set(LIBBPF_LIBRARIES libbpf_static)
  set(LIBBPF_INCLUDE_DIRS ${LIBBPF_BUILD}/include)
endif()

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE.
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBpf ${LIBBPF_ERROR_MESSAGE}
  LIBBPF_LIBRARIES
  LIBBPF_INCLUDE_DIRS)

# Parse version information out of libbpf_version.h
if(EXISTS "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h")
  file(READ "${LIBBPF_INCLUDE_DIRS}/bpf/libbpf_version.h" version_header)
  string(REGEX MATCH "LIBBPF_MAJOR_VERSION[ \t]+([0-9]+)" major_match "${version_header}")
  string(REGEX MATCH "LIBBPF_MINOR_VERSION[ \t]+([0-9]+)" minor_match "${version_header}")
  string(REGEX REPLACE "LIBBPF_MAJOR_VERSION[ \t]+" "" LIBBPF_VERSION_MAJOR "${major_match}")
  string(REGEX REPLACE "LIBBPF_MINOR_VERSION[ \t]+" "" LIBBPF_VERSION_MINOR "${minor_match}")
else()
  set(LIBBPF_VERSION_MAJOR 0)
  set(LIBBPF_VERSION_MINOR 0)
  message(SEND_ERROR "Libbpf version is too old and does not have libbpf_version.h, which was introduced in v0.6")
endif()

mark_as_advanced(LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES LIBBPF_VERSION_MAJOR LIBBPF_VERSION_MINOR)

INCLUDE(CheckCXXSourceCompiles)
SET(CMAKE_REQUIRED_INCLUDES ${LIBBPF_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_LIBRARIES ${LIBBPF_LIBRARIES} elf z)
SET(CMAKE_REQUIRED_INCLUDES)
SET(CMAKE_REQUIRED_LIBRARIES)
