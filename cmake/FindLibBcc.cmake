# - Try to find libbcc
# Once done this will define
#
#  LIBBCC_FOUND - system has libbcc
#  LIBBCC_INCLUDE_DIRS - the libbcc include directory
#  LIBBCC_LIBRARIES - Link these to use libbcc
#  LIBBCC_DEFINITIONS - Compiler switches required for using libbcc
#  LIBBCC_BPF_LIBRARIES - libbcc runtime library
#  LIBBCC_LOADER_LIBRARY_STATIC - libbcc helper static library (for static compilation)
#  LIBBCC_BPF_CONTAINS_RUNTIME - whether libbcc_bpf.so has been expanded to contain everything !llvm & !clang
#
# Note that the shared libbcc binary has libbpf and bcc_loader already compiled in but
# the static doesn't. So when creating a static build those have to be included too.

if (LIBBCC_LIBRARIES AND LIBBCC_INCLUDE_DIRS)
  set (LibBcc_FIND_QUIETLY TRUE)
endif (LIBBCC_LIBRARIES AND LIBBCC_INCLUDE_DIRS)

if (USE_SYSTEM_BPF_BCC)
  find_path (LIBBCC_INCLUDE_DIRS
    NAMES
      bcc/libbpf.h
    PATHS
      ENV CPATH
  )

  find_library (LIBBCC_LIBRARIES
    NAMES
      bcc
    PATHS
      ENV LIBRARY_PATH
      ENV LD_LIBRARY_PATH
  )

  find_library (LIBBCC_BPF_LIBRARIES
    NAMES
      bcc_bpf
    PATHS
      ENV LIBRARY_PATH
      ENV LD_LIBRARY_PATH)

  find_library (LIBBCC_LOADER_LIBRARY_STATIC
    NAMES
      bcc-loader-static
    PATHS
      ENV LIBRARY_PATH
      ENV LD_LIBRARY_PATH)
  set(LIBBCC_ERROR_MESSAGE "Please install the bcc library package, which is required. Depending on your distro, it may be called bpfcclib or bcclib (Ubuntu), bcc-devel (Fedora), or something else. If unavailable, install bcc from source (github.com/iovisor/bcc).")
else()
  # Use static linking with vendored libbcc
  set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
  set(SAVED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(CMAKE_PREFIX_PATH ${BPF_BCC_PREFIX_PATH})
  find_path (LIBBCC_INCLUDE_DIRS
    NAMES
      bcc/libbpf.h
    NO_CMAKE_SYSTEM_PATH)

  find_library (LIBBCC_LIBRARIES
    NAMES
      bcc
    NO_CMAKE_SYSTEM_PATH)

  find_library (LIBBCC_BPF_LIBRARIES
    NAMES
      bcc_bpf
    NO_CMAKE_SYSTEM_PATH)

  find_library (LIBBCC_LOADER_LIBRARY_STATIC
    NAMES
      bcc-loader-static
    NO_CMAKE_SYSTEM_PATH)

  set(CMAKE_PREFIX_PATH ${SAVED_CMAKE_PREFIX_PATH})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES})
  set(LIBBCC_ERROR_MESSAGE "Please run ${CMAKE_SOURCE_DIR}/build-libs.sh from the build folder first")
endif()

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBBCC_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibBcc ${LIBBCC_ERROR_MESSAGE}
  LIBBCC_LIBRARIES
  LIBBCC_INCLUDE_DIRS)

# Check bpf_attach_kprobe signature
if(${LIBBCC_FOUND})
if(STATIC_BPF_BCC)
  # libbcc.a is not statically linked with libbpf.a, libelf.a, libz.a, and liblzma.a.
  # If we do a static bpftrace build, we must link them in.
  find_package(LibBpf)
  find_package(LibElf)
  find_package(LibLzma)

  if(ANDROID)
    # libz is part of the Android NDK; link against it dynamically
    SET(CMAKE_REQUIRED_LIBRARIES ${LIBBCC_BPF_LIBRARIES} ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${LIBLZMA_LIBRARIES})
    SET(CMAKE_REQUIRED_LINK_OPTIONS "-lz")
  else()
    find_package(LibZ)
    SET(CMAKE_REQUIRED_LIBRARIES ${LIBBCC_BPF_LIBRARIES} ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${LIBLZMA_LIBRARIES} ${LIBZ_LIBRARIES})
  endif()
else()
  SET(CMAKE_REQUIRED_LIBRARIES ${LIBBCC_LIBRARIES} ${LIBBPF_LIBRARIES})
endif()

INCLUDE(CheckCXXSourceCompiles)
SET(CMAKE_REQUIRED_INCLUDES ${LIBBCC_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_LIBRARIES ${LIBBCC_BPF_LIBRARIES})
include(CheckSymbolExists)
check_symbol_exists(bcc_usdt_foreach ${LIBBCC_INCLUDE_DIRS}/bcc/bcc_usdt.h LIBBCC_BPF_CONTAINS_RUNTIME)
SET(CMAKE_REQUIRED_LIBRARIES)
SET(CMAKE_REQUIRED_INCLUDES)
endif(${LIBBCC_FOUND})
