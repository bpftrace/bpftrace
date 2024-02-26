# This file generates the file "version.h", containing an up-to-date version
# string on each build.

# Inputs:
#   File names:
#     VERSION_H_IN - name of template source file
#     VERSION_H    - name of populated file to be generated
#   Fallback version numbers when not building in a Git repository:
#     bpftrace_VERSION_MAJOR
#     bpftrace_VERSION_MINOR
#     bpftrace_VERSION_PATCH

# Try and get a version string from Git tags
execute_process(
  COMMAND git describe --abbrev=4 --dirty --tags
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE BPFTRACE_VERSION
  ERROR_VARIABLE GIT_DESCRIBE_ERROR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE retcode
)

# If the build is not done from a git repo, get the version information from
# the version variables in main CMakeLists.txt
if(NOT ${retcode} EQUAL 0)
  set(BPFTRACE_VERSION "v${bpftrace_VERSION_MAJOR}.${bpftrace_VERSION_MINOR}.${bpftrace_VERSION_PATCH}")
  message(STATUS "Could not obtain version string from Git. Falling back to CMake version string.")
endif()

configure_file(${VERSION_H_IN} ${VERSION_H} @ONLY)
