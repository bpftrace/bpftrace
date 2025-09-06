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

# Check if we're in a git repo
execute_process(
  COMMAND git rev-parse --short HEAD
  WORKING_DIRECTORY ${bpftrace_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_SHORT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE retcode
)

set(BPFTRACE_BASE_VERSION "v${bpftrace_VERSION_MAJOR}.${bpftrace_VERSION_MINOR}.${bpftrace_VERSION_PATCH}")

# Append git hash if we're in a git repository
if(retcode EQUAL 0)
  set(BPFTRACE_VERSION "${BPFTRACE_BASE_VERSION}-${GIT_SHORT_HASH}")
else()
  set(BPFTRACE_VERSION "${BPFTRACE_BASE_VERSION}")
endif()

set(MIN_KERNEL_VERSION_MAJOR 5)
set(MIN_KERNEL_VERSION_MINOR 15)
set(MIN_KERNEL_VERSION_PATCH 0)

configure_file(${VERSION_H_IN} ${VERSION_H} @ONLY)
