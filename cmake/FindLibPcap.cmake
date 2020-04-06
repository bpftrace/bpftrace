# - Try to find libpcap
# Once done this will define
#
#  LIBPCAP_INCLUDE_DIRS - where to find pcap/pcap.h
#  LIBPCAP_LIBRARIES    - List of libraries when using pcap
#  LIBPCAP_FOUND        - True if pcap found.

find_path(LIBPCAP_INCLUDE_DIRS
  NAMES
    pcap/pcap.h
  PATHS
    /usr/include
    /usr/local/include
    /opt/local/include
    /sw/include
    ENV CPATH
)

find_library(LIBPCAP_LIBRARIES
  NAMES
    pcap
  PATHS
    /usr/lib
    /usr/lib64
    /usr/local/lib
    /opt/local/lib
    /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH
)

include (FindPackageHandleStandardArgs)

# handle the QUIETLY and REQUIRED arguments and set LIBPCAP_FOUND to TRUE if all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibPcap "Please install the libcap development package"
  LIBPCAP_LIBRARIES
  LIBPCAP_INCLUDE_DIRS)

mark_as_advanced(LIBPCAP_INCLUDE_DIRS LIBPCAP_LIBRARIES)
