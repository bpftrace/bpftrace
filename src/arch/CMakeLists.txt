if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_library(arch aarch64.cpp)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ppc64" OR
       CMAKE_SYSTEM_PROCESSOR STREQUAL "ppc64le")
    add_library(arch ppc64.cpp)
else()
    add_library(arch x86_64.cpp)
endif()
