include(ExternalProject)
include(ProcessorCount)
include(embed_patches)
include(embed_platforms)

# Workaround to remove dynamic libs from library dependencies
function(unlink_transitive_dependency targets dep_to_remove)
  foreach(tgt ${targets})
    get_target_property(int_link_libs ${tgt} INTERFACE_LINK_LIBRARIES)

    if(NOT(int_link_libs MATCHES "-NOTFOUND$"))
      list(REMOVE_ITEM int_link_libs "${dep_to_remove}")
      set_target_properties(${tgt} PROPERTIES
        INTERFACE_LINK_LIBRARIES "${int_link_libs}")
    endif()
  endforeach(tgt ${targets})
endfunction(unlink_transitive_dependency)

# Detect the distribution bpftrace is being built on
function(detect_host_os os_id)
  file(STRINGS "/etc/os-release" HOST_OS_INFO)
  foreach(os_info IN LISTS HOST_OS_INFO)
    if(os_info MATCHES "^ID=")
      string(REPLACE "ID=" "" HOST_OS_ID ${os_info})
      set(${os_id} ${HOST_OS_ID} PARENT_SCOPE)
      break()
    endif()
  endforeach(os_info)
endfunction(detect_host_os os_id)

function(detect_host_os_family family_id)
  file(STRINGS "/etc/os-release" HOST_OS_INFO)
  foreach(os_info IN LISTS HOST_OS_INFO)
    if(os_info MATCHES "^ID_LIKE=")
      string(REPLACE "ID_LIKE=" "" HOST_OS_ID_LIKE ${os_info})
      set(${family_id} ${HOST_OS_ID_LIKE} PARENT_SCOPE)
      break()
    endif()
  endforeach(os_info)
endfunction(detect_host_os_family family_id)

# TODO dalehamel
# DRY up get_host_triple and get_target_triple by accepting a triple_type arg
# For simplicity sake, kept separate for now.
function(get_host_triple out)
  # Get the architecture.
  set(arch ${CMAKE_HOST_SYSTEM_PROCESSOR})
  # Get os and vendor
  if (${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    set(vendor "generic")
    set(os "linux")
  else()
    message(AUTHOR_WARNING "The host system ${CMAKE_HOST_SYSTEM_NAME} isn't supported")
  endif()
  set(triple "${arch}-${vendor}-${os}")
  set(${out} ${triple} PARENT_SCOPE)
  message(STATUS "Detected host triple: ${triple}")
endfunction()

function(get_target_triple out)
  # Get the architecture.
  set(arch ${CMAKE_SYSTEM_PROCESSOR})
  # Get os and vendor
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(vendor "generic")
    set(os "linux")
  elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    set(vendor "android")
    set(os "linux")
  endif()
  set(triple "${arch}-${vendor}-${os}")
  set(${out} ${triple} PARENT_SCOPE)
  message(STATUS "Detected target triple: ${triple}")
endfunction()

# If an external dependency doesn't use cmake, it cannot use the toolchain file
# To substitute for this, the toolchain is exported via standard env vars
function(get_toolchain_exports out)

  get_target_triple(TARGET_TRIPLE)
  if(NOT ${TARGET_TRIPLE} MATCHES android)
    message(FATAL_ERROR "No cross toolchain exists for non-android platform yet")
  endif()

  set(API_NUM "${ANDROID_NATIVE_API_LEVEL}")
  set(arch ${CMAKE_SYSTEM_PROCESSOR})

  if("${arch}" MATCHES "armv7")
    # FIXME use env var for toolchain home
    set(CROSS_EXPORTS
        "export TOOLCHAIN=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64 && \
        export AR=$TOOLCHAIN/bin/arm-linux-androideabi-ar && \
        export AS=$TOOLCHAIN/bin/arm-linux-androideabi-as && \
        export CC=$TOOLCHAIN/bin/armv7a-linux-androideabi${API_NUM}-clang && \
        export CXX=$TOOLCHAIN/bin/armv7a-linux-androideabi${API_NUM}-clang++ && \
        export LD=$TOOLCHAIN/bin/arm-linux-androideabi-ld && \
        export RANLIB=$TOOLCHAIN/bin/arm-linux-androideabi-ranlib && \
        export STRIP=$TOOLCHAIN/bin/arm-linux-androideabi-strip"
        )
  elseif("${arch}" MATCHES "x86_64")
    set(CROSS_EXPORTS
        "export TOOLCHAIN=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64 && \
        export AR=$TOOLCHAIN/bin/x86_64-linux-android-ar && \
        export AS=$TOOLCHAIN/bin/x86_64-linux-android-as && \
        export CC=$TOOLCHAIN/bin/x86_64-linux-android${API_NUM}-clang && \
        export CXX=$TOOLCHAIN/bin/x86_64-linux-android${API_NUM}-clang++ && \
        export LD=$TOOLCHAIN/bin/x86_64-linux-android-ld && \
        export RANLIB=$TOOLCHAIN/bin/x86_64-linux-android-ranlib && \
        export STRIP=$TOOLCHAIN/bin/x86_64-linux-android-strip"
        )
  elseif("${arch}" MATCHES "aarch64")
    set(CROSS_EXPORTS
        "export TOOLCHAIN=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64 && \
        export AR=$TOOLCHAIN/bin/aarch64-linux-android-ar && \
        export AS=$TOOLCHAIN/bin/aarch64-linux-android-as && \
        export CC=$TOOLCHAIN/bin/aarch64-linux-android${API_NUM}-clang && \
        export CXX=$TOOLCHAIN/bin/aarch64-linux-android${API_NUM}-clang++ && \
        export LD=$TOOLCHAIN/bin/aarch64-linux-android-ld && \
        export RANLIB=$TOOLCHAIN/bin/aarch64-linux-android-ranlib && \
        export STRIP=$TOOLCHAIN/bin/aarch64-linux-android-strip"
        )
  else()
    message(FATAL_ERROR "${arch} doesn't match any supported android ABI")
  endif()

  set(${out} "${CROSS_EXPORTS}" PARENT_SCOPE)
endfunction(get_toolchain_exports out)

function(get_android_cross_tuple out)
  set(arch ${CMAKE_SYSTEM_PROCESSOR})
  if("${arch}" MATCHES "armv7")
    set(${out} "armv7a-linux-androideabi" PARENT_SCOPE)
  elseif("${arch}" MATCHES "x86_64")
    set(${out} "x86_64-linux-android" PARENT_SCOPE)
  elseif("${arch}" MATCHES "aarch64")
    set(${out} "aarch64-linux-android" PARENT_SCOPE)
  else()
    message(FATAL_ERROR "${arch} doesn't match any supported android ABI")
  endif()
endfunction(get_android_cross_tuple out)

function(get_android_wordsize out)
  set(arch ${CMAKE_SYSTEM_PROCESSOR})
  if("${arch}" MATCHES "armv7")
    set(${out} 32 PARENT_SCOPE)
  elseif("${arch}" MATCHES "x86_64")
    set(${out} 64 PARENT_SCOPE)
  elseif("${arch}" MATCHES "aarch64")
    set(${out} 64 PARENT_SCOPE)
  else()
    message(FATAL_ERROR "${arch} doesn't match any supported android ABI")
  endif()
endfunction(get_android_wordsize out)

function(fix_llvm_linkflags targetProperty propertyValue)
  set_target_properties(${target_property} PROPERTIES
      INTERFACE_LINK_LIBRARIES "${propertyValue}"
    )
endfunction(fix_llvm_linkflags targetProperty propertyValue)

function(prepare_patch_series patchSeries patchPath)
  message("Writing patch series to ${patchPath}/series ...")
  file(WRITE "${patchPath}/series" "")
  foreach(patch_info IN ITEMS ${patchSeries})
    file(APPEND "${patchPath}/series" "${patch_info}\n")
  endforeach(patch_info)
endfunction(prepare_patch_series patchSeries patchPath)

function(fetch_patches patchName patchPath patchURL patchChecksum stripLevel)
  if(NOT EXISTS "${patchPath}/${patchName}")
    message("Downloading ${patchURL}")
    file(MAKE_DIRECTORY ${patchPath})
    file(DOWNLOAD "${patchURL}" "${patchPath}/${patchName}"
         EXPECTED_HASH SHA256=${patchChecksum})

    # Can add to this if ladder to support additional patch formats, tar
    # probably catches quit a lot...
    if(patchName MATCHES .*tar.*)
      if(NOT ${stripLevel})
        set(stripLevel 0)
      endif()
      message("Extracting ${patchName} to ${patchPath}, strip level ${stripLevel}")
      execute_process(COMMAND tar -xpf ${patchPath}/${patchName} --strip-components=${stripLevel} -C ${patchPath})
    else()
      message(WARNING "Patch ${patchName} doesn't appear to a tar achive, assuming it is a plaintext patch")
    endif()
  endif()
endfunction(fetch_patches patchName patchPatch patchURL patchChecksum stripLevel)
