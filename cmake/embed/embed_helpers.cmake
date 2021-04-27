include(ExternalProject)
include(ProcessorCount)

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
    message(AUTHOR_WARNING "Android build not yet fully implemented.")
  else()
    message(AUTHOR_WARNING "The target system ${CMAKE_SYSTEM_NAME} isn't supported")
  endif()
  set(triple "${arch}-${vendor}-${os}")
  set(${out} ${triple} PARENT_SCOPE)
  message(STATUS "Detected target triple: ${triple}")
endfunction()

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
      execute_process(COMMAND tar -xpf ${patchPath}/${patchName} --strip-components=${stripLevel} -C ${patchPath})
    else()
      message("Patch ${patchName} doesn't appear to a tar achive, assuming it is a plaintext patch")
    endif()
  endif()
endfunction(fetch_patches patchName patchPatch patchURL patchChecksum)
