# Workaround to remove dynamic libs from static library dependencies
function(unlink_transitive_dependency targets dep_to_remove)
  foreach(tgt ${targets})
    if(NOT TARGET ${tgt})
      continue()
    endif()

    get_target_property(int_link_libs ${tgt} INTERFACE_LINK_LIBRARIES)

    if(NOT(int_link_libs MATCHES "-NOTFOUND$"))
      list(REMOVE_ITEM int_link_libs "${dep_to_remove}")
      set_target_properties(${tgt} PROPERTIES
        INTERFACE_LINK_LIBRARIES "${int_link_libs}")
    endif()
  endforeach(tgt ${targets})
endfunction(unlink_transitive_dependency)

