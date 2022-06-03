option(INSTALL_TOOL_DOCS "Install example text files demonstrating tools" ON)

if (INSTALL_TOOL_DOCS)
  file(GLOB TXT_FILES *.txt)
  list(REMOVE_ITEM TXT_FILES ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt)
  install(FILES ${TXT_FILES} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bpftrace/tools/doc)
endif()

file(GLOB BT_FILES *.bt)
install(PROGRAMS ${BT_FILES} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bpftrace/tools)
add_subdirectory(old)
