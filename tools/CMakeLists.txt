file(GLOB BT_FILES *.bt)
install(PROGRAMS ${BT_FILES} DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/bpftrace/tools)

add_subdirectory(old)

