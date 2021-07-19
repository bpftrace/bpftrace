find_program(GZIP gzip REQUIRED)
file(GLOB FILES *.8)
set(GZFILES "")
foreach(FIL ${FILES})
  get_filename_component(NAME ${FIL} NAME)
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz
    COMMAND ${GZIP} -c ${FIL} > ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz
    DEPENDS ${FIL})
  list(APPEND GZFILES "${CMAKE_CURRENT_BINARY_DIR}/${NAME}.gz")
endforeach()
add_custom_target(man_man DEPENDS ${GZFILES})
install(FILES ${GZFILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
