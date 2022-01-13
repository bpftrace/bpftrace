find_program(GZIP gzip REQUIRED)
find_program(ASCIIDOCTOR asciidoctor)
file(GLOB FILES *.adoc)
set(GZFILES "")
if(NOT "${ASCIIDOCTOR}" STREQUAL "ASCIIDOCTOR-NOTFOUND")
  foreach(FIL ${FILES})
    get_filename_component(NAME ${FIL} NAME_WE)
    set(MANPAGE_FILE ${CMAKE_CURRENT_BINARY_DIR}/${NAME}.8)
    set(GZ_MANPAGE_FILE "${MANPAGE_FILE}.gz")

    add_custom_command(OUTPUT ${MANPAGE_FILE}
      COMMAND ${ASCIIDOCTOR} ${FIL} -b manpage -o - > ${MANPAGE_FILE}
      DEPENDS ${FIL})

    add_custom_command(OUTPUT ${GZ_MANPAGE_FILE}
      COMMAND ${GZIP} -c ${MANPAGE_FILE} > ${GZ_MANPAGE_FILE}
      DEPENDS ${MANPAGE_FILE})

    list(APPEND GZFILES ${GZ_MANPAGE_FILE})
  endforeach()
  add_custom_target(adoc_man DEPENDS ${GZFILES})
  install(FILES ${GZFILES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
else()
  message(WARNING "asciidoctor not found, building without bpftrace manpage")
  add_custom_target(adoc_man)
endif()
