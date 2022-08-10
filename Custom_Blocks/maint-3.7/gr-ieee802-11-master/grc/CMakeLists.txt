file(GLOB xml_files "*.xml")

install(FILES ${xml_files} DESTINATION share/gnuradio/grc/blocks )
