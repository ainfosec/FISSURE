#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "gnuradio::gnuradio-ainfosec" for configuration "Release"
set_property(TARGET gnuradio::gnuradio-ainfosec APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(gnuradio::gnuradio-ainfosec PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/x86_64-linux-gnu/libgnuradio-ainfosec.so.1.0.0.0"
  IMPORTED_SONAME_RELEASE "libgnuradio-ainfosec.so.1.0.0"
  )

list(APPEND _cmake_import_check_targets gnuradio::gnuradio-ainfosec )
list(APPEND _cmake_import_check_files_for_gnuradio::gnuradio-ainfosec "${_IMPORT_PREFIX}/lib/x86_64-linux-gnu/libgnuradio-ainfosec.so.1.0.0.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
