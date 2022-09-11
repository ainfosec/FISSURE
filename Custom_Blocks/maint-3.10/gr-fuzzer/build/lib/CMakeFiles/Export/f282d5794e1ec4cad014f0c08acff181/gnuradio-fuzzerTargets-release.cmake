#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "gnuradio::gnuradio-fuzzer" for configuration "Release"
set_property(TARGET gnuradio::gnuradio-fuzzer APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(gnuradio::gnuradio-fuzzer PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/x86_64-linux-gnu/libgnuradio-fuzzer.so.1.0.0.0"
  IMPORTED_SONAME_RELEASE "libgnuradio-fuzzer.so.1.0.0"
  )

list(APPEND _cmake_import_check_targets gnuradio::gnuradio-fuzzer )
list(APPEND _cmake_import_check_files_for_gnuradio::gnuradio-fuzzer "${_IMPORT_PREFIX}/lib/x86_64-linux-gnu/libgnuradio-fuzzer.so.1.0.0.0" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
