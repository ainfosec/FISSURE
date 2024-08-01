find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_FUZZER gnuradio-fuzzer)

FIND_PATH(
    GR_FUZZER_INCLUDE_DIRS
    NAMES gnuradio/fuzzer/api.h
    HINTS $ENV{FUZZER_DIR}/include
        ${PC_FUZZER_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_FUZZER_LIBRARIES
    NAMES gnuradio-fuzzer
    HINTS $ENV{FUZZER_DIR}/lib
        ${PC_FUZZER_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-fuzzerTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_FUZZER DEFAULT_MSG GR_FUZZER_LIBRARIES GR_FUZZER_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_FUZZER_LIBRARIES GR_FUZZER_INCLUDE_DIRS)
