INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_FUZZER fuzzer)

FIND_PATH(
    FUZZER_INCLUDE_DIRS
    NAMES fuzzer/api.h
    HINTS $ENV{FUZZER_DIR}/include
        ${PC_FUZZER_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    FUZZER_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/fuzzerTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(FUZZER DEFAULT_MSG FUZZER_LIBRARIES FUZZER_INCLUDE_DIRS)
MARK_AS_ADVANCED(FUZZER_LIBRARIES FUZZER_INCLUDE_DIRS)
