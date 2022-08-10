INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_CLAPPER_PLUS clapper_plus)

FIND_PATH(
    CLAPPER_PLUS_INCLUDE_DIRS
    NAMES clapper_plus/api.h
    HINTS $ENV{CLAPPER_PLUS_DIR}/include
        ${PC_CLAPPER_PLUS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    CLAPPER_PLUS_LIBRARIES
    NAMES gnuradio-clapper_plus
    HINTS $ENV{CLAPPER_PLUS_DIR}/lib
        ${PC_CLAPPER_PLUS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/clapper_plusTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CLAPPER_PLUS DEFAULT_MSG CLAPPER_PLUS_LIBRARIES CLAPPER_PLUS_INCLUDE_DIRS)
MARK_AS_ADVANCED(CLAPPER_PLUS_LIBRARIES CLAPPER_PLUS_INCLUDE_DIRS)
