find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_CLAPPER_PLUS gnuradio-clapper_plus)

FIND_PATH(
    GR_CLAPPER_PLUS_INCLUDE_DIRS
    NAMES gnuradio/clapper_plus/api.h
    HINTS $ENV{CLAPPER_PLUS_DIR}/include
        ${PC_CLAPPER_PLUS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_CLAPPER_PLUS_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-clapper_plusTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_CLAPPER_PLUS DEFAULT_MSG GR_CLAPPER_PLUS_LIBRARIES GR_CLAPPER_PLUS_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_CLAPPER_PLUS_LIBRARIES GR_CLAPPER_PLUS_INCLUDE_DIRS)
