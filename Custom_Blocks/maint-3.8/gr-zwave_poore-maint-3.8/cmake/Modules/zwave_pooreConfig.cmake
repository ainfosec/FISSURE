INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_ZWAVE_POORE zwave_poore)

FIND_PATH(
    ZWAVE_POORE_INCLUDE_DIRS
    NAMES zwave_poore/api.h
    HINTS $ENV{ZWAVE_POORE_DIR}/include
        ${PC_ZWAVE_POORE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    ZWAVE_POORE_LIBRARIES
    NAMES gnuradio-zwave_poore
    HINTS $ENV{ZWAVE_POORE_DIR}/lib
        ${PC_ZWAVE_POORE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/zwave_pooreTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ZWAVE_POORE DEFAULT_MSG ZWAVE_POORE_LIBRARIES ZWAVE_POORE_INCLUDE_DIRS)
MARK_AS_ADVANCED(ZWAVE_POORE_LIBRARIES ZWAVE_POORE_INCLUDE_DIRS)
