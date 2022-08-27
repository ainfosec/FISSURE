find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_ZWAVE_POORE gnuradio-zwave_poore)

FIND_PATH(
    GR_ZWAVE_POORE_INCLUDE_DIRS
    NAMES gnuradio/zwave_poore/api.h
    HINTS $ENV{ZWAVE_POORE_DIR}/include
        ${PC_ZWAVE_POORE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_ZWAVE_POORE_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-zwave_pooreTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_ZWAVE_POORE DEFAULT_MSG GR_ZWAVE_POORE_LIBRARIES GR_ZWAVE_POORE_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_ZWAVE_POORE_LIBRARIES GR_ZWAVE_POORE_INCLUDE_DIRS)
