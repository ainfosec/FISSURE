find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_TPMS_POORE gnuradio-tpms_poore)

FIND_PATH(
    GR_TPMS_POORE_INCLUDE_DIRS
    NAMES gnuradio/tpms_poore/api.h
    HINTS $ENV{TPMS_POORE_DIR}/include
        ${PC_TPMS_POORE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_TPMS_POORE_LIBRARIES
    NAMES gnuradio-tpms_poore
    HINTS $ENV{TPMS_POORE_DIR}/lib
        ${PC_TPMS_POORE_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-tpms_pooreTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_TPMS_POORE DEFAULT_MSG GR_TPMS_POORE_LIBRARIES GR_TPMS_POORE_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_TPMS_POORE_LIBRARIES GR_TPMS_POORE_INCLUDE_DIRS)
