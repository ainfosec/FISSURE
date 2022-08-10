INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_TPMS_POORE tpms_poore)

FIND_PATH(
    TPMS_POORE_INCLUDE_DIRS
    NAMES tpms_poore/api.h
    HINTS $ENV{TPMS_POORE_DIR}/include
        ${PC_TPMS_POORE_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    TPMS_POORE_LIBRARIES
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

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(TPMS_POORE DEFAULT_MSG TPMS_POORE_LIBRARIES TPMS_POORE_INCLUDE_DIRS)
MARK_AS_ADVANCED(TPMS_POORE_LIBRARIES TPMS_POORE_INCLUDE_DIRS)

