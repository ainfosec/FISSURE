INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_TPMS tpms)

FIND_PATH(
    TPMS_INCLUDE_DIRS
    NAMES tpms/api.h
    HINTS $ENV{TPMS_DIR}/include
        ${PC_TPMS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREEFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    TPMS_LIBRARIES
    NAMES gnuradio-tpms
    HINTS $ENV{TPMS_DIR}/lib
        ${PC_TPMS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(TPMS DEFAULT_MSG TPMS_LIBRARIES TPMS_INCLUDE_DIRS)
MARK_AS_ADVANCED(TPMS_LIBRARIES TPMS_INCLUDE_DIRS)

