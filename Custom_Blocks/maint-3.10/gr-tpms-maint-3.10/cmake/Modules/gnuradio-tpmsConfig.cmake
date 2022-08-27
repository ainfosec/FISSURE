find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_TPMS gnuradio-tpms)

FIND_PATH(
    GR_TPMS_INCLUDE_DIRS
    NAMES gnuradio/tpms/api.h
    HINTS $ENV{TPMS_DIR}/include
        ${PC_TPMS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_TPMS_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-tpmsTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_TPMS DEFAULT_MSG GR_TPMS_LIBRARIES GR_TPMS_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_TPMS_LIBRARIES GR_TPMS_INCLUDE_DIRS)
