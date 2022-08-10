INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_AIS ais)

FIND_PATH(
    AIS_INCLUDE_DIRS
    NAMES ais/api.h
    HINTS $ENV{AIS_DIR}/include
        ${PC_AIS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    AIS_LIBRARIES
    NAMES gnuradio-ais
    HINTS $ENV{AIS_DIR}/lib
        ${PC_AIS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

include("${CMAKE_CURRENT_LIST_DIR}/aisTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(AIS DEFAULT_MSG AIS_LIBRARIES AIS_INCLUDE_DIRS)
MARK_AS_ADVANCED(AIS_LIBRARIES AIS_INCLUDE_DIRS)

