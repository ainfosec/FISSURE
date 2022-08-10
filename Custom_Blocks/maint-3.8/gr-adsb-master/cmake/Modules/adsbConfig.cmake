INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_ADSB adsb)

FIND_PATH(
    ADSB_INCLUDE_DIRS
    NAMES adsb/api.h
    HINTS $ENV{ADSB_DIR}/include
        ${PC_ADSB_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    ADSB_LIBRARIES
    NAMES gnuradio-adsb
    HINTS $ENV{ADSB_DIR}/lib
        ${PC_ADSB_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/adsbTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ADSB DEFAULT_MSG ADSB_LIBRARIES ADSB_INCLUDE_DIRS)
MARK_AS_ADVANCED(ADSB_LIBRARIES ADSB_INCLUDE_DIRS)
