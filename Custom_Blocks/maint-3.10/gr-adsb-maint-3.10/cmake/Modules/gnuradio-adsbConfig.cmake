find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_ADSB gnuradio-adsb)

FIND_PATH(
    GR_ADSB_INCLUDE_DIRS
    NAMES gnuradio/adsb/api.h
    HINTS $ENV{ADSB_DIR}/include
        ${PC_ADSB_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_ADSB_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-adsbTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_ADSB DEFAULT_MSG GR_ADSB_LIBRARIES GR_ADSB_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_ADSB_LIBRARIES GR_ADSB_INCLUDE_DIRS)
