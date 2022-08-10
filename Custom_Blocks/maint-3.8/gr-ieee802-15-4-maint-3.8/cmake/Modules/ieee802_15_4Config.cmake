INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_IEEE802_15_4 ieee802_15_4)

FIND_PATH(
    IEEE802_15_4_INCLUDE_DIRS
    NAMES ieee802_15_4/api.h
    HINTS $ENV{IEEE802_15_4_DIR}/include
        ${PC_IEEE802_15_4_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    IEEE802_15_4_LIBRARIES
    NAMES gnuradio-ieee802_15_4
    HINTS $ENV{IEEE802_15_4_DIR}/lib
        ${PC_IEEE802_15_4_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/ieee802_15_4Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(IEEE802_15_4 DEFAULT_MSG IEEE802_15_4_LIBRARIES IEEE802_15_4_INCLUDE_DIRS)
MARK_AS_ADVANCED(IEEE802_15_4_LIBRARIES IEEE802_15_4_INCLUDE_DIRS)
