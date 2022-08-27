if(NOT PKG_CONFIG_FOUND)
    INCLUDE(FindPkgConfig)
endif()
PKG_CHECK_MODULES(PC_IEEE802_11 ieee802_11)

FIND_PATH(
    IEEE802_11_INCLUDE_DIRS
    NAMES ieee802_11/api.h
    HINTS $ENV{IEEE802_11_DIR}/include
        ${PC_IEEE802_11_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    IEEE802_11_LIBRARIES
    NAMES gnuradio-ieee802_11
    HINTS $ENV{IEEE802_11_DIR}/lib
        ${PC_IEEE802_11_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/ieee802_11Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(IEEE802_11 DEFAULT_MSG IEEE802_11_LIBRARIES IEEE802_11_INCLUDE_DIRS)
MARK_AS_ADVANCED(IEEE802_11_LIBRARIES IEEE802_11_INCLUDE_DIRS)
