INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_IRIDIUM iridium)

FIND_PATH(
    IRIDIUM_INCLUDE_DIRS
    NAMES iridium/api.h
    HINTS $ENV{IRIDIUM_DIR}/include
        ${PC_IRIDIUM_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    IRIDIUM_LIBRARIES
    NAMES gnuradio-iridium
    HINTS $ENV{IRIDIUM_DIR}/lib
        ${PC_IRIDIUM_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/iridiumTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(IRIDIUM DEFAULT_MSG IRIDIUM_LIBRARIES IRIDIUM_INCLUDE_DIRS)
MARK_AS_ADVANCED(IRIDIUM_LIBRARIES IRIDIUM_INCLUDE_DIRS)
