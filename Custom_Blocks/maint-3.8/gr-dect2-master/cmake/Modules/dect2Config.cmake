INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_DECT2 dect2)

FIND_PATH(
    DECT2_INCLUDE_DIRS
    NAMES dect2/api.h
    HINTS $ENV{DECT2_DIR}/include
        ${PC_DECT2_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    DECT2_LIBRARIES
    NAMES gnuradio-dect2
    HINTS $ENV{DECT2_DIR}/lib
        ${PC_DECT2_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(DECT2 DEFAULT_MSG DECT2_LIBRARIES DECT2_INCLUDE_DIRS)
MARK_AS_ADVANCED(DECT2_LIBRARIES DECT2_INCLUDE_DIRS)

