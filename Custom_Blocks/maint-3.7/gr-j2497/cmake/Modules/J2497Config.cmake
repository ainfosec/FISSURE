INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_J2497 J2497)

FIND_PATH(
    J2497_INCLUDE_DIRS
    NAMES J2497/api.h
    HINTS $ENV{J2497_DIR}/include
        ${PC_J2497_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    J2497_LIBRARIES
    NAMES gnuradio-J2497
    HINTS $ENV{J2497_DIR}/lib
        ${PC_J2497_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(J2497 DEFAULT_MSG J2497_LIBRARIES J2497_INCLUDE_DIRS)
MARK_AS_ADVANCED(J2497_LIBRARIES J2497_INCLUDE_DIRS)

