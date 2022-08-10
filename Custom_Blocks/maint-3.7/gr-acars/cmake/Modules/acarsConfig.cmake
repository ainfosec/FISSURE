INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_ACARS acars)

FIND_PATH(
    ACARS_INCLUDE_DIRS
    NAMES acars/api.h
    HINTS $ENV{ACARS_DIR}/include
        ${PC_ACARS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    ACARS_LIBRARIES
    NAMES gnuradio-acars
    HINTS $ENV{ACARS_DIR}/lib
        ${PC_ACARS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ACARS DEFAULT_MSG ACARS_LIBRARIES ACARS_INCLUDE_DIRS)
MARK_AS_ADVANCED(ACARS_LIBRARIES ACARS_INCLUDE_DIRS)

