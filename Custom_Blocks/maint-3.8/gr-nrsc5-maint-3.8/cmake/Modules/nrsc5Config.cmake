INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_NRSC5 nrsc5)

FIND_PATH(
    NRSC5_INCLUDE_DIRS
    NAMES nrsc5/api.h
    HINTS $ENV{NRSC5_DIR}/include
        ${PC_NRSC5_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    NRSC5_LIBRARIES
    NAMES gnuradio-nrsc5
    HINTS $ENV{NRSC5_DIR}/lib
        ${PC_NRSC5_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/nrsc5Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(NRSC5 DEFAULT_MSG NRSC5_LIBRARIES NRSC5_INCLUDE_DIRS)
MARK_AS_ADVANCED(NRSC5_LIBRARIES NRSC5_INCLUDE_DIRS)
