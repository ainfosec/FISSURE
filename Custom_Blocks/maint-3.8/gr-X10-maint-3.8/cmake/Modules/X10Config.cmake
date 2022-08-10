INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_X10 X10)

FIND_PATH(
    X10_INCLUDE_DIRS
    NAMES X10/api.h
    HINTS $ENV{X10_DIR}/include
        ${PC_X10_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    X10_LIBRARIES
    NAMES gnuradio-X10
    HINTS $ENV{X10_DIR}/lib
        ${PC_X10_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/X10Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(X10 DEFAULT_MSG X10_LIBRARIES X10_INCLUDE_DIRS)
MARK_AS_ADVANCED(X10_LIBRARIES X10_INCLUDE_DIRS)
