find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_X10 gnuradio-X10)

FIND_PATH(
    GR_X10_INCLUDE_DIRS
    NAMES gnuradio/X10/api.h
    HINTS $ENV{X10_DIR}/include
        ${PC_X10_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_X10_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-X10Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_X10 DEFAULT_MSG GR_X10_LIBRARIES GR_X10_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_X10_LIBRARIES GR_X10_INCLUDE_DIRS)
