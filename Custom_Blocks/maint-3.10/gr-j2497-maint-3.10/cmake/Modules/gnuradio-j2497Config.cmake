find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_J2497 gnuradio-j2497)

FIND_PATH(
    GR_J2497_INCLUDE_DIRS
    NAMES gnuradio/j2497/api.h
    HINTS $ENV{J2497_DIR}/include
        ${PC_J2497_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_J2497_LIBRARIES
    NAMES gnuradio-j2497
    HINTS $ENV{J2497_DIR}/lib
        ${PC_J2497_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-j2497Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_J2497 DEFAULT_MSG GR_J2497_LIBRARIES GR_J2497_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_J2497_LIBRARIES GR_J2497_INCLUDE_DIRS)
