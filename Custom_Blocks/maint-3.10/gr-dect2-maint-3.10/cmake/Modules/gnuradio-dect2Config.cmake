find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_DECT2 gnuradio-dect2)

FIND_PATH(
    GR_DECT2_INCLUDE_DIRS
    NAMES gnuradio/dect2/api.h
    HINTS $ENV{DECT2_DIR}/include
        ${PC_DECT2_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_DECT2_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-dect2Target.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_DECT2 DEFAULT_MSG GR_DECT2_LIBRARIES GR_DECT2_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_DECT2_LIBRARIES GR_DECT2_INCLUDE_DIRS)
