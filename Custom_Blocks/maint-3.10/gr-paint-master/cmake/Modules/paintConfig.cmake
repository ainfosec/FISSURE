INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_PAINT paint)

FIND_PATH(
    PAINT_INCLUDE_DIRS
    NAMES paint/api.h
    HINTS $ENV{PAINT_DIR}/include
        ${PC_PAINT_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    PAINT_LIBRARIES
    NAMES gnuradio-paint
    HINTS $ENV{PAINT_DIR}/lib
        ${PC_PAINT_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/paintTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PAINT DEFAULT_MSG PAINT_LIBRARIES PAINT_INCLUDE_DIRS)
MARK_AS_ADVANCED(PAINT_LIBRARIES PAINT_INCLUDE_DIRS)
