INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_FOO foo)

FIND_PATH(
    FOO_INCLUDE_DIRS
    NAMES foo/api.h
    HINTS $ENV{FOO_DIR}/include
        ${PC_FOO_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    FOO_LIBRARIES
    NAMES gnuradio-foo
    HINTS $ENV{FOO_DIR}/lib
        ${PC_FOO_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/fooTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(FOO DEFAULT_MSG FOO_LIBRARIES FOO_INCLUDE_DIRS)
MARK_AS_ADVANCED(FOO_LIBRARIES FOO_INCLUDE_DIRS)
