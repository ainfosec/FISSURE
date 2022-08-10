INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_LIMESDR limesdr)

FIND_PATH(
    LIMESDR_INCLUDE_DIRS
    NAMES limesdr/api.h
    HINTS $ENV{LIMESDR_DIR}/include
        ${PC_LIMESDR_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    LIMESDR_LIBRARIES
    NAMES gnuradio-limesdr
    HINTS $ENV{LIMESDR_DIR}/lib
        ${PC_LIMESDR_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIMESDR DEFAULT_MSG LIMESDR_LIBRARIES LIMESDR_INCLUDE_DIRS)
MARK_AS_ADVANCED(LIMESDR_LIBRARIES LIMESDR_INCLUDE_DIRS)

