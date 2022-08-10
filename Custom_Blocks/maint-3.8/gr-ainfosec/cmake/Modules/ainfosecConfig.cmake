INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_AINFOSEC ainfosec)

FIND_PATH(
    AINFOSEC_INCLUDE_DIRS
    NAMES ainfosec/api.h
    HINTS $ENV{AINFOSEC_DIR}/include
        ${PC_AINFOSEC_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    AINFOSEC_LIBRARIES
    NAMES gnuradio-ainfosec
    HINTS $ENV{AINFOSEC_DIR}/lib
        ${PC_AINFOSEC_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/ainfosecTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(AINFOSEC DEFAULT_MSG AINFOSEC_LIBRARIES AINFOSEC_INCLUDE_DIRS)
MARK_AS_ADVANCED(AINFOSEC_LIBRARIES AINFOSEC_INCLUDE_DIRS)
