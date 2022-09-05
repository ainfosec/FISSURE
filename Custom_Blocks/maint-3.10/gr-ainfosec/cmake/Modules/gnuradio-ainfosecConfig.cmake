find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_AINFOSEC gnuradio-ainfosec)

FIND_PATH(
    GR_AINFOSEC_INCLUDE_DIRS
    NAMES gnuradio/ainfosec/api.h
    HINTS $ENV{AINFOSEC_DIR}/include
        ${PC_AINFOSEC_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_AINFOSEC_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-ainfosecTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_AINFOSEC DEFAULT_MSG GR_AINFOSEC_LIBRARIES GR_AINFOSEC_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_AINFOSEC_LIBRARIES GR_AINFOSEC_INCLUDE_DIRS)
