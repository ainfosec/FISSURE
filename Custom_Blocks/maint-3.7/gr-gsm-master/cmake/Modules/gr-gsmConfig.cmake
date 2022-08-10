INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_GR_GSM grgsm)

FIND_PATH(
    GR_GSM_INCLUDE_DIRS
    NAMES grgsm/api.h
    HINTS $ENV{GR_GSM_DIR}/include
        ${PC_GR_GSM_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_GSM_LIBRARIES
    NAMES grgsm
    HINTS $ENV{GR_GSM_DIR}/lib
        ${PC_GR_GSM_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_GSM DEFAULT_MSG GR_GSM_LIBRARIES GR_GSM_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_GSM_LIBRARIES GR_GSM_INCLUDE_DIRS)

