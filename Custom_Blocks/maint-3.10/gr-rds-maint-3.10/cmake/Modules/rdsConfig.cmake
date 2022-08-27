if(NOT PKG_CONFIG_FOUND)
    INCLUDE(FindPkgConfig)
endif()
PKG_CHECK_MODULES(PC_RDS rds)

FIND_PATH(
    RDS_INCLUDE_DIRS
    NAMES rds/api.h
    HINTS $ENV{RDS_DIR}/include
        ${PC_RDS_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    RDS_LIBRARIES
    NAMES gnuradio-rds
    HINTS $ENV{RDS_DIR}/lib
        ${PC_RDS_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/rdsTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(RDS DEFAULT_MSG RDS_LIBRARIES RDS_INCLUDE_DIRS)
MARK_AS_ADVANCED(RDS_LIBRARIES RDS_INCLUDE_DIRS)
