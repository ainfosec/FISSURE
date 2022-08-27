find_package(PkgConfig)

PKG_CHECK_MODULES(PC_GR_GARAGE_DOOR gnuradio-garage_door)

FIND_PATH(
    GR_GARAGE_DOOR_INCLUDE_DIRS
    NAMES gnuradio/garage_door/api.h
    HINTS $ENV{GARAGE_DOOR_DIR}/include
        ${PC_GARAGE_DOOR_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GR_GARAGE_DOOR_LIBRARIES
    NAMES gnuradio-garage_door
    HINTS $ENV{GARAGE_DOOR_DIR}/lib
        ${PC_GARAGE_DOOR_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          )

include("${CMAKE_CURRENT_LIST_DIR}/gnuradio-garage_doorTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GR_GARAGE_DOOR DEFAULT_MSG GR_GARAGE_DOOR_LIBRARIES GR_GARAGE_DOOR_INCLUDE_DIRS)
MARK_AS_ADVANCED(GR_GARAGE_DOOR_LIBRARIES GR_GARAGE_DOOR_INCLUDE_DIRS)
