INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_GARAGE_DOOR garage_door)

FIND_PATH(
    GARAGE_DOOR_INCLUDE_DIRS
    NAMES garage_door/api.h
    HINTS $ENV{GARAGE_DOOR_DIR}/include
        ${PC_GARAGE_DOOR_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GARAGE_DOOR_LIBRARIES
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

include("${CMAKE_CURRENT_LIST_DIR}/garage_doorTarget.cmake")

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GARAGE_DOOR DEFAULT_MSG GARAGE_DOOR_LIBRARIES GARAGE_DOOR_INCLUDE_DIRS)
MARK_AS_ADVANCED(GARAGE_DOOR_LIBRARIES GARAGE_DOOR_INCLUDE_DIRS)
