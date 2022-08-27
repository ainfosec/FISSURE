#find_package(PkgConfig)
INCLUDE(FindPkgConfig)
pkg_check_modules(PC_libosmocore libosmocore)
set(LIBOSMOCORE_DEFINITIONS ${PC_LIBOSMOCORE_CFLAGS_OTHER})

find_path(
        LIBOSMOCORE_INCLUDE_DIR
        NAMES   osmocom/core/application.h
        HINTS   ${PC_libosmocore_INCLUDEDIR}
                ${PC_libosmocore_INCLUDE_DIRS}
                ${CMAKE_INSTALL_PREFIX}/include
        PATHS   /usr/local/include
                /usr/include
)

find_library(
        LIBOSMOCORE_LIBRARY
        NAMES   libosmocore osmocore
        HINTS   ${PC_libosmocore_LIBDIR}
                ${PC_libosmocore_LIBRARY_DIRS}
                ${CMAKE_INSTALL_PREFIX}/lib/
                ${CMAKE_INSTALL_PREFIX}/lib64/
        PATHS   /usr/local/lib
                /usr/lib
)


set(LIBOSMOCORE_LIBRARIES ${LIBOSMOCORE_LIBRARY})
set(LIBOSMOCORE_INCLUDE_DIRS ${LIBOSMOCORE_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libosmocore  DEFAULT_MSG LIBOSMOCORE_LIBRARY LIBOSMOCORE_INCLUDE_DIR)
mark_as_advanced(LIBOSMOCORE_INCLUDE_DIR LIBOSMOCORE_LIBRARY )
