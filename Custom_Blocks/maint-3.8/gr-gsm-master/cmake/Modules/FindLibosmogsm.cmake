INCLUDE(FindPkgConfig)
pkg_check_modules(PC_libosmogsm libosmogsm)
set(LIBOSMOGSM_DEFINITIONS ${PC_LIBOSMOGSM_CFLAGS_OTHER})

find_path(
        LIBOSMOGSM_INCLUDE_DIR
        NAMES   osmocom/gsm/gsm_utils.h
        HINTS   ${PC_libosmogsm_INCLUDEDIR}
                ${PC_libosmogsm_INCLUDE_DIRS}
                ${CMAKE_INSTALL_PREFIX}/include
        PATHS   /usr/local/include
                /usr/include
)

find_library(
        LIBOSMOGSM_LIBRARY
        NAMES   libosmogsm osmogsm
        HINTS   ${PC_libosmogsm_LIBDIR}
                ${PC_libosmogsm_LIBRARY_DIRS}
                ${CMAKE_INSTALL_PREFIX}/lib/
                ${CMAKE_INSTALL_PREFIX}/lib64/
        PATHS   /usr/local/lib
                /usr/lib
)


set(LIBOSMOGSM_LIBRARIES ${LIBOSMOGSM_LIBRARY})
set(LIBOSMOGSM_INCLUDE_DIRS ${LIBOSMOGSM_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libosmogsm  DEFAULT_MSG LIBOSMOGSM_LIBRARY LIBOSMOGSM_INCLUDE_DIR)
mark_as_advanced(LIBOSMOGSM_INCLUDE_DIR LIBOSMOGSM_LIBRARY )
