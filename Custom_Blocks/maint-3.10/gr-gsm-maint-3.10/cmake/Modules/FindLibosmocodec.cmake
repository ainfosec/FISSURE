INCLUDE(FindPkgConfig)
pkg_check_modules(PC_libosmocodec libosmocodec)
set(LIBOSMOCODEC_DEFINITIONS ${PC_LIBOSMOCODEC_CFLAGS_OTHER})

find_path(
        LIBOSMOCODEC_INCLUDE_DIR
        NAMES   osmocom/codec/codec.h
        HINTS   ${PC_libosmocodec_INCLUDEDIR}
                ${PC_libosmocodec_INCLUDE_DIRS}
                ${CMAKE_INSTALL_PREFIX}/include
        PATHS   /usr/local/include
                /usr/include
)

find_library(
        LIBOSMOCODEC_LIBRARY
        NAMES   libosmocodec osmocodec
        HINTS   ${PC_libosmocodec_LIBDIR}
                ${PC_libosmocodec_LIBRARY_DIRS}
                ${CMAKE_INSTALL_PREFIX}/lib/
                ${CMAKE_INSTALL_PREFIX}/lib64/
        PATHS   /usr/local/lib
                /usr/lib
)


set(LIBOSMOCODEC_LIBRARIES ${LIBOSMOCODEC_LIBRARY})
set(LIBOSMOCODEC_INCLUDE_DIRS ${LIBOSMOCODEC_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libosmocodec  DEFAULT_MSG LIBOSMOCODEC_LIBRARY LIBOSMOCODEC_INCLUDE_DIR)
mark_as_advanced(LIBOSMOCODEC_INCLUDE_DIR LIBOSMOCODEC_LIBRARY )
