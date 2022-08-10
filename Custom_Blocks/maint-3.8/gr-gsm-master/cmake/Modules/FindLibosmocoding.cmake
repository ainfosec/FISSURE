find_package(PkgConfig)
pkg_check_modules(PC_libosmocoding libosmocoding)
set(LIBOSMOCODING_DEFINITIONS ${PC_LIBOSMOCODING_CFLAGS_OTHER})

find_path(
        LIBOSMOCODING_INCLUDE_DIR
        NAMES   osmocom/coding/gsm0503_coding.h
        HINTS   ${PC_libosmocoding_INCLUDEDIR}
                ${PC_libosmocoding_INCLUDE_DIRS}
                ${CMAKE_INSTALL_PREFIX}/include
        PATHS   /usr/local/include
                /usr/include
)

find_library(
        LIBOSMOCODING_LIBRARY
        NAMES   libosmocoding osmocoding
        HINTS   ${PC_libosmocoding_LIBDIR}
                ${PC_libosmocoding_LIBRARY_DIRS}
                ${CMAKE_INSTALL_PREFIX}/lib/
                ${CMAKE_INSTALL_PREFIX}/lib64/
        PATHS   /usr/local/lib
                /usr/lib
)


set(LIBOSMOCODING_LIBRARIES ${LIBOSMOCODING_LIBRARY})
set(LIBOSMOCODING_INCLUDE_DIRS ${LIBOSMOCODING_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libosmocoding  DEFAULT_MSG LIBOSMOCODING_LIBRARY LIBOSMOCODING_INCLUDE_DIR)
mark_as_advanced(LIBOSMOCODING_INCLUDE_DIR LIBOSMOCODING_LIBRARY )