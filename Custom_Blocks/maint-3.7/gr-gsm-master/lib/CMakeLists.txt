# Copyright 2011,2012 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

include(GrPlatform) #define LIB_SUFFIX
include(GrMiscUtils)

########################################################################
# Add sources macro
########################################################################
set(grgsm_sources "")

macro (add_sources)
    file (RELATIVE_PATH _relPath "${PROJECT_SOURCE_DIR}/lib" "${CMAKE_CURRENT_SOURCE_DIR}")
    foreach (_src ${ARGN})
        if (_relPath)
            list (APPEND grgsm_sources "${_relPath}/${_src}")
        else()
            list (APPEND grgsm_sources "${_src}")
        endif()
    endforeach()
    if (_relPath)
        # propagate grgsm_sources to parent directory
        set (grgsm_sources ${grgsm_sources} PARENT_SCOPE)
    endif()
endmacro()

########################################################################
# Handle the generated constants
########################################################################
execute_process(COMMAND ${PYTHON_EXECUTABLE} -c
    "import time;print time.strftime('%a, %d %b %Y %H:%M:%S', time.gmtime())"
    OUTPUT_VARIABLE BUILD_DATE OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "Loading build date ${BUILD_DATE} into constants...")
message(STATUS "Loading version ${VERSION} into constants...")

#double escape for windows backslash path separators
string(REPLACE "\\" "\\\\" prefix "${prefix}")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/constants.cc.in
    ${CMAKE_CURRENT_BINARY_DIR}/constants.cc
    ESCAPE_QUOTES
@ONLY)

list(APPEND grgsm_sources ${CMAKE_CURRENT_BINARY_DIR}/constants.cc)
#########################################################################
# Subdirecories
#########################################################################
add_subdirectory(decoding)
add_subdirectory(decryption)
add_subdirectory(demapping)
add_subdirectory(flow_control)
add_subdirectory(misc_utils)
add_subdirectory(qa_utils)
add_subdirectory(receiver)
add_subdirectory(transmitter)
add_subdirectory(trx)

########################################################################
# Setup library
########################################################################
include_directories(${Boost_INCLUDE_DIR} receiver)
link_directories(${Boost_LIBRARY_DIRS})

set(grgsm_link_libraries "")
list (APPEND grgsm_link_libraries ${Boost_LIBRARIES})
list (APPEND grgsm_link_libraries ${GNURADIO_ALL_LIBRARIES})
list (APPEND grgsm_link_libraries ${VOLK_LIBRARIES})
if(WIN32)
    list (APPEND grgsm_link_libraries wsock32)
    list (APPEND grgsm_link_libraries ws2_32)
endif()

if(NOT LOCAL_OSMOCOM)
    list (APPEND grgsm_link_libraries ${LIBOSMOCORE_LIBRARIES} ${LIBOSMOCODEC_LIBRARIES} ${LIBOSMOGSM_LIBRARY})
    if(LIBOSMOCODING_FOUND)
        list (APPEND grgsm_link_libraries ${LIBOSMOCODING_LIBRARIES})
    endif()
endif()

add_library(grgsm SHARED ${grgsm_sources})
target_link_libraries(grgsm ${grgsm_link_libraries}
# libraries required by plotting.h - have troubles to be installed by pybombs
#    boost_iostreams
#    boost_system
#    boost_filesystem
)

set_target_properties(grgsm PROPERTIES DEFINE_SYMBOL "grgsm_EXPORTS")
GR_LIBRARY_FOO(grgsm)

########################################################################
# Install built library files
########################################################################
install(TARGETS grgsm
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)

########################################################################
# Build and register unit test
########################################################################
#include(GrTest)

#include_directories(${CPPUNIT_INCLUDE_DIRS})

#list(APPEND test_grgsm_sources
#    ${CMAKE_CURRENT_SOURCE_DIR}/test_gsm.cc
#    ${CMAKE_CURRENT_SOURCE_DIR}/qa_gsm.cc
#    ${CMAKE_CURRENT_SOURCE_DIR}/qa_receiver.cc
#)

#add_executable(test-gsm ${test_grgsm_sources})

#target_link_libraries(
#  test-gsm
#  ${GNURADIO_RUNTIME_LIBRARIES}
#  ${Boost_LIBRARIES}
#  ${CPPUNIT_LIBRARIES}
#  grgsm
#)

#GR_ADD_TEST(test_gsm test-gsm)
