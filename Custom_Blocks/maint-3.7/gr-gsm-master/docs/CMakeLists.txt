# Copyright 2011 Free Software Foundation, Inc.
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

########################################################################
# Setup dependencies
########################################################################
find_package(Doxygen)

########################################################################
# Begin conditional configuration
########################################################################
if(ENABLE_DOXYGEN)

########################################################################
# Add subdirectories
########################################################################
add_subdirectory(doxygen)

endif(ENABLE_DOXYGEN)

########################################################################
# Convert manual pages from rst to roff and install them
########################################################################
find_program(RST2MAN_EXECUTABLE NAMES rst2man rst2man.py rst2man2 rst2man2.py)

function(BUILD_MAN_PAGE _sources _src _dst)
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${_dst}"
                       COMMAND ${RST2MAN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/${_src} ${CMAKE_CURRENT_BINARY_DIR}/${_dst}
                       DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_src})

    list(APPEND ${_sources} "${CMAKE_CURRENT_BINARY_DIR}/${_dst}")
    set(${_sources} ${${_sources}} PARENT_SCOPE)

    add_custom_target(man_${_src} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${_dst})
endfunction()

if(NOT RST2MAN_EXECUTABLE)
    message(WARNING "rst2man from python-docutils is required to build man pages")
else()
    build_man_page(MAN1_OUTPUT grgsm_livemon.rst grgsm_livemon.1)
    install(FILES ${MAN1_OUTPUT} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1)
endif()


