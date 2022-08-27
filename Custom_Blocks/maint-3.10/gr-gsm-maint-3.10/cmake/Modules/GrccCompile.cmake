# Author (C) 2018 by Piotr Krysik <ptrkrysik@gmail.com>
# Author (C) 2018 by Vasil Velichkov <vvvelichkov@gmail.com>
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

SET(PYTHONPATH
    ${CMAKE_BINARY_DIR}/test_modules
    $ENV{PYTHONPATH}
    )
string(REPLACE ";" ":" PYTHONPATH "${PYTHONPATH}")

find_program(GRCC grcc
    PATHS ${CMAKE_INSTALL_PREFIX}/${GR_RUNTIME_DIR}
    )

macro(GRCC_COMPILE file_name)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${file_name}
        COMMAND "${CMAKE_COMMAND}"
        -E env PYTHONPATH="${PYTHONPATH}" GRC_BLOCKS_PATH=${CMAKE_SOURCE_DIR}/grc
        CMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
        ${GRCC} -o ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/${file_name}.grc
        COMMAND "${CMAKE_COMMAND}" -E rename ${CMAKE_CURRENT_BINARY_DIR}/${file_name}.py ${CMAKE_CURRENT_BINARY_DIR}/${file_name}
        DEPENDS ${file_name}.grc
        )
endmacro(GRCC_COMPILE)

########################################################################
# Override the GR_UNIQUE_TARGET function to not append a hash
# to the `target` name, because we need a known name in order
# to add an explicit dependency that's needed for the parallel build
#
# The original code segment (taken from GrPython.cmake) is
#
#    execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import re, hashlib
#unique = hashlib.md5('${reldir}${ARGN}').hexdigest()[:5]
#print(re.sub('\\W', '_', '${desc} ${reldir} ' + unique))"
#    OUTPUT_VARIABLE _target OUTPUT_STRIP_TRAILING_WHITESPACE)
#
########################################################################
function(GR_UNIQUE_TARGET desc)
    file(RELATIVE_PATH reldir ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
    execute_process(COMMAND ${PYTHON_EXECUTABLE} -c "import re, hashlib
print(re.sub('\\W', '_', '${desc} ${reldir}'))"
    OUTPUT_VARIABLE _target OUTPUT_STRIP_TRAILING_WHITESPACE)
    add_custom_target(${_target} ALL DEPENDS ${ARGN})
endfunction(GR_UNIQUE_TARGET)
