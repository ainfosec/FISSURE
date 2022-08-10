#
#  Copyright (C) 2013, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

########################################################################
# Install public header files
########################################################################

list(APPEND include_sources
    api.h
    chunks_to_symbols.h
    constellations.h
    decode_mac.h
    ether_encap.h
    frame_equalizer.h
    mac.h
    mapper.h
    parse_mac.h
    signal_field.h
    sync_long.h
    sync_short.h
)

install(
    FILES ${include_sources}
    DESTINATION ${GR_INCLUDE_DIR}
    COMPONENT "ieee802_11_devel"
)
