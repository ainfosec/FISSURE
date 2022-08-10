#
# Try to find the wireshark library and its includes
#
# This snippet sets the following variables:
#  WIRESHARK_FOUND             True if wireshark library got found
#  WIRESHARK_INCLUDE_DIRS      Location of the wireshark headers 
#  WIRESHARK_LIBRARIES         List of libraries to use wireshark
#
#  Copyright (c) 2011 Reinhold Kainhofer <reinhold@kainhofer.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

# wireshark does not install its library with pkg-config information,
# so we need to manually find the libraries and headers

FIND_PATH( WIRESHARK_INCLUDE_DIRS epan/packet.h PATH_SUFFIXES wireshark )
FIND_LIBRARY( WIRESHARK_LIBRARIES wireshark )

# Report results
IF ( WIRESHARK_LIBRARIES AND WIRESHARK_INCLUDE_DIRS )
  SET( WIRESHARK_FOUND 1 )
ELSE ( WIRESHARK_LIBRARIES AND WIRESHARK_INCLUDE_DIRS )
  MESSAGE( SEND_ERROR "Could NOT find the wireshark library and headers" )
ENDIF ( WIRESHARK_LIBRARIES AND WIRESHARK_INCLUDE_DIRS )

