#
#  Copyright (C) 2014 Bastian Bloessl <bloessl@ccs-labs.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Install public header files
########################################################################
install(FILES
    api.h
    decoder.h
    encoder.h
    parser.h DESTINATION include/rds
)
