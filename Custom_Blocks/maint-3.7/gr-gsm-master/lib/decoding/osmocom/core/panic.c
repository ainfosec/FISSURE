/*! \file panic.c
 *  Routines for panic handling. */
/*
 * (C) 2010 by Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/*! \addtogroup utils
 *  @{
 * \file panic.c */

#include <osmocom/core/panic.h>
//#include <osmocom/core/backtrace.h>

//#include "../config.h"


static osmo_panic_handler_t osmo_panic_handler = (void*)0;


#ifndef PANIC_INFLOOP

#include <stdio.h>
#include <stdlib.h>

static void osmo_panic_default(const char *fmt, va_list args)
{
	vfprintf(stderr, fmt, args);
	//osmo_generate_backtrace();
	abort();
}

#else

static void osmo_panic_default(const char *fmt, va_list args)
{
	while (1);
}

#endif


/*! Terminate the current program with a panic
 *
 * You can call this function in case some severely unexpected situation
 * is detected and the program is supposed to terminate in a way that
 * reports the fact that it terminates.
 *
 * The application can register a panic handler function using \ref
 * osmo_set_panic_handler.  If it doesn't, a default panic handler
 * function is called automatically.
 *
 * The default function on most systems will generate a backtrace and
 * then abort() the process.
 */
void osmo_panic(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	if (osmo_panic_handler)
		osmo_panic_handler(fmt, args);
	else
		osmo_panic_default(fmt, args);

	va_end(args);
}
 

/*! Set the panic handler
 *  \param[in] h New panic handler function
 *
 *  This changes the panic handling function from the currently active
 *  function to a new call-back function supplied by the caller.
 */
void osmo_set_panic_handler(osmo_panic_handler_t h)
{
	osmo_panic_handler = h;
}

/*! @} */
