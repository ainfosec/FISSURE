#pragma once

/*! \addtogroup utils
 *  @{
 * \file panic.h */

#include <stdarg.h>

/*! panic handler callback function type */
typedef void (*osmo_panic_handler_t)(const char *fmt, va_list args);

extern void osmo_panic(const char *fmt, ...);
extern void osmo_set_panic_handler(osmo_panic_handler_t h);

/*! @} */
