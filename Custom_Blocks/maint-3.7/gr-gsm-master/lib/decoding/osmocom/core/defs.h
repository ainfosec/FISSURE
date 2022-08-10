/*! \file defs.h
 *  General definitions that are meant to be included from header files.
 */

#pragma once

/*! \defgroup utils General-purpose utility functions
 *  @{
 * \file defs.h */

/*! Check for gcc and version.
 *
 * \note Albeit glibc provides a features.h file that contains a similar
 *       definition (__GNUC_PREREQ), this definition has been copied from there
 *       to have it available with other libraries, too.
 *
 * \return != 0 iff gcc is used and it's version is at least maj.min.
 */
#if defined __GNUC__ && defined __GNUC_MINOR__
# define OSMO_GNUC_PREREQ(maj, min) \
	((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
# define OSMO_GNUC_PREREQ(maj, min) 0
#endif

/*! Set the deprecated attribute with a message.
 */
#if defined(__clang__)
# define _OSMO_HAS_ATTRIBUTE_DEPRECATED __has_attribute(deprecated)
# define _OSMO_HAS_ATTRIBUTE_DEPRECATED_WITH_MESSAGE __has_extension(attribute_deprecated_with_message)
#elif defined(__GNUC__)
# define _OSMO_HAS_ATTRIBUTE_DEPRECATED 1
# define _OSMO_HAS_ATTRIBUTE_DEPRECATED_WITH_MESSAGE OSMO_GNUC_PREREQ(4,5)
#endif

#if _OSMO_HAS_ATTRIBUTE_DEPRECATED_WITH_MESSAGE
# define OSMO_DEPRECATED(text)  __attribute__((__deprecated__(text)))
#elif _OSMO_HAS_ATTRIBUTE_DEPRECATED
# define OSMO_DEPRECATED(text)  __attribute__((__deprecated__))
#else
# define OSMO_DEPRECATED(text)
#endif

#if BUILDING_LIBOSMOCORE
# define OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE
#else
# define OSMO_DEPRECATED_OUTSIDE_LIBOSMOCORE OSMO_DEPRECATED("For internal use inside libosmocore only.")
#endif

#undef _OSMO_HAS_ATTRIBUTE_DEPRECATED_WITH_MESSAGE
#undef _OSMO_HAS_ATTRIBUTE_DEPRECATED

/*! @} */
