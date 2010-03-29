/**
 * @file sipe-backend.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/** DEBUGGING ****************************************************************/

typedef enum {
	SIPE_DEBUG_LEVEL_INFO,
	SIPE_DEBUG_LEVEL_WARNING,
	SIPE_DEBUG_LEVEL_ERROR,
	SIPE_DEBUG_LEVEL_FATAL,
}  sipe_debug_level;

/**
 * Output debug information
 *
 * Shouldn't be used directly. Instead use SIPE_DEBUG_xxx() macros
 *
 * @param level  debug level
 * @param format format string. "\n" will be automatically appended.
 */
void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...) G_GNUC_PRINTF(2, 3);

/* Convenience macros */
#define SIPE_DEBUG_INFO(fmt, ...)        sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    fmt, __VA_ARGS__)
#define SIPE_DEBUG_INFO_NOFORMAT(msg)    sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    msg)
#define SIPE_DEBUG_WARNING(fmt, ...)     sipe_backend_debug(SIPE_DEBUG_LEVEL_WARNING, fmt, __VA_ARGS__)
#define SIPE_DEBUG_WARNING_NOFORMAT(msg) sipe_backend_debug(SIPE_DEBUG_LEVEL_WARNING, msg)
#define SIPE_DEBUG_ERROR(fmt, ...)       sipe_backend_debug(SIPE_DEBUG_LEVEL_ERROR,   fmt, __VA_ARGS__)
#define SIPE_DEBUG_ERROR_NOFORMAT(msg)   sipe_backend_debug(SIPE_DEBUG_LEVEL_ERROR,   msg)
#define SIPE_DEBUG_FATAL(fmt, ...)       sipe_backend_debug(SIPE_DEBUG_LEVEL_FATAL,   fmt, __VA_ARGS__)
#define SIPE_DEBUG_FATAL_NOFORMAT(msg)   sipe_backend_debug(SIPE_DEBUG_LEVEL_FATAL,   msg)

/** DIGEST *******************************************************************/

const guchar *sipe_backend_digest_sha1(const guchar *data, gsize length);

/** MARKUP *******************************************************************/

gchar *sipe_backend_markup_css_property(const gchar *style,
					const gchar *option); 
gchar *sipe_backend_markup_strip_html(const gchar *html);

/** NETWORK ******************************************************************/

const gchar *sipe_backend_network_ip_address(void);
