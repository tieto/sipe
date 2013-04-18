/**
 * @file sip-sec-digest-test.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
 *
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <glib.h>

#include "sipe-common.h"
#include "uuid.h"

#include "sip-sec-digest.c"

/*
 * Stubs
 */
gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG(%d): %s\n", level, msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	gchar *newformat = g_strdup_printf("DEBUG(%d): %s\n", level, format);

	va_start(ap, format);
	vprintf(newformat, ap);
	va_end(ap);

	g_free(newformat);
}

const gchar *sipe_backend_network_ip_address(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return(NULL);
}

char *generateUUIDfromEPID(SIPE_UNUSED_PARAMETER const gchar *epid)
{
	return(NULL);
}

char *sipe_get_epid(SIPE_UNUSED_PARAMETER const char *self_sip_uri,
		    SIPE_UNUSED_PARAMETER const char *hostname,
		    SIPE_UNUSED_PARAMETER const char *ip_address)
{
	return(NULL);
}

/*
 * Tester code
 */
int main(SIPE_UNUSED_PARAMETER int argc, SIPE_UNUSED_PARAMETER char *argv[])
{
	guint failed = 0;

	return(failed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
