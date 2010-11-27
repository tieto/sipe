/**
 * @file miranda-debug.c
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

#include <windows.h>
#include <process.h>
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"

#include "sipe-backend.h"
#include "miranda-private.h"

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	FILE *fh;
	char *str;

	if (0) {
//		str = sipe_miranda_getString(pr, "debuglog");
	} else {
		str = g_strdup("c:/sipsimple.log");
	}

	if (sipe_backend_debug_enabled()) {
		if (!fopen_s(&fh, str, "a")) {
			fprintf(fh, "<[%d]> %s\n", _getpid(), msg);
			fclose(fh);
		}
	}
	g_free(str);

}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...) G_GNUC_PRINTF(2, 3)
{
	va_list ap;

	va_start(ap,format);

	if (sipe_backend_debug_enabled()) {
		gchar *msg = g_strdup_vprintf(format, ap);
		sipe_backend_debug_literal(level, msg);
		g_free(msg);
	}

	va_end(ap);
}

gboolean sipe_backend_debug_enabled(void)
{
	return TRUE;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
