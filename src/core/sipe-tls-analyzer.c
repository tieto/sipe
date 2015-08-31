/**
 * @file sipe-tls-analyzer.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2015 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * Takes Base64-encoded gssapi-data= values from TLS-DSK authentication attempt
 * on the command line and prints out the TLS message contents in human readable
 * format.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "sipe-common.h"
#include "sipe-utils.h"
#define _SIPE_COMPILING_ANALYZER
#include "sipe-tls.c"

/* stub functions */
void sipe_backend_debug_literal(SIPE_UNUSED_PARAMETER sipe_debug_level level,
				const gchar *msg)
{
	printf("%s", msg);
}

void sipe_backend_debug(SIPE_UNUSED_PARAMETER sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

int main(int argc, char *argv[])
{
	struct tls_internal_state *state;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <gssapi-data> ...\n", argv[0]);
		return(1);
	}

	state = g_new0(struct tls_internal_state, 1);
	state->debug = g_string_new("");

	while (--argc > 0) {
		const gchar *base64 = *++argv;
		guchar *buffer;

		printf("Base64: %s\n", base64);
		buffer = g_base64_decode(base64, &state->common.in_length);
		if (buffer && state->common.in_length) {
			printf("Decoded %" G_GSIZE_FORMAT " bytes\n",
			       state->common.in_length);
			state->common.in_buffer = buffer;
			tls_record_parse(state, TRUE, 0);
			free_parse_data(state);
			printf("-------------------------------------------------------------------------------\n");
			g_free(buffer);
		} else {
			printf("Corrupted Base64 - skipping\n");
		}
	}

	g_string_free(state->debug, TRUE);
	g_free(state);

	return(0);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
