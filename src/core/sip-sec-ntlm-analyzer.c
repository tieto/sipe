/**
 * @file sip-sec-ntlm-analyzer.c
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
 *
 *
 * Takes Base64-encoded gssapi-data= values from NTLM authentication attempt
 * on the command line and prints out the NTLM message contents in human readable
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
#define _SIPE_COMPILING_ANALYZER
#include "sip-sec-ntlm.c"

/* stub functions */
void sipe_backend_debug(SIPE_UNUSED_PARAMETER sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

gboolean sipe_strequal(const gchar *left, const gchar *right)
{
#if GLIB_CHECK_VERSION(2,16,0)
	return (g_strcmp0(left, right) == 0);
#else
	return ((left == NULL && right == NULL) ||
	        (left != NULL && right != NULL && strcmp(left, right) == 0));
#endif
}

/* copied from sipe-utils.c */
char *buff_to_hex_str(const guint8 *buff, const size_t buff_len)
{
	char *res;
	size_t i, j;

	if (!buff) return NULL;

        res = g_malloc(buff_len * 2 + 1);
	for (i = 0, j = 0; i < buff_len; i++, j+=2) {
		sprintf(&res[j], "%02X", buff[i]);
	}
	res[j] = '\0';
	return res;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <gssapi-data> ...\n", argv[0]);
		return(1);
	}

	sip_sec_init__ntlm();

	while (--argc > 0) {
		const gchar *base64 = *++argv;
		SipSecBuffer buffer;

		printf("Base64: %s\n", base64);
		buffer.value = g_base64_decode(base64, &buffer.length);
		if (buffer.value && buffer.length) {
			printf("Decoded %" G_GSIZE_FORMAT " bytes\n", buffer.length);
			sip_sec_ntlm_message_describe(&buffer, "analyzed");
			printf("-------------------------------------------------------------------------------\n");
			g_free(buffer.value);
		} else {
			printf("Corrupted Base64 - skipping\n");
		}
	}

	sip_sec_destroy__ntlm();

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
