/**
 * @file sipe-mime.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
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

#include <string.h>

#include "sipe-common.h"

#include <glib.h>

/*
 * GMIME interfaces fail to compile on ARM architecture with -Wcast-align
 *
 * Diagnostic #pragma was added in GCC 4.2.0
 */
#if defined(__GNUC__)
#if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || (__GNUC__ >= 5)
#if defined(__ARMEL__) || defined(__ARMEB__) || defined(__mips__) || defined(__sparc__) || (defined(__powerpc__) && defined(__NO_FPRS__))
#pragma GCC diagnostic ignored "-Wcast-align"
#endif
#endif
#endif

#include <gmime/gmime.h>

#include "sipe-mime.h"

#include "sipe-backend.h"
#include "sipe-utils.h"

void sipe_mime_init(void)
{
	g_mime_init(0);
}

void sipe_mime_shutdown(void)
{
	g_mime_shutdown();
}

struct gmime_callback_data {
	sipe_mime_parts_cb callback;
	gpointer user_data;
};

static GSList *gmime_fields_to_nameval(GMimeObject *part)
{
	GMimeHeaderList *headers = g_mime_object_get_header_list(part);
	GMimeHeaderIter *iter = g_mime_header_iter_new();
	GSList *fields = NULL;

	if (g_mime_header_list_get_iter(headers, iter)) {
		do {
			fields = sipe_utils_nameval_add(fields,
							g_mime_header_iter_get_name(iter),
							g_mime_header_iter_get_value(iter));

		} while (g_mime_header_iter_next(iter));
	}
	g_mime_header_iter_free(iter);

	return fields;
}

static void gmime_callback(SIPE_UNUSED_PARAMETER GMimeObject *parent,
			   GMimeObject *part,
			   gpointer user_data)
{
	GMimeDataWrapper *data = g_mime_part_get_content_object((GMimePart *)part);

	if (data) {
		GMimeStream *stream = g_mime_data_wrapper_get_stream(data);

		if (stream) {
			ssize_t length = 0;
			const char *encoding;
			gchar *buffer;
			GString *content;

			encoding = g_mime_object_get_header(part,
					"Content-Transfer-Encoding");
			if (encoding) {
				GMimeFilter *filter = g_mime_filter_basic_new(
						g_mime_content_encoding_from_string(encoding), FALSE);
				stream = g_mime_stream_filter_new (stream);
				g_mime_stream_filter_add(GMIME_STREAM_FILTER(stream), filter);
				g_object_unref (filter);
			}

			/* g_mime_stream_read() might not read everything in one call */
			content = g_string_new(NULL);
			buffer = g_malloc(4096);
			while ((length = g_mime_stream_read(stream, buffer, 4096)) > 0) {
				g_string_append_len(content, buffer, length);
			}
			g_free(buffer);

			if (length == 0) {
				struct gmime_callback_data *cd = user_data;
				GSList *fields = gmime_fields_to_nameval(part);

				cd->callback(cd->user_data, fields,
						content->str, content->len);

				sipe_utils_nameval_free(fields);
			}

			g_string_free(content, TRUE);

			if (encoding) {
				// Unref GMimeStreamFilter wrapping GMimeStream.
				g_object_unref(stream);
			}
		}
	}
}

void sipe_mime_parts_foreach(const gchar *type,
			     const gchar *body,
			     sipe_mime_parts_cb callback,
			     gpointer user_data)
{
	gchar *doc = g_strdup_printf("Content-Type: %s\r\n\r\n%s", type, body);
	GMimeStream *stream = g_mime_stream_mem_new_with_buffer(doc, strlen(doc));

	if (stream) {
		GMimeParser *parser = g_mime_parser_new_with_stream(stream);
		GMimeMultipart *multipart = (GMimeMultipart *)g_mime_parser_construct_part(parser);

		if (multipart) {
			struct gmime_callback_data cd = {callback, user_data};

			SIPE_DEBUG_INFO("sipe_mime_parts_foreach: %d parts", g_mime_multipart_get_count(multipart));

			g_mime_multipart_foreach(multipart, gmime_callback, &cd);
			g_object_unref(multipart);
		}

		g_object_unref(parser);
		g_object_unref(stream);
	}
	g_free(doc);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
