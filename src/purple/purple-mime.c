/**
 * @file purple-mime.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"

#include "mime.h"

#include "sipe-mime.h"
#include "sipe-core.h"

void sipe_mime_init(void)
{
	/* Nothing to do */
}

void sipe_mime_shutdown(void)
{
	/* Nothing to do */
}

static
GSList * mime_fields_to_nameval(PurpleMimePart* part)
{
	GList *keys = purple_mime_part_get_fields(part);
	GSList *fields = NULL;

	while (keys) {
		const char *key = keys->data;
		const char *value = purple_mime_part_get_field(part, key);

		fields = sipe_utils_nameval_add(fields, key, value);

		keys = keys->next;
	}

	return fields;
}

void sipe_mime_parts_foreach(const gchar *type,
			     const gchar *body,
			     sipe_mime_parts_cb callback,
			     gpointer user_data)
{
	gchar *doc = g_strdup_printf("Content-Type: %s\r\n\r\n%s", type, body);
	PurpleMimeDocument *mime = purple_mime_document_parse(doc);

	if (mime) {
		GList* parts = purple_mime_document_get_parts(mime);

		while (parts) {
			const gchar *content_type = purple_mime_part_get_field(parts->data,
									       "Content-Type");
			if (content_type) {
				const gchar *content = NULL;
				gchar *content_decoded = NULL;
				gsize length = 0;

				GSList *fields = mime_fields_to_nameval(parts->data);

				purple_mime_part_get_data_decoded(parts->data,
								  (guchar **)&content_decoded, &length);
				if (content_decoded) {
					content = content_decoded;
				} else {
					/* Unknown encoding in Content-Transfer-Encoding
					 * field; revert to the plain content extraction. */
					content = purple_mime_part_get_data(parts->data);
					length = purple_mime_part_get_length(parts->data);
				}

				(*callback)(user_data, fields, content, length);

				sipe_utils_nameval_free(fields);
				g_free(content_decoded);
			}
			parts = parts->next;
		}
		purple_mime_document_free(mime);
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
