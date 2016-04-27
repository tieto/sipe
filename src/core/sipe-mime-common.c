/**
 * @file sipe-mime.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2015 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-common.h"
#include "sipe-mime.h"
#include "sipe-utils.h"

struct parts_contain_cb_data {
	const gchar * type;
	gboolean result;
};

static void
parts_contain_cb(gpointer user_data, const GSList *fields,
		 SIPE_UNUSED_PARAMETER const gchar *body,
		 SIPE_UNUSED_PARAMETER gsize length)
{
	struct parts_contain_cb_data *data = user_data;

	if (!data->result &&
	    sipe_strequal(data->type, sipe_utils_nameval_find(fields, "Content-Type"))) {
		data->result = TRUE;
	}
}

gboolean
sipe_mime_parts_contain(const gchar *type,
			const gchar *body,
			const gchar *part_type)
{
	struct parts_contain_cb_data data;
	data.type = part_type;
	data.result = FALSE;

	sipe_mime_parts_foreach(type, body, parts_contain_cb, &data);
	return data.result;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
