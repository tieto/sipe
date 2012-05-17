/**
 * @file sipe-mime.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * MIME backend initialization
 */
void sipe_mime_init(void);

/**
 * MIME backend shutdown
 */
void sipe_mime_shutdown(void);

/**
 * Callback type for sipe_mime_parts_foreach().
 *
 * @param user_data callback data.
 * @param fields    list of @c sipnameval structures with the header fields
 * @param body      text of the MIME part.
 * @param length    length of the body text.
 */
typedef void (*sipe_mime_parts_cb)(gpointer user_data,
				   const GSList *fields,
				   const gchar *body,
				   gsize length);

/**
 * Parse MIME document and call a function for each part.
 *
 * @param type      content type of the MIME document.
 * @param body      body of the MIME document.
 * @param callback  function to call for each MIME part.
 * @param user_data callback data.
 */
void sipe_mime_parts_foreach(const gchar *type,
			     const gchar *body,
			     sipe_mime_parts_cb callback,
			     gpointer user_data);
