/**
 * @file sipe-webticket.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipe_core_private;
struct sipe_svc_session;

/**
 * Web Ticket callback
 *
 * @param sipe_private  SIPE core private data
 * @param base_uri      Web Service base URI
 * @param auth_uri      Web Service auth. URI    (@c NULL when request aborted)
 * @param wsse_security Web Ticket XML fragment  (@c NULL when request failed)
 * @param failure_msg   Web Ticket error message (may be @c NULL)
 * @param callback_data callback data
 */
typedef void (sipe_webticket_callback)(struct sipe_core_private *sipe_private,
				       const gchar *base_uri,
				       const gchar *auth_uri,
				       const gchar *wsse_security,
				       const gchar *failure_msg,
				       gpointer callback_data);

/**
 * Request a Web Ticket for Web Service URI
 *
 * NOTE: the callback can be called immediately if the Web Ticket is cached.
 *       The callback data must therefore be properly initialized already.
 *
 * @param sipe_private  SIPE core private data
 * @param base_uri      Web Service base URI
 * @param port_name     Web Service authentication port name
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if web ticket fetch was triggered
 */
gboolean sipe_webticket_request(struct sipe_core_private *sipe_private,
				struct sipe_svc_session *session,
				const gchar *base_uri,
				const gchar *port_name,
				sipe_webticket_callback *callback,
				gpointer callback_data);

/**
 * Free webticket data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_webticket_free(struct sipe_core_private *sipe_private);
