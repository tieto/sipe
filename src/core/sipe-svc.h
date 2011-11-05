/**
 * @file sipe-svc.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
struct _sipe_xml;

/**
 * Service XML callback
 *
 * @param sipe_private  SIPE core private data
 * @param uri           service URI     (NULL when request aborted)
 * @param xml           parsed XML data (NULL when request failed)
 * @param callback_data callback data
 */
typedef void (sipe_svc_callback)(struct sipe_core_private *sipe_private,
				 const gchar *uri,
				 struct _sipe_xml *xml,
				 gpointer callback_data);

/**
 * Trigger fetch of WebTicket security token
 *
 * @param sipe_private  SIPE core private data
 * @param uri           service URI
 * @param authuser      user name for authentication
 * @param service_uri   request token for this service URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if token fetch was triggered
 */
gboolean sipe_svc_webticket(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    const gchar *authuser,
			    const gchar *service_uri,
			    sipe_svc_callback *callback,
			    gpointer callback_data);

/**
 * Trigger fetch of service metadata
 *
 * @param sipe_private  SIPE core private data
 * @param uri           service URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if metadata fetch was triggered
 */
gboolean sipe_svc_metadata(struct sipe_core_private *sipe_private,
			   const gchar *uri,
			   sipe_svc_callback *callback,
			   gpointer callback_data);

/**
 * Free service data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_svc_free(struct sipe_core_private *sipe_private);
