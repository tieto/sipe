/**
 * @file sipe-svc.h
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
struct sipe_tls_random;
struct _sipe_xml;

/**
 * Service XML callback
 *
 * @param sipe_private  SIPE core private data
 * @param uri           service URI     (NULL when request aborted)
 * @param raw           raw XML data    (NULL when request failed)
 * @param xml           parsed XML data (NULL when request failed)
 * @param callback_data callback data
 */
typedef void (sipe_svc_callback)(struct sipe_core_private *sipe_private,
				 const gchar *uri,
				 const gchar *raw,
				 struct _sipe_xml *xml,
				 gpointer callback_data);

/**
 * Start a session of related service requests
 *
 * @return Opaque session pointer
 */
struct sipe_svc_session *sipe_svc_session_start(void);

/**
 * Close a session of related service requests
 *
 * @param session Opaque session pointer
 */
void sipe_svc_session_close(struct sipe_svc_session *session);

/**
 * Trigger fetch of Get & Publish certificate
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param uri           service URI
 * @param wsse_security predefined authentication token
 * @param certreq       certificate request (Base64 encoded)
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if certificate fetch was triggered
 */
gboolean sipe_svc_get_and_publish_cert(struct sipe_core_private *sipe_private,
				       struct sipe_svc_session *session,
				       const gchar *uri,
				       const gchar *wsse_security,
				       const gchar *certreq,
				       sipe_svc_callback *callback,
				       gpointer callback_data);

/**
 * Trigger [MS-DLX] address book entry search
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param uri           service URI
 * @param wsse_security predefined authentication token
 * @param search        [MS-DLX] AbEntryRequest.ChangeSearchQuery in XML
 * @param entries       array entries in search XML string
 * @param max_returns   how many entries to return
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if search was triggered
 */
gboolean sipe_svc_ab_entry_request(struct sipe_core_private *sipe_private,
				   struct sipe_svc_session *session,
				   const gchar *uri,
				   const gchar *wsse_security,
				   const gchar *search,
				   guint entries,
				   guint max_returns,
				   sipe_svc_callback *callback,
				   gpointer callback_data);

/**
 * Trigger fetch of WebTicket security token
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param uri           service URI
 * @param wsse_security predefined authentication token. May be @c NULL
 * @param service_uri   request token for this service URI
 * @param entropy       random bytes buffer for entropy
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if token fetch was triggered
 */
gboolean sipe_svc_webticket(struct sipe_core_private *sipe_private,
			    struct sipe_svc_session *session,
			    const gchar *uri,
			    const gchar *wsse_security,
			    const gchar *service_uri,
			    const struct sipe_tls_random *entropy,
			    sipe_svc_callback *callback,
			    gpointer callback_data);

/**
 * Trigger fetch of WebTicket security token from ADFS of a federated domain
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param adfs_uri      ADFS authentication URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if token fetch was triggered
 */
gboolean sipe_svc_webticket_adfs(struct sipe_core_private *sipe_private,
				 struct sipe_svc_session *session,
				 const gchar *adfs_uri,
				 sipe_svc_callback *callback,
				 gpointer callback_data);

/**
 * Trigger fetch of WebTicket security token from login.microsoftonline.com
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param service_uri   request token for this service URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if token fetch was triggered
 */
gboolean sipe_svc_webticket_lmc(struct sipe_core_private *sipe_private,
				struct sipe_svc_session *session,
				const gchar *service_uri,
				sipe_svc_callback *callback,
				gpointer callback_data);

/**
 * Trigger fetch of WebTicket security token from login.microsoftonline.com
 * using a Web Ticket acquired
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param wsse_security predefined authentication token. May be @c NULL
 * @param service_uri   request token for this service URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if token fetch was triggered
 */
gboolean sipe_svc_webticket_lmc_federated(struct sipe_core_private *sipe_private,
					  struct sipe_svc_session *session,
					  const gchar *wsse_security,
					  const gchar *service_uri,
					  sipe_svc_callback *callback,
					  gpointer callback_data);

/**
 * Trigger fetch of RealmInfo data from login.microsoftonline.com
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if data fetch was triggered
 */
gboolean sipe_svc_realminfo(struct sipe_core_private *sipe_private,
			    struct sipe_svc_session *session,
			    sipe_svc_callback *callback,
			    gpointer callback_data);

/**
 * Trigger fetch of service metadata
 *
 * @param sipe_private  SIPE core private data
 * @param session       opaque session pointer
 * @param uri           service URI
 * @param callback      callback function
 * @param callback_data callback data
 * @return              @c TRUE if metadata fetch was triggered
 */
gboolean sipe_svc_metadata(struct sipe_core_private *sipe_private,
			   struct sipe_svc_session *session,
			   const gchar *uri,
			   sipe_svc_callback *callback,
			   gpointer callback_data);

/**
 * Free service data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_svc_free(struct sipe_core_private *sipe_private);
