/**
 * @file sipe-http.h
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
 * Public interface to HTTP request service
 */

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipe_core_private;
struct sipe_http_request;
struct sipe_http_session;

/**
 * HTTP response callback
 *
 * @param sipe_private  SIPE core private data
 * @param status        status code
 * @param headers       response headers (@c NULL if request aborted)
 * @param body          response body    (@c NULL if request aborted)
 * @param callback_data callback data
 */
typedef void (sipe_http_response_callback)(struct sipe_core_private *sipe_private,
					   guint status,
					   GSList *headers,
					   const gchar *body,
					   gpointer callback_data);

/* HTTP response status codes */
#define SIPE_HTTP_STATUS_FAILED                0 /* internal use */
#define SIPE_HTTP_STATUS_OK                  200
#define SIPE_HTTP_STATUS_REDIRECTION         300 /* - 399 */
#define SIPE_HTTP_STATUS_CLIENT_ERROR        400 /* - 499 */
#define SIPE_HTTP_STATUS_CLIENT_UNAUTHORIZED 401
#define SIPE_HTTP_STATUS_CLIENT_FORBIDDEN    403
#define SIPE_HTTP_STATUS_CLIENT_PROXY_AUTH   407
#define SIPE_HTTP_STATUS_SERVER_ERROR        500 /* - 599 */
#define SIPE_HTTP_STATUS_CANCELLED            -2 /* internal use */
#define SIPE_HTTP_STATUS_ABORTED              -1 /* internal use */

/**
 * Free HTTP data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_http_free(struct sipe_core_private *sipe_private);

/**
 * Start HTTP session
 *
 * @return pointer to opaque HTTP session data structure
 */
struct sipe_http_session *sipe_http_session_start(void);

/**
 * Close HTTP session
 *
 * @param session pointer to opaque HTTP session data structure
 */
void sipe_http_session_close(struct sipe_http_session *session);

/**
 * Create HTTP GET request
 *
 * @param sipe_private  SIPE core private data
 * @param uri           URI
 * @param headers       additional headers (may be @c NULL)
 * @param callback      callback function
 * @param callback_data callback data
 *
 * @return pointer to opaque HTTP request data structure (@c NULL if failed)
 */
struct sipe_http_request *sipe_http_request_get(struct sipe_core_private *sipe_private,
						const gchar *uri,
						const gchar *headers,
						sipe_http_response_callback *callback,
						gpointer callback_data);

/**
 * Create HTTP POST request
 *
 * @param sipe_private  SIPE core private data
 * @param uri           URI
 * @param headers       additional headers (may be @c NULL)
 * @param body          body contents
 * @param content_type  body content type
 * @param callback      callback function
 * @param callback_data callback data
 *
 * @return pointer to opaque HTTP request data structure (@c NULL if failed)
 */
struct sipe_http_request *sipe_http_request_post(struct sipe_core_private *sipe_private,
						 const gchar *uri,
						 const gchar *headers,
						 const gchar *body,
						 const gchar *content_type,
						 sipe_http_response_callback *callback,
						 gpointer callback_data);

/**
 * HTTP request is ready to be sent
 *
 * @param request pointer to opaque HTTP request data structure
 */
void sipe_http_request_ready(struct sipe_http_request *request);

/**
 * Cancel pending HTTP request
 *
 * @param request pointer to opaque HTTP request data structure
 */
void sipe_http_request_cancel(struct sipe_http_request *request);

/**
 * Assign request to HTTP session
 *
 * @param request pointer to opaque HTTP request data structure
 * @param session pointer to opaque HTTP session data structure
 */
void sipe_http_request_session(struct sipe_http_request *request,
			       struct sipe_http_session *session);

/**
 * Allow redirection of HTTP request
 *
 * @param request pointer to opaque HTTP request data structure
 */
void sipe_http_request_allow_redirect(struct sipe_http_request *request);

/**
 * Provide authentication information for HTTP request
 *
 * @param request  pointer to opaque HTTP request data structure
 * @param domain   domain name (MUST stay valid for duration of request!)
 * @param user     user name   (MUST stay valid for duration of request!)
 * @param password Password    (MUST stay valid for duration of request!)
 */
void sipe_http_request_authentication(struct sipe_http_request *request,
				      const gchar *domain,
				      const gchar *user,
				      const gchar *password);
