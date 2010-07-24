/**
 * @file sipe-backend.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 * SIPE Core -> Backend API - functions called by SIPE core code
 *
 ***************** !!! IMPORTANT NOTE FOR BACKEND CODERS !!! *****************
 *
 *            The SIPE core assumes atomicity and is *NOT* thread-safe.
 *
 * It *does not* protect any of its data structures or code paths with locks!
 *
 * In no circumstances it must be possible that a sipe_core_xxx() function can
 * be entered through another thread while the first thread has entered the
 * backend specific code through a sipe_backend_xxx() function.
 *
 ***************** !!! IMPORTANT NOTE FOR BACKEND CODERS !!! *****************
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct sipe_backend_session;
struct sipe_core_public;
struct sipe_transport_connection;
struct sipe_file_transfer;
struct sipe_media_call;
struct sipe_media;

/** MISC. STUFF **************************************************************/
/**
 * Get the version of the backend suitable for e.g. UserAgent
 *
 * @return backend version string. Will be g_free()'d.by the core.
 */
gchar *sipe_backend_version(void);

/** DEBUGGING ****************************************************************/

typedef enum {
	SIPE_DEBUG_LEVEL_INFO,
	SIPE_DEBUG_LEVEL_WARNING,
	SIPE_DEBUG_LEVEL_ERROR,
	SIPE_DEBUG_LEVEL_FATAL,
}  sipe_debug_level;

/**
 * Output debug information without formatting
 *
 * Shouldn't be used directly. Instead use SIPE_DEBUG_xxx() macros
 *
 * @param level  debug level
 * @param msg    debug message "\n" will be automatically appended.
 */
void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg);

/**
 * Output debug information
 *
 * Shouldn't be used directly. Instead use SIPE_DEBUG_xxx() macros
 *
 * @param level  debug level
 * @param format format string. "\n" will be automatically appended.
 */
void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...) G_GNUC_PRINTF(2, 3);

/* Convenience macros */
#define SIPE_DEBUG_INFO(fmt, ...)        sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    fmt, __VA_ARGS__)
#define SIPE_DEBUG_INFO_NOFORMAT(msg)    sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_INFO,    msg)
#define SIPE_DEBUG_WARNING(fmt, ...)     sipe_backend_debug(SIPE_DEBUG_LEVEL_WARNING, fmt, __VA_ARGS__)
#define SIPE_DEBUG_WARNING_NOFORMAT(msg) sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_WARNING, msg)
#define SIPE_DEBUG_ERROR(fmt, ...)       sipe_backend_debug(SIPE_DEBUG_LEVEL_ERROR,   fmt, __VA_ARGS__)
#define SIPE_DEBUG_ERROR_NOFORMAT(msg)   sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_ERROR,   msg)
#define SIPE_DEBUG_FATAL(fmt, ...)       sipe_backend_debug(SIPE_DEBUG_LEVEL_FATAL,   fmt, __VA_ARGS__)
#define SIPE_DEBUG_FATAL_NOFORMAT(msg)   sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_FATAL,   msg)

/**
 * Check backend debugging status
 *
 * @return TRUE if debugging is enabled
 */
gboolean sipe_backend_debug_enabled(void);

/** CHAT *********************************************************************/

//void sipe_backend_chat_(struct sipe_backend_session *backend_session, );
void sipe_backend_chat_add(struct sipe_backend_session *backend_session,
			   const gchar *uri,
			   gboolean is_new);
void sipe_backend_chat_close(struct sipe_backend_session *backend_session);
struct sipe_backend_session *sipe_backend_chat_create(struct sipe_core_public *sipe_public,
						      int id,
						      const gchar *title,
						      const gchar *nick,
						      gboolean rejoin);
gboolean sipe_backend_chat_find(struct sipe_backend_session *backend_session,
				const gchar *uri);
gboolean sipe_backend_chat_is_operator(struct sipe_backend_session *backend_session,
				       const gchar *uri);
void sipe_backend_chat_message(struct sipe_core_public *sipe_public,
			       int id,
			       const gchar *from,
			       const gchar *html);
void sipe_backend_chat_operator(struct sipe_backend_session *backend_session,
				const gchar *uri);
void sipe_backend_chat_rejoin_all(struct sipe_core_public *sipe_public);
void sipe_backend_chat_remove(struct sipe_backend_session *backend_session,
			      const gchar *uri);
void sipe_backend_chat_topic(struct sipe_backend_session *backend_session,
			      const gchar *topic);

/** CONNECTION ***************************************************************/

void sipe_backend_connection_completed(struct sipe_core_public *sipe_public);

typedef enum {
  SIPE_CONNECTION_ERROR_NETWORK = 0,
  SIPE_CONNECTION_ERROR_INVALID_USERNAME,
  SIPE_CONNECTION_ERROR_INVALID_SETTINGS,
  SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
  SIPE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
  SIPE_CONNECTION_ERROR_LAST
} sipe_connection_error;
void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg);

gboolean sipe_backend_connection_is_disconnecting(struct sipe_core_public *sipe_public);
gboolean sipe_backend_connection_is_valid(struct sipe_core_public *sipe_public);

/** DNS QUERY ****************************************************************/

void sipe_backend_dns_query(struct sipe_core_public *sipe_public,
			    const gchar *protocol,
			    const gchar *transport,
			    const gchar *domain);

/** FILE TRANSFER ************************************************************/
void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const gchar *errmsg);
const gchar *sipe_backend_ft_get_error(struct sipe_file_transfer *ft);
void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft);

/**
 * Try to read up to @c size bytes from file transfer connection
 *
 * @param backend_ft backend private file transfer data.
 * @param data       buffer to read data into.
 * @param size       buffer size in bytes.
 *
 * @return number of bytes read or negative on failure.
 *         EAGAIN should return 0 bytes read.
 */
gssize sipe_backend_ft_read(struct sipe_file_transfer *ft,
			    guchar *data,
			    gsize size);

/**
 * Try to write up to @c size bytes to file transfer connection
 *
 * @param backend_ft backend private file transfer data.
 * @param data       data to write
 * @param size       buffer size in bytes.
 *
 * @return number of bytes read or negative on failure.
 *         EAGAIN should return 0 bytes written.
 */
gssize sipe_backend_ft_write(struct sipe_file_transfer *ft,
			     const guchar *data,
			     gsize size);


void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft);
void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft);

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size);
gboolean sipe_backend_ft_incoming_accept(struct sipe_file_transfer *ft,
					 const gchar *ip,
					 unsigned short port_min,
					 unsigned short port_max);

/** IM ***********************************************************************/

void sipe_backend_im_message(struct sipe_core_public *sipe_public,
			     const gchar *from,
			     const gchar *html);

/** MARKUP *******************************************************************/

gchar *sipe_backend_markup_css_property(const gchar *style,
					const gchar *option);
gchar *sipe_backend_markup_strip_html(const gchar *html);

/** MEDIA ********************************************************************/

typedef enum {
	SIPE_CANDIDATE_TYPE_HOST,
	SIPE_CANDIDATE_TYPE_RELAY,
	SIPE_CANDIDATE_TYPE_SRFLX,
	SIPE_CANDIDATE_TYPE_PRFLX
} SipeCandidateType;

typedef enum {
	SIPE_COMPONENT_NONE = 0,
	SIPE_COMPONENT_RTP  = 1,
	SIPE_COMPONENT_RTCP = 2
} SipeComponentType;

typedef enum {
	SIPE_MEDIA_AUDIO,
	SIPE_MEDIA_VIDEO
} SipeMediaType;

typedef enum {
	SIPE_NETWORK_PROTOCOL_TCP,
	SIPE_NETWORK_PROTOCOL_UDP
} SipeNetworkProtocol;

struct sipe_media_call;
struct sipe_backend_media;
struct sipe_backend_codec;
struct sipe_backend_candidate;
struct sipe_backend_stream;

struct sipe_media_call {
	struct sipe_backend_media *backend_private;

	void (*candidates_prepared_cb)(struct sipe_media_call *);
	void (*media_connected_cb)();
	void (*call_accept_cb)(struct sipe_media_call *, gboolean local);
	void (*call_reject_cb)(struct sipe_media_call *, gboolean local);
	void (*call_hold_cb)  (struct sipe_media_call *, gboolean local,
			       gboolean state);
	void (*call_hangup_cb)(struct sipe_media_call *, gboolean local);

	gboolean local_on_hold;
	gboolean remote_on_hold;
};

/* Media handling */
struct sipe_backend_media *sipe_backend_media_new(struct sipe_core_public *sipe_public,
						  struct sipe_media_call *call,
						  const gchar *participant,
						  gboolean initiator);
void sipe_backend_media_free(struct sipe_backend_media *media);
struct sipe_backend_stream *sipe_backend_media_add_stream(struct sipe_backend_media *media,
							  const gchar *participant,
							  SipeMediaType type, gboolean use_nice,
							  gboolean initiator);
void sipe_backend_media_remove_stream(struct sipe_backend_media *media,
				      struct sipe_backend_stream *stream);
void sipe_backend_media_add_remote_candidates(struct sipe_backend_media *media,
					      struct sipe_backend_stream *stream,
					      GList *candidates);
gboolean sipe_backend_media_is_initiator(struct sipe_backend_media *media,
					 struct sipe_backend_stream *stream);
gboolean sipe_backend_media_accepted(struct sipe_backend_media *media);
GList *sipe_backend_media_get_active_local_candidates(struct sipe_backend_media *media,
						      struct sipe_backend_stream *stream);
GList *sipe_backend_media_get_active_remote_candidates(struct sipe_backend_media *media,
						       struct sipe_backend_stream *stream);

/* Codec handling */
struct sipe_backend_codec *sipe_backend_codec_new(int id,
						  const char *name,
						  SipeMediaType type, guint clock_rate);
void sipe_backend_codec_free(struct sipe_backend_codec *codec);
int sipe_backend_codec_get_id(struct sipe_backend_codec *codec);
/**
 * @return codec name. Will be g_free'd() by the core.
 */
gchar *sipe_backend_codec_get_name(struct sipe_backend_codec *codec);
guint sipe_backend_codec_get_clock_rate(struct sipe_backend_codec *codec);
void sipe_backend_codec_add_optional_parameter(struct sipe_backend_codec *codec,
					       const gchar *name,
					       const gchar *value);
GList *sipe_backend_codec_get_optional_parameters(struct sipe_backend_codec *codec);
gboolean sipe_backend_set_remote_codecs(struct sipe_backend_media *media,
					struct sipe_backend_stream *stream,
					GList *codecs);
GList* sipe_backend_get_local_codecs(struct sipe_media_call *call,
				     struct sipe_backend_stream *stream);

/* Candidate handling */
struct sipe_backend_candidate * sipe_backend_candidate_new(const gchar *foundation,
							   SipeComponentType component,
							   SipeCandidateType type,
							   SipeNetworkProtocol proto,
							   const gchar *ip, guint port);
void sipe_backend_candidate_free(struct sipe_backend_candidate *candidate);
/**
 * @return user name. Will be g_free'd() by the core.
 */
gchar *sipe_backend_candidate_get_username(struct sipe_backend_candidate *candidate);
/**
 * @return password. Will be g_free'd() by the core.
 */
gchar *sipe_backend_candidate_get_password(struct sipe_backend_candidate *candidate);
/**
 * @return foundation. Will be g_free'd() by the core.
 */
gchar *sipe_backend_candidate_get_foundation(struct sipe_backend_candidate *candidate);
/**
 * @return IP address string. Will be g_free'd() by the core.
 */
gchar *sipe_backend_candidate_get_ip(struct sipe_backend_candidate *candidate);
guint sipe_backend_candidate_get_port(struct sipe_backend_candidate *candidate);
/**
 * @return IP address string. Will be g_free'd() by the core.
 */
gchar *sipe_backend_candidate_get_base_ip(struct sipe_backend_candidate *candidate);
guint sipe_backend_candidate_get_base_port(struct sipe_backend_candidate *candidate);
guint32 sipe_backend_candidate_get_priority(struct sipe_backend_candidate *candidate);
void sipe_backend_candidate_set_priority(struct sipe_backend_candidate *candidate, guint32 priority);
SipeComponentType sipe_backend_candidate_get_component_type(struct sipe_backend_candidate *candidate);
SipeCandidateType sipe_backend_candidate_get_type(struct sipe_backend_candidate *candidate);
SipeNetworkProtocol sipe_backend_candidate_get_protocol(struct sipe_backend_candidate *candidate);
void sipe_backend_candidate_set_username_and_pwd(struct sipe_backend_candidate *candidate,
						 const gchar *username,
						 const gchar *password);
GList* sipe_backend_get_local_candidates(struct sipe_backend_media *media,
					 struct sipe_backend_stream *stream);
void sipe_backend_media_hold(struct sipe_backend_media *media, gboolean local);
void sipe_backend_media_unhold(struct sipe_backend_media *media, gboolean local);
void sipe_backend_media_hangup(struct sipe_backend_media *media, gboolean local);
void sipe_backend_media_reject(struct sipe_backend_media *media, gboolean local);

/** NETWORK ******************************************************************/

const gchar *sipe_backend_network_ip_address(void);

/** SCHEDULE *****************************************************************/

gpointer sipe_backend_schedule_seconds(struct sipe_core_public *sipe_public,
				       guint timeout,
				       gpointer data);
gpointer sipe_backend_schedule_mseconds(struct sipe_core_public *sipe_public,
					guint timeout,
					gpointer data);
void sipe_backend_schedule_cancel(struct sipe_core_public *sipe_public,
				  gpointer data);

/** SETTINGS *****************************************************************/

typedef enum {
  SIPE_SETTING_EMAIL_URL = 0,
  SIPE_SETTING_EMAIL_LOGIN,
  SIPE_SETTING_EMAIL_PASSWORD,
  SIPE_SETTING_USER_AGENT,
  SIPE_SETTING_LAST
} sipe_setting;
const gchar *sipe_backend_setting(struct sipe_core_public *sipe_public,
				  sipe_setting type);

/** TRANSPORT ****************************************************************/

typedef void transport_connected_cb(struct sipe_transport_connection *conn);
typedef void transport_input_cb(struct sipe_transport_connection *conn);
typedef void transport_error_cb(struct sipe_transport_connection *conn,
				const gchar *msg);

typedef struct {
	guint type;
	const gchar *server_name;
	guint server_port;
	gpointer user_data;
	transport_connected_cb *connected;
	transport_input_cb *input;
	transport_error_cb *error;
} sipe_connect_setup;
struct sipe_transport_connection *sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
								 const sipe_connect_setup *setup);
void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn);
void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer);
void sipe_backend_transport_flush(struct sipe_transport_connection *conn);

/** USER *********************************************************************/

void sipe_backend_user_feedback_typing(struct sipe_core_public *sipe_public,
				       const gchar *from);
void sipe_backend_user_feedback_typing_stop(struct sipe_core_public *sipe_public,
					    const gchar *from);

/** NOTIFICATIONS *************************************************************/

void sipe_backend_notify_error(const gchar *title, const gchar *msg);


#ifdef __cplusplus
}
#endif

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
