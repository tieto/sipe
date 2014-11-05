/**
 * @file sipe-backend.h
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
struct sipe_backend_chat_session;
struct sipe_chat_session;
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
	SIPE_LOG_LEVEL_INFO,
	SIPE_LOG_LEVEL_WARNING,
	SIPE_LOG_LEVEL_ERROR,
	SIPE_DEBUG_LEVEL_INFO,
	SIPE_DEBUG_LEVEL_WARNING,
	SIPE_DEBUG_LEVEL_ERROR,
}  sipe_debug_level;
#define SIPE_DEBUG_LEVEL_LOWEST SIPE_DEBUG_LEVEL_INFO

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
#define SIPE_LOG_INFO(fmt, ...)          sipe_backend_debug(SIPE_LOG_LEVEL_INFO,    fmt, __VA_ARGS__)
#define SIPE_LOG_INFO_NOFORMAT(msg)      sipe_backend_debug_literal(SIPE_LOG_LEVEL_INFO,    msg)
#define SIPE_LOG_WARNING(fmt, ...)       sipe_backend_debug(SIPE_LOG_LEVEL_WARNING, fmt, __VA_ARGS__)
#define SIPE_LOG_WARNING_NOFORMAT(msg)   sipe_backend_debug_literal(SIPE_LOG_LEVEL_WARNING, msg)
#define SIPE_LOG_ERROR(fmt, ...)         sipe_backend_debug(SIPE_LOG_LEVEL_ERROR,   fmt, __VA_ARGS__)
#define SIPE_LOG_ERROR_NOFORMAT(msg)     sipe_backend_debug_literal(SIPE_LOG_LEVEL_ERROR,   msg)
#define SIPE_DEBUG_INFO(fmt, ...)        sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    fmt, __VA_ARGS__)
#define SIPE_DEBUG_INFO_NOFORMAT(msg)    sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_INFO,    msg)
#define SIPE_DEBUG_WARNING(fmt, ...)     sipe_backend_debug(SIPE_DEBUG_LEVEL_WARNING, fmt, __VA_ARGS__)
#define SIPE_DEBUG_WARNING_NOFORMAT(msg) sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_WARNING, msg)
#define SIPE_DEBUG_ERROR(fmt, ...)       sipe_backend_debug(SIPE_DEBUG_LEVEL_ERROR,   fmt, __VA_ARGS__)
#define SIPE_DEBUG_ERROR_NOFORMAT(msg)   sipe_backend_debug_literal(SIPE_DEBUG_LEVEL_ERROR,   msg)

/**
 * Check backend debugging status
 *
 * @return TRUE if debugging is enabled
 */
gboolean sipe_backend_debug_enabled(void);

/** CHAT *********************************************************************/

void sipe_backend_chat_session_destroy(struct sipe_backend_chat_session *session);
void sipe_backend_chat_add(struct sipe_backend_chat_session *backend_session,
			   const gchar *uri,
			   gboolean is_new);
void sipe_backend_chat_close(struct sipe_backend_chat_session *backend_session);

/**
 * Joined a new chat
 */
struct sipe_backend_chat_session *sipe_backend_chat_create(struct sipe_core_public *sipe_public,
							   struct sipe_chat_session *session,
							   const gchar *title,
							   const gchar *nick);
gboolean sipe_backend_chat_find(struct sipe_backend_chat_session *backend_session,
				const gchar *uri);
gboolean sipe_backend_chat_is_operator(struct sipe_backend_chat_session *backend_session,
				       const gchar *uri);
void sipe_backend_chat_message(struct sipe_core_public *sipe_public,
			       struct sipe_backend_chat_session *backend_session,
			       const gchar *from,
			       time_t when,
			       const gchar *html);
void sipe_backend_chat_operator(struct sipe_backend_chat_session *backend_session,
				const gchar *uri);

/**
 * Rejoin an existing chat window after connection re-establishment
 */
void sipe_backend_chat_rejoin(struct sipe_core_public *sipe_public,
			      struct sipe_backend_chat_session *backend_session,
			      const gchar *nick,
			      const gchar *title);

/**
 * Core has completed connection re-establishment.
 * Should call sipe_core_chat_rejoin() for existing chats.
 */
void sipe_backend_chat_rejoin_all(struct sipe_core_public *sipe_public);
void sipe_backend_chat_remove(struct sipe_backend_chat_session *backend_session,
			      const gchar *uri);

/**
 * Move chat window to the front. Will be called when
 * a user tries to join an already joined chat again.
 */
void sipe_backend_chat_show(struct sipe_backend_chat_session *backend_session);
void sipe_backend_chat_topic(struct sipe_backend_chat_session *backend_session,
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

typedef void (*sipe_dns_resolved_cb)(gpointer data, const gchar *hostname, guint port);

struct sipe_dns_query *sipe_backend_dns_query_srv(struct sipe_core_public *sipe_public,
						  const gchar *protocol,
						  const gchar *transport,
						  const gchar *domain,
						  sipe_dns_resolved_cb callback,
						  gpointer data);

struct sipe_dns_query *sipe_backend_dns_query_a(struct sipe_core_public *sipe_public,
						const gchar *hostname,
						guint port,
						sipe_dns_resolved_cb callback,
						gpointer data);

void sipe_backend_dns_query_cancel(struct sipe_dns_query *query);

/** FILE TRANSFER ************************************************************/

struct sipe_backend_fd;

void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const gchar *errmsg);
const gchar *sipe_backend_ft_get_error(struct sipe_file_transfer *ft);
void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft);

/**
 * Try to read up to @c size bytes from file transfer connection
 *
 * @param ft   file transfer data.
 * @param data buffer to read data into.
 * @param size buffer size in bytes.
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
 * @param ft   file transfer data.
 * @param data data to write
 * @param size buffer size in bytes.
 *
 * @return number of bytes read or negative on failure.
 *         EAGAIN should return 0 bytes written.
 */
gssize sipe_backend_ft_write(struct sipe_file_transfer *ft,
			     const guchar *data,
			     gsize size);

void sipe_backend_ft_set_completed(struct sipe_file_transfer *ft);

void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft);
void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft);

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size);
/**
 * Allocates and initializes backend file transfer structure for sending a file.
 *
 * @param sipe_public (in) the handle representing the protocol instance
 * @param ft (in) sipe core file transfer structure
 * @param who (in) SIP URI of the file recipient
 * @param file_name (in) filesystem path of the file being sent
 */
void sipe_backend_ft_outgoing(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name);
/**
 * Begins file transfer with remote peer.
 *
 * You can provide either opened file descriptor to use for read/write operations
 * or ip address and port where the backend should connect.
 *
 * @param ft   file transfer data
 * @param fd   opaque file descriptor pointer or NULL if ip and port are used
 * @param ip   ip address to connect of NULL when file descriptor is used
 * @param port port to connect or 0 when file descriptor is used
 */
void sipe_backend_ft_start(struct sipe_file_transfer *ft,
			   struct sipe_backend_fd *fd,
			   const char* ip, unsigned port);

/**
 * Check whether file transfer is incoming or outgoing
 *
 * @param ft file transfer data
 * @return @c TRUE if @c ft is incoming, otherwise @c FALSE
 */
gboolean sipe_backend_ft_is_incoming(struct sipe_file_transfer *ft);

/** GROUP CHAT ***************************************************************/

#define SIPE_GROUPCHAT_ROOM_FILEPOST 0x00000001
#define SIPE_GROUPCHAT_ROOM_INVITE   0x00000002
#define SIPE_GROUPCHAT_ROOM_LOGGED   0x00000004
#define SIPE_GROUPCHAT_ROOM_PRIVATE  0x00000008

/**
 * Add a room found through room query
 *
 * @param uri         room URI
 * @param name        human readable name for room
 * @param description room description
 * @param users       number of users in the room
 * @param flags       SIPE_GROUPCHAT_ROOM_* flags
 */
void sipe_backend_groupchat_room_add(struct sipe_core_public *sipe_public,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *description,
				     guint users,
				     guint32 flags);

/**
 * Terminate room query
 */
void sipe_backend_groupchat_room_terminate(struct sipe_core_public *sipe_public);

/** IM ***********************************************************************/

void sipe_backend_im_message(struct sipe_core_public *sipe_public,
			     const gchar *from,
			     const gchar *html);
void sipe_backend_im_topic(struct sipe_core_public *sipe_public,
			   const gchar *with,
			   const gchar *topic);

/** MARKUP *******************************************************************/

gchar *sipe_backend_markup_css_property(const gchar *style,
					const gchar *option);
gchar *sipe_backend_markup_strip_html(const gchar *html);

/** MEDIA ********************************************************************/

typedef enum {
	/* This client is the one who invites other participant to the call. */
	SIPE_MEDIA_CALL_INITIATOR = 1,
	/* Don't show any user interface elements for the call. */
	SIPE_MEDIA_CALL_NO_UI = 2
} SipeMediaCallFlags;

typedef enum {
	SIPE_ICE_NO_ICE,
	SIPE_ICE_DRAFT_6,
	SIPE_ICE_RFC_5245
} SipeIceVersion;

typedef enum {
	SIPE_CANDIDATE_TYPE_ANY,
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
	SIPE_MEDIA_VIDEO,
	SIPE_MEDIA_APPLICATION
} SipeMediaType;

typedef enum {
	SIPE_NETWORK_PROTOCOL_UDP,
	SIPE_NETWORK_PROTOCOL_TCP_ACTIVE,
	SIPE_NETWORK_PROTOCOL_TCP_PASSIVE,
	SIPE_NETWORK_PROTOCOL_TCP_SO,
} SipeNetworkProtocol;

typedef enum {
	SIPE_ENCRYPTION_POLICY_REJECTED,
	SIPE_ENCRYPTION_POLICY_OPTIONAL,
	SIPE_ENCRYPTION_POLICY_REQUIRED,
	SIPE_ENCRYPTION_POLICY_OBEY_SERVER
} SipeEncryptionPolicy;

struct sipe_media_call;
struct sipe_backend_media;
struct sipe_backend_codec;
struct sipe_backend_candidate;
struct sipe_backend_media_stream;
struct sipe_backend_media_relays;

struct ssrc_range {
	guint32 begin;
	guint32 end;
};

struct sipe_media_stream {
	struct sipe_backend_media_stream *backend_private;

	struct sipe_media_call *call;
	gchar *id;
	struct ssrc_range *ssrc_range;

	void (*candidate_pairs_established_cb)(struct sipe_media_stream *);
	void (*read_cb)(struct sipe_media_stream *);
	void (*writable_cb)(struct sipe_media_stream *);
	void (*mute_cb)(struct sipe_media_stream *, gboolean is_muted);
};

struct sipe_media_call {
	struct sipe_backend_media *backend_private;

	gchar *with;

	void (*stream_initialized_cb)(struct sipe_media_call *,
				      struct sipe_media_stream *);
	void (*media_end_cb)(struct sipe_media_call *);
	void (*call_accept_cb)(struct sipe_media_call *, gboolean local);
	void (*call_reject_cb)(struct sipe_media_call *, gboolean local);
	void (*call_hold_cb)  (struct sipe_media_call *, gboolean local,
			       gboolean state);
	void (*call_hangup_cb)(struct sipe_media_call *, gboolean local);
	void (*error_cb)(struct sipe_media_call *, gchar *message);
};

struct sipe_media_relay {
	gchar		      *hostname;
	guint		       udp_port;
	guint		       tcp_port;
	struct sipe_dns_query *dns_query;
};

/* Media handling */
struct sipe_backend_media *sipe_backend_media_new(struct sipe_core_public *sipe_public,
						  struct sipe_media_call *call,
						  const gchar *participant,
						  SipeMediaCallFlags flags);
void sipe_backend_media_free(struct sipe_backend_media *media);

void sipe_backend_media_set_cname(struct sipe_backend_media *media, gchar *cname);

struct sipe_backend_media_relays * sipe_backend_media_relays_convert(GSList *media_relays,
								     gchar *username,
								     gchar *password);
void sipe_backend_media_relays_free(struct sipe_backend_media_relays *media_relays);

struct sipe_backend_media_stream *sipe_backend_media_add_stream(struct sipe_media_stream *stream,
							  SipeMediaType type,
							  SipeIceVersion ice_version,
							  gboolean initiator,
							  struct sipe_backend_media_relays *media_relays,
							  guint min_port, guint max_port);
void sipe_backend_media_add_remote_candidates(struct sipe_media_call *media,
					      struct sipe_media_stream *stream,
					      GList *candidates);
gboolean sipe_backend_media_is_initiator(struct sipe_media_call *media,
					 struct sipe_media_stream *stream);
gboolean sipe_backend_media_accepted(struct sipe_backend_media *media);
gboolean sipe_backend_stream_initialized(struct sipe_media_call *media,
					 struct sipe_media_stream *stream);
void sipe_backend_media_set_encryption_keys(struct sipe_media_call *media,
					    struct sipe_media_stream *stream,
					    const guchar *encryption_key,
					    const guchar *decryption_key);

/* Stream handling */
void sipe_backend_stream_hold(struct sipe_media_call *media,
			      struct sipe_media_stream *stream,
			      gboolean local);
void sipe_backend_stream_unhold(struct sipe_media_call *media,
				struct sipe_media_stream *stream,
				gboolean local);
gboolean sipe_backend_stream_is_held(struct sipe_media_stream *stream);

GList *sipe_backend_media_stream_get_active_local_candidates(struct sipe_media_stream *stream);
GList *sipe_backend_media_stream_get_active_remote_candidates(struct sipe_media_stream *stream);

gssize sipe_backend_media_stream_read(struct sipe_media_stream *stream,
				     guint8 *buffer, gsize len);
gssize sipe_backend_media_stream_write(struct sipe_media_stream *stream,
				       guint8 *buffer, gsize len);

void sipe_backend_media_stream_end(struct sipe_media_call *media,
				   struct sipe_media_stream *stream);
void sipe_backend_media_stream_free(struct sipe_backend_media_stream *stream);

/* Codec handling */
struct sipe_backend_codec *sipe_backend_codec_new(int id,
						  const char *name,
						  SipeMediaType type,
						  guint clock_rate,
						  guint channels);
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
gboolean sipe_backend_set_remote_codecs(struct sipe_media_call *media,
					struct sipe_media_stream *stream,
					GList *codecs);
GList* sipe_backend_get_local_codecs(struct sipe_media_call *media,
				     struct sipe_media_stream *stream);

/* Candidate handling */
struct sipe_backend_candidate * sipe_backend_candidate_new(const gchar *foundation,
							   SipeComponentType component,
							   SipeCandidateType type,
							   SipeNetworkProtocol proto,
							   const gchar *ip, guint port,
							   const gchar *username,
							   const gchar *password);
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
GList* sipe_backend_get_local_candidates(struct sipe_media_call *media,
					 struct sipe_media_stream *stream);
void sipe_backend_media_accept(struct sipe_backend_media *media, gboolean local);
void sipe_backend_media_hangup(struct sipe_backend_media *media, gboolean local);
void sipe_backend_media_reject(struct sipe_backend_media *media, gboolean local);

/** NETWORK ******************************************************************/

struct sipe_backend_listendata;

typedef void (*sipe_listen_start_cb)(unsigned short port, gpointer data);
typedef void (*sipe_client_connected_cb)(struct sipe_backend_fd *fd, gpointer data);

struct sipe_backend_listendata *
sipe_backend_network_listen_range(unsigned short port_min,
				  unsigned short port_max,
				  sipe_listen_start_cb listen_cb,
				  sipe_client_connected_cb connect_cb,
				  gpointer data);
void sipe_backend_network_listen_cancel(struct sipe_backend_listendata *ldata);

struct sipe_backend_fd * sipe_backend_fd_from_int(int fd);
gboolean sipe_backend_fd_is_valid(struct sipe_backend_fd *fd);
void sipe_backend_fd_free(struct sipe_backend_fd *fd);

/** NOTIFICATIONS *************************************************************/

void sipe_backend_notify_message_error(struct sipe_core_public *sipe_public,
				       struct sipe_backend_chat_session *backend_session,
				       const gchar *who,
				       const gchar *message);
void sipe_backend_notify_message_info(struct sipe_core_public *sipe_public,
				      struct sipe_backend_chat_session *backend_session,
				      const gchar *who,
				      const gchar *message);

/**
 * @param msg  error message. Maybe @NULL
 */
void sipe_backend_notify_error(struct sipe_core_public *sipe_public,
			       const gchar *title,
			       const gchar *msg);

/** SCHEDULE *****************************************************************/

gpointer sipe_backend_schedule_seconds(struct sipe_core_public *sipe_public,
				       guint timeout,
				       gpointer data);
gpointer sipe_backend_schedule_mseconds(struct sipe_core_public *sipe_public,
					guint timeout,
					gpointer data);
void sipe_backend_schedule_cancel(struct sipe_core_public *sipe_public,
				  gpointer data);

/** SEARCH *******************************************************************/

struct sipe_backend_search_results;
struct sipe_backend_search_token;

void sipe_backend_search_failed(struct sipe_core_public *sipe_public,
				struct sipe_backend_search_token *token,
				const gchar *msg);
struct sipe_backend_search_results *sipe_backend_search_results_start(struct sipe_core_public *sipe_public,
								      struct sipe_backend_search_token *token);
void sipe_backend_search_results_add(struct sipe_core_public *sipe_public,
				     struct sipe_backend_search_results *results,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *company,
				     const gchar *country,
				     const gchar *email);
void sipe_backend_search_results_finalize(struct sipe_core_public *sipe_public,
					  struct sipe_backend_search_results *results,
					  const gchar *description,
					  gboolean more);

/** SETTINGS *****************************************************************/

typedef enum {
  SIPE_SETTING_EMAIL_URL = 0,
  SIPE_SETTING_EMAIL_LOGIN,
  SIPE_SETTING_EMAIL_PASSWORD,
  SIPE_SETTING_GROUPCHAT_USER,
  SIPE_SETTING_RDP_CLIENT,
  SIPE_SETTING_USER_AGENT,
  SIPE_SETTING_LAST
} sipe_setting;
const gchar *sipe_backend_setting(struct sipe_core_public *sipe_public,
				  sipe_setting type);

/** STATUS *******************************************************************/

guint sipe_backend_status(struct sipe_core_public *sipe_public);
gboolean sipe_backend_status_changed(struct sipe_core_public *sipe_public,
				     guint activity,
				     const gchar *message);

/**
 * Update user client with new status and note received from server
 *
 * NOTE: this must *NOT* trigger a call to @c sipe_core_status_set()!
 *
 * @param sipe_public   The handle representing the protocol instance
 * @param activity      New activity
 * @param message       New note text
 */
void sipe_backend_status_and_note(struct sipe_core_public *sipe_public,
				  guint activity,
				  const gchar *message);

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
gchar *sipe_backend_transport_ip_address(struct sipe_transport_connection *conn);
void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer);
void sipe_backend_transport_flush(struct sipe_transport_connection *conn);

/** USER *********************************************************************/

void sipe_backend_user_feedback_typing(struct sipe_core_public *sipe_public,
				       const gchar *from);
void sipe_backend_user_feedback_typing_stop(struct sipe_core_public *sipe_public,
					    const gchar *from);

/**
 * Present a query that is to be accepted or declined by the user
 *
 * @param sipe_public   The handle representing the protocol instance
 * @param message       Text of the query to be shown to user
 * @param accept_label  Label to be displayed on UI control that accepts query
 * @param decline_label Label to be displayed on UI control that declines query
 * @param key           Opaque handle uniquely identifying the query. Backend
 *                      should store it for the case SIPE core requests the
 *                      query to be closed prematurely.
 */
void sipe_backend_user_ask(struct sipe_core_public *sipe_public,
			   const gchar *message,
			   const gchar *accept_label,
			   const gchar *decline_label,
			   gpointer key);

/**
 * Closes the pending user query
 *
 * @param key Opaque handle uniquely identifying the query.
 */
void sipe_backend_user_close_ask(gpointer key);

/** BUDDIES ******************************************************************/

/*
 * sipe_backend_buddy_get/set_string(): properties a buddy can have
 * sipe_backend_buddy_info_add():       mapped, e.g. to a string label
 */
typedef enum
{
	SIPE_BUDDY_INFO_DISPLAY_NAME = 0,
	SIPE_BUDDY_INFO_JOB_TITLE,
	SIPE_BUDDY_INFO_CITY,
	SIPE_BUDDY_INFO_STATE,
	SIPE_BUDDY_INFO_OFFICE,
	SIPE_BUDDY_INFO_DEPARTMENT,
	SIPE_BUDDY_INFO_COUNTRY,
	SIPE_BUDDY_INFO_WORK_PHONE,
	SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY,
	SIPE_BUDDY_INFO_COMPANY,
	SIPE_BUDDY_INFO_EMAIL,
	SIPE_BUDDY_INFO_SITE,
	SIPE_BUDDY_INFO_ZIPCODE,
	SIPE_BUDDY_INFO_STREET,
	SIPE_BUDDY_INFO_MOBILE_PHONE,
	SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY,
	SIPE_BUDDY_INFO_HOME_PHONE,
	SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY,
	SIPE_BUDDY_INFO_OTHER_PHONE,
	SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY,
	SIPE_BUDDY_INFO_CUSTOM1_PHONE,
	SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY,
	SIPE_BUDDY_INFO_ALIAS,  /* only for sipe_backend_buddy_info_add() */
	SIPE_BUDDY_INFO_DEVICE, /* only for sipe_backend_buddy_info_add() */
} sipe_buddy_info_fields;

/* Opaque token */
typedef void* sipe_backend_buddy;

/**
 * Find a buddy in the given group of the buddy list, or anywhere on the
 * list if @group_name is empty
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param buddy_name The name of the buddy
 * @param group_name The name of the group to look in, or NULL for any group
 * @return opaque handle to the buddy, or NULL if no buddy found
 */
sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *buddy_name,
					   const gchar *group_name);

/*
 * Find all named buddies in the given group of the buddy list, or anywhere on the
 * list if @group_name is empty; or all buddies if @name is empty
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param name The name of the buddy
 * @param group_name The name of the group to look in, or NULL for any group
 * @return GSList of opaque handles to the buddies
 */
GSList* sipe_backend_buddy_find_all(struct sipe_core_public *sipe_public,
				    const gchar *buddy_name,
				    const gchar *group_name);

/**
 * Gets the name of a contact.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @return The name. Must be freed.
 */
gchar* sipe_backend_buddy_get_name(struct sipe_core_public *sipe_public,
				   const sipe_backend_buddy who);

/**
 * Gets the alias for a contact.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @return The alias. Must be gfree'd.
 */
gchar* sipe_backend_buddy_get_alias(struct sipe_core_public *sipe_public,
				    const sipe_backend_buddy who);

/**
 * Gets the server alias for a contact.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @return The alias. Must be freed.
 */
gchar* sipe_backend_buddy_get_server_alias(struct sipe_core_public *sipe_public,
					   const sipe_backend_buddy who);

/**
 * Gets the local alias for a contact
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param uri         the budyy name
 *
 * @return the alias. Must be @g_free()'d.
 */
gchar *sipe_backend_buddy_get_local_alias(struct sipe_core_public *sipe_public,
					  const sipe_backend_buddy who);

/**
 * Gets the name of the group a contact belongs to.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @return The name. Must be freed.
 */
gchar* sipe_backend_buddy_get_group_name(struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who);

/**
 * Called to retrieve a buddy-specific setting.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param buddy The handle representing the buddy
 * @param key The name of the setting
 * @return The value of the setting. Must be freed.
 */
gchar* sipe_backend_buddy_get_string(struct sipe_core_public *sipe_public,
				     sipe_backend_buddy buddy,
				     const sipe_buddy_info_fields key);

/**
 * Called to set a buddy-specific setting.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param buddy The handle representing the buddy
 * @param key The name of the setting
 * @param val The value to set
 */
void sipe_backend_buddy_set_string(struct sipe_core_public *sipe_public,
				   sipe_backend_buddy buddy,
				   const sipe_buddy_info_fields key,
				   const gchar *val);

/**
 * Called after one ore more buddy-specific settings have been updated.
 *
 * Can be used by the backend to trigger an UI update event
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param uri         SIP URI of the contact
 */
void sipe_backend_buddy_refresh_properties(struct sipe_core_public *sipe_public,
					   const gchar *uri);

/**
 * Get the status token for a contact
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param uri         SIP URI of the contact
 *
 * @return activity
 */
guint sipe_backend_buddy_get_status(struct sipe_core_public *sipe_public,
				    const gchar *uri);

/**
 * Sets the alias for a contact.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @param alias The location where the alias will be put
 * case. FALSE if the buddy was not found. The value of alias will not be changed.
 */
void sipe_backend_buddy_set_alias(struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias);

/**
 * Sets the server alias for a contact.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 * @param alias The server alias of the contact
 */
void sipe_backend_buddy_set_server_alias(struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who,
					 const gchar *alias);

/**
 * Start processing buddy list
 *
 * Will be called every time we receive a buddy list in roaming contacts
 *
 * @param sipe_public The handle representing the protocol instance making the call
 */
void sipe_backend_buddy_list_processing_start(struct sipe_core_public *sipe_public);

/**
 * Finished processing buddy list
 *
 * Will be called every time we receive a buddy list in roaming contacts
 *
 * @param sipe_public The handle representing the protocol instance making the call
 */
void sipe_backend_buddy_list_processing_finish(struct sipe_core_public *sipe_public);

/**
 * Add a contact to the buddy list
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param name The name of the contact
 * @param alias The alias of the contact
 * @param groupname The name of the group to add this contact to
 * @return A handle to the newly created buddy
 */
sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *groupname);

/**
 * Remove a contact from the buddy list
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The opaque handle to the contact as found by find_buddy
 */
void sipe_backend_buddy_remove(struct sipe_core_public *sipe_public,
			       const sipe_backend_buddy who);

/**
 * Notifies the user that a remote user has wants to add the local user to his
 * or her buddy list and requires authorization to do so.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The name of the user that added this account
 * @param alias The optional alias of the remote user
 * @param on_list True if the user is already in our list
 * @param auth_cb The callback called when the local user accepts
 * @param deny_cb The callback called when the local user rejects
 * @param data Data to be passed back to the above callbacks
 */
typedef void (*sipe_backend_buddy_request_authorization_cb)(void *);

void sipe_backend_buddy_request_add(struct sipe_core_public *sipe_public,
				    const gchar *who,
				    const gchar *alias);

void sipe_backend_buddy_request_authorization(struct sipe_core_public *sipe_public,
					      const gchar *who,
					      const gchar *alias,
					      gboolean on_list,
					      sipe_backend_buddy_request_authorization_cb auth_cb,
					      sipe_backend_buddy_request_authorization_cb deny_cb,
					      gpointer data);

gboolean sipe_backend_buddy_is_blocked(struct sipe_core_public *sipe_public,
				       const gchar *who);

void sipe_backend_buddy_set_blocked_status(struct sipe_core_public *sipe_public,
					   const gchar *who,
					   gboolean blocked);

void sipe_backend_buddy_set_status(struct sipe_core_public *sipe_public,
				   const gchar *who,
				   guint activity);

/**
 * Checks whether backend has a capability to use buddy photos. If this function
 * returns @c FALSE, SIPE core will not attempt to download the photos from
 * server to save bandwidth.
 *
 * @return @c TRUE if backend is photo capable, otherwise @FALSE
 */
gboolean sipe_backend_uses_photo(void);

/**
 * Gives backend a photo image associated with a SIP URI. Backend has ownership
 * of the data and must free it when not needed.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The name of the user whose photo is being set
 * @param image_data The photo image data, must be g_free()'d by backend
 * @param image_len Size of the image in Bytes
 * @param photo_hash A data checksum provided by the server
 */
void sipe_backend_buddy_set_photo(struct sipe_core_public *sipe_public,
				  const gchar *who,
				  gpointer image_data,
				  gsize image_len,
				  const gchar *photo_hash);

/**
 * Retrieves a photo hash stored together with image data by
 * @c sipe_backend_buddy_set_photo. Value is used by the core to detect photo
 * file changes on server.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param who The name of the user whose photo hash to retrieve
 * @return a photo hash (may be NULL)
 */
const gchar *sipe_backend_buddy_get_photo_hash(struct sipe_core_public *sipe_public,
					       const gchar *who);

/**
 * Called when a new internal group is about to be added. If this returns FALSE,
 * the group will not be added.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param group_name  The group being added
 * @return TRUE if everything is ok, FALSE if the group should not be added
 */
gboolean sipe_backend_buddy_group_add(struct sipe_core_public *sipe_public,
				      const gchar *group_name);

/**
 * Called when a new internal group has been renamed
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param old_name old name of the group
 * @param new_name new name of the group
 * @return TRUE if the group was found and renamed
 */
gboolean sipe_backend_buddy_group_rename(struct sipe_core_public *sipe_public,
					 const gchar *old_name,
					 const gchar *new_name);

/**
 * Called when a new internal group should be deleted
 *
 * NOTE: this will only be called on empty groups.
 *
 * @param sipe_public The handle representing the protocol instance making the call
 * @param group_name  The group that should be removed
 */
void sipe_backend_buddy_group_remove(struct sipe_core_public *sipe_public,
				     const gchar *group_name);

/**
 * Present requested buddy information to the user
 */
struct sipe_backend_buddy_info;
struct sipe_backend_buddy_info *sipe_backend_buddy_info_start(struct sipe_core_public *sipe_public);
void sipe_backend_buddy_info_add(struct sipe_core_public *sipe_public,
				 struct sipe_backend_buddy_info *info,
				 sipe_buddy_info_fields key,
				 const gchar *value);
void sipe_backend_buddy_info_break(struct sipe_core_public *sipe_public,
				   struct sipe_backend_buddy_info *info);
void sipe_backend_buddy_info_finalize(struct sipe_core_public *sipe_public,
				      struct sipe_backend_buddy_info *info,
				      const gchar *uri);

struct sipe_backend_buddy_tooltip;
void sipe_backend_buddy_tooltip_add(struct sipe_core_public *sipe_public,
				    struct sipe_backend_buddy_tooltip *tooltip,
				    const gchar *description,
				    const gchar *value);

/**
 * Buddy menu creation
 */
enum sipe_buddy_menu_type {
	SIPE_BUDDY_MENU_MAKE_CHAT_LEADER = 0,
	SIPE_BUDDY_MENU_REMOVE_FROM_CHAT,
	SIPE_BUDDY_MENU_INVITE_TO_CHAT,
	SIPE_BUDDY_MENU_NEW_CHAT,
	SIPE_BUDDY_MENU_MAKE_CALL,
	SIPE_BUDDY_MENU_SEND_EMAIL,
	SIPE_BUDDY_MENU_ACCESS_LEVEL_HELP,
	SIPE_BUDDY_MENU_CHANGE_ACCESS_LEVEL,
	SIPE_BUDDY_MENU_ADD_NEW_DOMAIN,
	SIPE_BUDDY_MENU_SHARE_DESKTOP,
	SIPE_BUDDY_MENU_TYPES
};

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_start(struct sipe_core_public *sipe_public);
struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_add(struct sipe_core_public *sipe_public,
							    struct sipe_backend_buddy_menu *menu,
							    const gchar *label,
							    enum sipe_buddy_menu_type type,
							    gpointer parameter);
struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_separator(struct sipe_core_public *sipe_public,
								  struct sipe_backend_buddy_menu *menu,
								  const gchar *label);
struct sipe_backend_buddy_menu *sipe_backend_buddy_sub_menu_add(struct sipe_core_public *sipe_public,
								struct sipe_backend_buddy_menu *menu,
								const gchar *label,
								struct sipe_backend_buddy_menu *sub);

SipeEncryptionPolicy sipe_backend_media_get_encryption_policy(struct sipe_core_public *sipe_public);

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
