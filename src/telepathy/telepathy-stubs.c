/**
 * @file telepathy-stubs.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2016 SIPE Project <http://sipe.sourceforge.net/>
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
 * Stubs for all unimplemented backend functions, because
 *
 *    - feature is not yet implemented, or
 *    - feature can't be implemented for telepathy backend
 *
 * Ordering copied from sipe-backend.h
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

/** BUDDIES ******************************************************************/

void sipe_backend_buddy_list_processing_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) {}
void sipe_backend_buddy_request_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    SIPE_UNUSED_PARAMETER const gchar *who,
				    SIPE_UNUSED_PARAMETER const gchar *alias) {}
void sipe_backend_buddy_request_authorization(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					      SIPE_UNUSED_PARAMETER const gchar *who,
					      SIPE_UNUSED_PARAMETER const gchar *alias,
					      SIPE_UNUSED_PARAMETER gboolean on_list,
					      SIPE_UNUSED_PARAMETER sipe_backend_buddy_request_authorization_cb auth_cb,
					      SIPE_UNUSED_PARAMETER sipe_backend_buddy_request_authorization_cb deny_cb,
					      SIPE_UNUSED_PARAMETER gpointer data) {}
gboolean sipe_backend_buddy_is_blocked(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       SIPE_UNUSED_PARAMETER const gchar *who) { return(FALSE); }
void sipe_backend_buddy_set_blocked_status(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   SIPE_UNUSED_PARAMETER const gchar *who,
					   SIPE_UNUSED_PARAMETER gboolean blocked) {}
gboolean sipe_backend_buddy_group_rename(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 SIPE_UNUSED_PARAMETER const gchar *old_name,
					 SIPE_UNUSED_PARAMETER const gchar *new_name) { return(FALSE); }
struct sipe_backend_buddy_info *sipe_backend_buddy_info_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) {  return(NULL); }
void sipe_backend_buddy_info_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				 SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_info *info,
				 SIPE_UNUSED_PARAMETER sipe_buddy_info_fields key,
				 SIPE_UNUSED_PARAMETER const gchar *value) {}
void sipe_backend_buddy_info_break(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_info *info) {}
void sipe_backend_buddy_info_finalize(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				      SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_info *info,
				      SIPE_UNUSED_PARAMETER const gchar *uri) {}
void sipe_backend_buddy_tooltip_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_tooltip *tooltip,
				    SIPE_UNUSED_PARAMETER const gchar *description,
				    SIPE_UNUSED_PARAMETER const gchar *value) {}
struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(NULL); }
struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
							    SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_menu *menu,
							    SIPE_UNUSED_PARAMETER const gchar *label,
							    SIPE_UNUSED_PARAMETER enum sipe_buddy_menu_type type,
							    SIPE_UNUSED_PARAMETER gpointer parameter) { return(NULL); }
struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_separator(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								  SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_menu *menu,
								  SIPE_UNUSED_PARAMETER const gchar *label) { return(NULL); }
struct sipe_backend_buddy_menu *sipe_backend_buddy_sub_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_menu *menu,
								SIPE_UNUSED_PARAMETER const gchar *label,
								SIPE_UNUSED_PARAMETER struct sipe_backend_buddy_menu *sub) { return(NULL); }

/** CHAT *********************************************************************/

void sipe_backend_chat_session_destroy(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *session) {}
void sipe_backend_chat_add(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
			   SIPE_UNUSED_PARAMETER const gchar *uri,
			   SIPE_UNUSED_PARAMETER gboolean is_new) {}
void sipe_backend_chat_close(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session) {}
struct sipe_backend_chat_session *sipe_backend_chat_create(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
							   SIPE_UNUSED_PARAMETER struct sipe_chat_session *session,
							   SIPE_UNUSED_PARAMETER const gchar *title,
							   SIPE_UNUSED_PARAMETER const gchar *nick) { return(NULL); }
gboolean sipe_backend_chat_find(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
				SIPE_UNUSED_PARAMETER const gchar *uri) { return(FALSE); }
gboolean sipe_backend_chat_is_operator(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
				       SIPE_UNUSED_PARAMETER const gchar *uri) { return(FALSE); }
void sipe_backend_chat_message(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			       SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
			       SIPE_UNUSED_PARAMETER const gchar *from,
			       SIPE_UNUSED_PARAMETER time_t when,
			       SIPE_UNUSED_PARAMETER const gchar *html) {}
void sipe_backend_chat_operator(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
				SIPE_UNUSED_PARAMETER const gchar *uri) {}
void sipe_backend_chat_rejoin(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			      SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
			      SIPE_UNUSED_PARAMETER const gchar *nick,
			      SIPE_UNUSED_PARAMETER const gchar *title) {}
void sipe_backend_chat_rejoin_all(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) {}
void sipe_backend_chat_remove(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
			      SIPE_UNUSED_PARAMETER const gchar *uri) {}
void sipe_backend_chat_show(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session) {}
void sipe_backend_chat_topic(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
			     SIPE_UNUSED_PARAMETER const gchar *topic) {}

/** FILE TRANSFER ************************************************************/

void sipe_backend_ft_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			   SIPE_UNUSED_PARAMETER const gchar *errmsg) {}
const gchar *sipe_backend_ft_get_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) { return(""); }
void sipe_backend_ft_deallocate(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
gssize sipe_backend_ft_read(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			    SIPE_UNUSED_PARAMETER guchar *data,
			    SIPE_UNUSED_PARAMETER gsize size) { return(-1); }
gssize sipe_backend_ft_write(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			     SIPE_UNUSED_PARAMETER const guchar *data,
			     SIPE_UNUSED_PARAMETER gsize size) { return(-1); }
void sipe_backend_ft_set_completed(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_cancel_local(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_cancel_remote(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_incoming(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			      SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			      SIPE_UNUSED_PARAMETER const gchar *who,
			      SIPE_UNUSED_PARAMETER const gchar *file_name,
			      SIPE_UNUSED_PARAMETER gsize file_size) {}
void sipe_backend_ft_outgoing(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			      SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			      SIPE_UNUSED_PARAMETER const gchar *who,
			      SIPE_UNUSED_PARAMETER const gchar *file_name) {}
void sipe_backend_ft_start(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			   SIPE_UNUSED_PARAMETER struct sipe_backend_fd *fd,
			   SIPE_UNUSED_PARAMETER const char* ip,
			   SIPE_UNUSED_PARAMETER unsigned port) {}
gboolean sipe_backend_ft_is_incoming(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) { return(FALSE); }

/** GROUP CHAT ***************************************************************/

void sipe_backend_groupchat_room_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER const gchar *uri,
				     SIPE_UNUSED_PARAMETER const gchar *name,
				     SIPE_UNUSED_PARAMETER const gchar *description,
				     SIPE_UNUSED_PARAMETER guint users,
				     SIPE_UNUSED_PARAMETER guint32 flags) {}
void sipe_backend_groupchat_room_terminate(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) {}

/** IM ***********************************************************************/

void sipe_backend_im_message(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			     SIPE_UNUSED_PARAMETER const gchar *from,
			     SIPE_UNUSED_PARAMETER const gchar *html) {}
void sipe_backend_im_topic(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			   SIPE_UNUSED_PARAMETER const gchar *with,
			   SIPE_UNUSED_PARAMETER const gchar *topic) {}

/** MARKUP *******************************************************************/

gchar *sipe_backend_markup_css_property(SIPE_UNUSED_PARAMETER SIPE_UNUSED_PARAMETER const gchar *style,
					SIPE_UNUSED_PARAMETER const gchar *option) { return(g_strdup("")); }
gchar *sipe_backend_markup_strip_html(SIPE_UNUSED_PARAMETER SIPE_UNUSED_PARAMETER const gchar *html) { return(g_strdup("")); }

/** MEDIA ********************************************************************/
#ifdef HAVE_VV
struct sipe_backend_media *sipe_backend_media_new(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
						  SIPE_UNUSED_PARAMETER struct sipe_media_call *call,
						  SIPE_UNUSED_PARAMETER const gchar *participant,
						  SIPE_UNUSED_PARAMETER SipeMediaCallFlags flags) { return(NULL); }
void sipe_backend_media_free(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media) {}
void sipe_backend_media_set_cname(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media,
				  SIPE_UNUSED_PARAMETER gchar *cname) {}
struct sipe_backend_media_relays * sipe_backend_media_relays_convert(SIPE_UNUSED_PARAMETER GSList *media_relays,
								     SIPE_UNUSED_PARAMETER gchar *username,
								     SIPE_UNUSED_PARAMETER gchar *password) { return(NULL); }
void sipe_backend_media_relays_free(SIPE_UNUSED_PARAMETER struct sipe_backend_media_relays *media_relays) {}
struct sipe_backend_media_stream *sipe_backend_media_add_stream(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
								SIPE_UNUSED_PARAMETER SipeMediaType type,
								SIPE_UNUSED_PARAMETER SipeIceVersion ice_version,
								SIPE_UNUSED_PARAMETER gboolean initiator,
								SIPE_UNUSED_PARAMETER struct sipe_backend_media_relays *media_relays,
								SIPE_UNUSED_PARAMETER guint min_port,
								SIPE_UNUSED_PARAMETER guint max_port) { return(NULL); }
void sipe_backend_media_add_remote_candidates(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					      SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
					      SIPE_UNUSED_PARAMETER GList *candidates) {}
gboolean sipe_backend_media_is_initiator(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					 SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(FALSE); }
gboolean sipe_backend_media_accepted(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media) { return(FALSE); }
gboolean sipe_backend_stream_initialized(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					 SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(FALSE); }
GList *sipe_backend_media_stream_get_active_local_candidates(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(NULL); }
GList *sipe_backend_media_stream_get_active_remote_candidates(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(NULL); }
void sipe_backend_media_set_encryption_keys(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					    SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
					    SIPE_UNUSED_PARAMETER const guchar *encryption_key,
					    SIPE_UNUSED_PARAMETER const guchar *decryption_key) {}
void sipe_backend_stream_hold(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
			      SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
			      SIPE_UNUSED_PARAMETER gboolean local) {}
void sipe_backend_stream_unhold(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
				SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
				SIPE_UNUSED_PARAMETER gboolean local) {}
gboolean sipe_backend_stream_is_held(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(FALSE); }
void sipe_backend_media_stream_end(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
				   SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) {}
void sipe_backend_media_stream_free(SIPE_UNUSED_PARAMETER struct sipe_backend_media_stream *stream) {}
struct sipe_backend_codec *sipe_backend_codec_new(SIPE_UNUSED_PARAMETER int id,
						  SIPE_UNUSED_PARAMETER const char *name,
						  SIPE_UNUSED_PARAMETER SipeMediaType type,
						  SIPE_UNUSED_PARAMETER guint clock_rate) { return(NULL); }
void sipe_backend_codec_free(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec) {}
int sipe_backend_codec_get_id(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec) { return(0); }
gchar *sipe_backend_codec_get_name(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec) { return(g_strdup("")); }
guint sipe_backend_codec_get_clock_rate(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec) { return(0); }
void sipe_backend_codec_add_optional_parameter(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec,
					       SIPE_UNUSED_PARAMETER const gchar *name,
					       SIPE_UNUSED_PARAMETER const gchar *value) {}
GList *sipe_backend_codec_get_optional_parameters(SIPE_UNUSED_PARAMETER struct sipe_backend_codec *codec) { return(NULL); }
gboolean sipe_backend_set_remote_codecs(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
					SIPE_UNUSED_PARAMETER GList *codecs) { return(FALSE); }
GList* sipe_backend_get_local_codecs(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
				     SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(NULL); }
struct sipe_backend_candidate * sipe_backend_candidate_new(SIPE_UNUSED_PARAMETER const gchar *foundation,
							   SIPE_UNUSED_PARAMETER SipeComponentType component,
							   SIPE_UNUSED_PARAMETER SipeCandidateType type,
							   SIPE_UNUSED_PARAMETER SipeNetworkProtocol proto,
							   SIPE_UNUSED_PARAMETER const gchar *ip,
							   SIPE_UNUSED_PARAMETER guint port,
							   SIPE_UNUSED_PARAMETER const gchar *username,
							   SIPE_UNUSED_PARAMETER const gchar *password) { return(NULL); }
void sipe_backend_candidate_free(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) {}
gchar *sipe_backend_candidate_get_username(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(g_strdup("")); }
gchar *sipe_backend_candidate_get_password(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(g_strdup("")); }
gchar *sipe_backend_candidate_get_foundation(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(g_strdup("")); }
gchar *sipe_backend_candidate_get_ip(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(g_strdup("127.0.0.1")); }
guint sipe_backend_candidate_get_port(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(0); }
gchar *sipe_backend_candidate_get_base_ip(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(g_strdup("127.0.0.1")); }
guint sipe_backend_candidate_get_base_port(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(0); }
guint32 sipe_backend_candidate_get_priority(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(0); }
void sipe_backend_candidate_set_priority(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate,
					 SIPE_UNUSED_PARAMETER guint32 priority) {}
SipeComponentType sipe_backend_candidate_get_component_type(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(SIPE_COMPONENT_NONE); }
SipeCandidateType sipe_backend_candidate_get_type(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(SIPE_CANDIDATE_TYPE_ANY); }
SipeNetworkProtocol sipe_backend_candidate_get_protocol(SIPE_UNUSED_PARAMETER struct sipe_backend_candidate *candidate) { return(SIPE_NETWORK_PROTOCOL_TCP_ACTIVE); }
GList* sipe_backend_get_local_candidates(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
					 SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream) { return(NULL); }
void sipe_backend_media_accept(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media,
			       SIPE_UNUSED_PARAMETER gboolean local) {}
void sipe_backend_media_hangup(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media,
			       SIPE_UNUSED_PARAMETER gboolean local) {}
void sipe_backend_media_reject(SIPE_UNUSED_PARAMETER struct sipe_backend_media *media,
			       SIPE_UNUSED_PARAMETER gboolean local) {}
SipeEncryptionPolicy sipe_backend_media_get_encryption_policy(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(SIPE_ENCRYPTION_POLICY_REJECTED); }
gssize sipe_backend_media_stream_read(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
				      SIPE_UNUSED_PARAMETER guint8 *buffer,
				      SIPE_UNUSED_PARAMETER gsize len) { return(-1); }
gssize sipe_backend_media_stream_write(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
				       SIPE_UNUSED_PARAMETER guint8 *buffer,
				       SIPE_UNUSED_PARAMETER gsize len) { return(-1); }
#endif

/** NETWORK ******************************************************************/

struct sipe_backend_listendata *sipe_backend_network_listen_range(SIPE_UNUSED_PARAMETER unsigned short port_min,
								  SIPE_UNUSED_PARAMETER unsigned short port_max,
								  SIPE_UNUSED_PARAMETER sipe_listen_start_cb listen_cb,
								  SIPE_UNUSED_PARAMETER sipe_client_connected_cb connect_cb,
								  SIPE_UNUSED_PARAMETER gpointer data) { return(NULL); }
void sipe_backend_network_listen_cancel(SIPE_UNUSED_PARAMETER struct sipe_backend_listendata *ldata) {}

struct sipe_backend_fd *sipe_backend_fd_from_int(SIPE_UNUSED_PARAMETER int fd) { return (NULL); }
gboolean sipe_backend_fd_is_valid(SIPE_UNUSED_PARAMETER struct sipe_backend_fd *fd) { return(FALSE); }
void sipe_backend_fd_free(SIPE_UNUSED_PARAMETER struct sipe_backend_fd *fd) {}

/** NOTIFICATIONS *************************************************************/

void sipe_backend_notify_message_error(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
				       SIPE_UNUSED_PARAMETER const gchar *who,
				       SIPE_UNUSED_PARAMETER const gchar *message) {}
void sipe_backend_notify_message_info(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				      SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *backend_session,
				      SIPE_UNUSED_PARAMETER const gchar *who,
				      SIPE_UNUSED_PARAMETER const gchar *message) {}
void sipe_backend_notify_error(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			       SIPE_UNUSED_PARAMETER const gchar *title,
			       SIPE_UNUSED_PARAMETER const gchar *msg) {}

/** USER *********************************************************************/

void sipe_backend_user_feedback_typing(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       SIPE_UNUSED_PARAMETER const gchar *from) {}
void sipe_backend_user_feedback_typing_stop(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					    SIPE_UNUSED_PARAMETER const gchar *from) {}
void sipe_backend_user_ask(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			   SIPE_UNUSED_PARAMETER const gchar *message,
			   SIPE_UNUSED_PARAMETER const gchar *accept_label,
			   SIPE_UNUSED_PARAMETER const gchar *decline_label,
			   SIPE_UNUSED_PARAMETER gpointer key) {}
void sipe_backend_user_close_ask(SIPE_UNUSED_PARAMETER gpointer key) {}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
