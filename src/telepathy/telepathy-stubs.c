/**
 * @file telepathy-stubs.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

/** BUDDIES ******************************************************************/

sipe_backend_buddy sipe_backend_buddy_find(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   SIPE_UNUSED_PARAMETER const gchar *buddy_name,
					   SIPE_UNUSED_PARAMETER const gchar *group_name) { return(NULL); }
GSList *sipe_backend_buddy_find_all(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    SIPE_UNUSED_PARAMETER const gchar *buddy_name,
				    SIPE_UNUSED_PARAMETER const gchar *group_name) { return(NULL); }
gchar *sipe_backend_buddy_get_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) { return(NULL); }
gchar *sipe_backend_buddy_get_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) { return(NULL); }
gchar *sipe_backend_buddy_get_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) { return(NULL); }
gchar *sipe_backend_buddy_get_local_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					  SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) { return(NULL); }
gchar *sipe_backend_buddy_get_group_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) { return(NULL); }
gchar *sipe_backend_buddy_get_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER sipe_backend_buddy buddy,
				     SIPE_UNUSED_PARAMETER const sipe_buddy_info_fields key) { return(NULL); }
void sipe_backend_buddy_set_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   SIPE_UNUSED_PARAMETER sipe_backend_buddy buddy,
				   SIPE_UNUSED_PARAMETER const sipe_buddy_info_fields key,
				   SIPE_UNUSED_PARAMETER const gchar *val) {}
guint sipe_backend_buddy_get_status(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    SIPE_UNUSED_PARAMETER const gchar *uri) { return(SIPE_ACTIVITY_AVAILABLE); }
void sipe_backend_buddy_set_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  SIPE_UNUSED_PARAMETER const sipe_backend_buddy who,
				  SIPE_UNUSED_PARAMETER const gchar *alias) {}
void sipe_backend_buddy_set_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 SIPE_UNUSED_PARAMETER const sipe_backend_buddy who,
					 SIPE_UNUSED_PARAMETER const gchar *alias) {}
sipe_backend_buddy sipe_backend_buddy_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					  SIPE_UNUSED_PARAMETER const gchar *name,
					  SIPE_UNUSED_PARAMETER const gchar *alias,
					  SIPE_UNUSED_PARAMETER const gchar *groupname) { return(NULL); }
void sipe_backend_buddy_remove(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			       SIPE_UNUSED_PARAMETER const sipe_backend_buddy who) {}
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
void sipe_backend_buddy_set_status(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   SIPE_UNUSED_PARAMETER const gchar *who,
				   SIPE_UNUSED_PARAMETER guint activity) {}
void sipe_backend_buddy_set_photo(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  SIPE_UNUSED_PARAMETER const gchar *who,
				  SIPE_UNUSED_PARAMETER gpointer image_data,
				  SIPE_UNUSED_PARAMETER gsize image_len,
				  SIPE_UNUSED_PARAMETER const gchar *photo_hash) {}
const gchar *sipe_backend_buddy_get_photo_hash(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					       SIPE_UNUSED_PARAMETER const gchar *who) { return(""); }
gboolean sipe_backend_buddy_group_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				      SIPE_UNUSED_PARAMETER const gchar *group_name) { return(FALSE); }
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

/** CONNECTION ***************************************************************/

void sipe_backend_connection_completed(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) {}
void sipe_backend_connection_error(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   SIPE_UNUSED_PARAMETER  sipe_connection_error error,
				   SIPE_UNUSED_PARAMETER const gchar *msg) {}
gboolean sipe_backend_connection_is_disconnecting(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(FALSE); }
gboolean sipe_backend_connection_is_valid(SIPE_UNUSED_PARAMETER SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(TRUE); }

/** DNS QUERY ****************************************************************/

struct sipe_dns_query *sipe_backend_dns_query_srv(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
						  SIPE_UNUSED_PARAMETER const gchar *protocol,
						  SIPE_UNUSED_PARAMETER const gchar *transport,
						  SIPE_UNUSED_PARAMETER const gchar *domain,
						  SIPE_UNUSED_PARAMETER sipe_dns_resolved_cb callback,
						  SIPE_UNUSED_PARAMETER gpointer data) { return(NULL); }
void sipe_backend_dns_query_cancel(SIPE_UNUSED_PARAMETER struct sipe_dns_query *query) {}

/** FILE TRANSFER ************************************************************/

void sipe_backend_ft_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			   SIPE_UNUSED_PARAMETER const gchar *errmsg) {}
void sipe_backend_ft_deallocate(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_cancel_local(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_cancel_remote(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft) {}
void sipe_backend_ft_incoming(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			      SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft,
			      SIPE_UNUSED_PARAMETER const gchar *who,
			      SIPE_UNUSED_PARAMETER const gchar *file_name,
			      SIPE_UNUSED_PARAMETER gsize file_size) {}
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

/** NETWORK ******************************************************************/

const gchar *sipe_backend_network_ip_address(SIPE_UNUSED_PARAMETER void) { return("127.0.0.1"); }
struct sipe_backend_listendata *sipe_backend_network_listen_range(SIPE_UNUSED_PARAMETER unsigned short port_min,
								  SIPE_UNUSED_PARAMETER unsigned short port_max,
								  SIPE_UNUSED_PARAMETER sipe_listen_start_cb listen_cb,
								  SIPE_UNUSED_PARAMETER sipe_client_connected_cb connect_cb,
								  SIPE_UNUSED_PARAMETER gpointer data) { return(NULL); }
void sipe_backend_network_listen_cancel(SIPE_UNUSED_PARAMETER struct sipe_backend_listendata *ldata) {}

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

/** SCHEDULE *****************************************************************/

gpointer sipe_backend_schedule_seconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       SIPE_UNUSED_PARAMETER guint timeout,
				       SIPE_UNUSED_PARAMETER gpointer data) { return(NULL); }
gpointer sipe_backend_schedule_mseconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					SIPE_UNUSED_PARAMETER guint timeout,
					SIPE_UNUSED_PARAMETER gpointer data) { return(NULL); }
void sipe_backend_schedule_cancel(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  SIPE_UNUSED_PARAMETER gpointer data) {}

/** SEARCH *******************************************************************/

struct sipe_backend_search_results *sipe_backend_search_results_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(NULL); }
void sipe_backend_search_results_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER struct sipe_backend_search_results *results,
				     SIPE_UNUSED_PARAMETER const gchar *uri,
				     SIPE_UNUSED_PARAMETER const gchar *name,
				     SIPE_UNUSED_PARAMETER const gchar *company,
				     SIPE_UNUSED_PARAMETER const gchar *country,
				     SIPE_UNUSED_PARAMETER const gchar *email) {}
void sipe_backend_search_results_finalize(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					  SIPE_UNUSED_PARAMETER struct sipe_backend_search_results *results,
					  SIPE_UNUSED_PARAMETER const gchar *description,
					  SIPE_UNUSED_PARAMETER gboolean more) {}

/** SETTINGS *****************************************************************/

const gchar *sipe_backend_setting(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  SIPE_UNUSED_PARAMETER sipe_setting type) { return(NULL); }

/** STATUS *******************************************************************/

guint sipe_backend_status(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public) { return(SIPE_ACTIVITY_AVAILABLE); }
gboolean sipe_backend_status_changed(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER guint activity,
				     SIPE_UNUSED_PARAMETER const gchar *message) { return(FALSE); }
void sipe_backend_status_and_note(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  SIPE_UNUSED_PARAMETER guint activity,
				  SIPE_UNUSED_PARAMETER const gchar *message) {}

/** TRANSPORT ****************************************************************/

struct sipe_transport_connection *sipe_backend_transport_connect(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								 SIPE_UNUSED_PARAMETER const sipe_connect_setup *setup) { return(NULL); }
void sipe_backend_transport_disconnect(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn) {}
void sipe_backend_transport_message(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn,
				    SIPE_UNUSED_PARAMETER const gchar *buffer) {}
void sipe_backend_transport_flush(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn) {}

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
void sipe_backend_user_close_ask(SIPE_UNUSED_PARAMETER SIPE_UNUSED_PARAMETER gpointer key) {}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
