/**
 * @file sipe-core.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
 * Backend -> SIPE Core API - functions called by backend code
 *
 ***************** !!! IMPORTANT NOTE FOR BACKEND CODERS !!! *****************
 *
 *            The SIPE core assumes atomicity and is *NOT* thread-safe.
 *
 * It *does not* protect any of its data structures or code paths with locks!
 *
 * In no circumstances it must be interrupted by another thread calling
 * sipe_core_xxx() while the first thread has entered the SIPE core through
 * a sipe_core_xxx() function.
 *
 ***************** !!! IMPORTANT NOTE FOR BACKEND CODERS !!! *****************
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Transport type
 */
#define SIPE_TRANSPORT_AUTO 0
#define SIPE_TRANSPORT_TLS  1
#define	SIPE_TRANSPORT_TCP  2

/**
 * Transport connection (public part)
 *
 * The receiver in the backend fills "buffer". The backend has to zero
 * terminate the buffer before calling the processing function in the core.
 *
 * The processing function in the core can remove content from the buffer.
 * It has to update buffer_used accordingly.
 *
 */
struct sipe_transport_connection {
	gpointer user_data;
	gchar *buffer;
	gsize buffer_used;        /* 0 < buffer_used < buffer_length */
	gsize buffer_length;      /* read-only */
	guint type;               /* read-only */
	guint client_port;        /* read-only */
};

/**
 * Opaque data type for chat session
 */
struct sipe_chat_session;

/**
 * File transport (public part)
 */
struct sipe_file_transfer {
	struct sipe_backend_file_transfer *backend_private;
};

/**
 * Opaque data type for backend private data.
 * The backend is responsible to allocate and free it.
 */
struct sipe_backend_private;

/**
 * SIP transport authentication scheme
 */
#define SIPE_AUTHENTICATION_TYPE_UNSET     0
#define SIPE_AUTHENTICATION_TYPE_BASIC     1 /* internal use only */
#define SIPE_AUTHENTICATION_TYPE_NTLM      2
#define SIPE_AUTHENTICATION_TYPE_KERBEROS  3
#define SIPE_AUTHENTICATION_TYPE_NEGOTIATE 4 /* internal use only */
#define SIPE_AUTHENTICATION_TYPE_TLS_DSK   5

/**
 * Flags
 */
/* user disabled calendar information publishing */
#define SIPE_CORE_FLAG_DONT_PUBLISH 0x00000001

#define SIPE_CORE_FLAG_IS(flag)    \
	((sipe_public->flags & SIPE_CORE_FLAG_ ## flag) == SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_FLAG_SET(flag)   \
	(sipe_public->flags |= SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_FLAG_UNSET(flag) \
	(sipe_public->flags &= ~SIPE_CORE_FLAG_ ## flag)

/**
 * Public part of the Sipe data structure
 *
 * This part contains the information needed by the core and the backend.
 */
struct sipe_core_public {
	/**
	 * This points to the private data for the backend.
	 * The backend is responsible to allocate and free it.
	 */
	struct sipe_backend_private *backend_private;

	/* flags (see above) */
	guint32 flags;

	/* user information */
	gchar *sip_name;
	gchar *sip_domain;

	/* server information */
	/* currently nothing */
};

/**
 * Initialize & destroy functions for the SIPE core
 * Should be called on loading and unloading of the plugin.
 */
void sipe_core_init(const char *locale_dir);
void sipe_core_destroy(void);

/** Utility functions exported by the core to backends ***********************/
gboolean sipe_strequal(const gchar *left, const gchar *right);

GSList *
sipe_utils_nameval_add(GSList *list, const gchar *name, const gchar *value);

const gchar *
sipe_utils_nameval_find(const GSList *list, const gchar *name);

const gchar *
sipe_utils_nameval_find_instance(const GSList *list, const gchar *name, int which);

void
sipe_utils_nameval_free(GSList *list);

gchar *sip_uri_from_name(const gchar *name);
gchar *sip_uri_if_valid(const gchar *string);

/*****************************************************************************/

/**
 * Other functions (need to be sorted once structure becomes clear.
 */

/* Get translated about string. Must be g_free'd(). */
gchar *sipe_core_about(void);

/* Execute a scheduled action */
void sipe_core_schedule_execute(gpointer data);

/* menu actions */
void sipe_core_update_calendar(struct sipe_core_public *sipe_public);
void sipe_core_reset_status(struct sipe_core_public *sipe_public);

/* access levels */
void sipe_core_change_access_level_from_container(struct sipe_core_public *sipe_public,
						  gpointer parameter);
void sipe_core_change_access_level_for_domain(struct sipe_core_public *sipe_public,
					      const gchar *domain,
					      guint index);

/**
 * Activity
 *   - core:    maps this to OCS protocol values
 *              maps this to translated descriptions
 *   - backend: maps this to backend status values
 *              backend token string can be used as "ID" in protocol
 *
 * This is passed back-and-forth and therefore defined as list, not as enum.
 * Can be used as array index
 */
#define SIPE_ACTIVITY_UNSET        0
#define	SIPE_ACTIVITY_AVAILABLE    1
#define SIPE_ACTIVITY_ONLINE       2
#define SIPE_ACTIVITY_INACTIVE     3
#define SIPE_ACTIVITY_BUSY         4
#define SIPE_ACTIVITY_BUSYIDLE     5
#define SIPE_ACTIVITY_DND          6
#define SIPE_ACTIVITY_BRB          7
#define SIPE_ACTIVITY_AWAY         8
#define SIPE_ACTIVITY_LUNCH        9
#define SIPE_ACTIVITY_INVISIBLE   10
#define SIPE_ACTIVITY_OFFLINE     11
#define SIPE_ACTIVITY_ON_PHONE    12
#define SIPE_ACTIVITY_IN_CONF     13
#define SIPE_ACTIVITY_IN_MEETING  14
#define SIPE_ACTIVITY_OOF         15
#define SIPE_ACTIVITY_URGENT_ONLY 16
#define SIPE_ACTIVITY_NUM_TYPES   17 /* use to define array size */

const gchar *sipe_core_activity_description(guint type);

/* buddy actions */
/**
 * Get status text for buddy.
 *
 * @param sipe_public Sipe core public data structure.
 * @param uri         SIP URI of the buddy
 * @param activity    activity value for buddy
 * @param status_text backend-specific buddy status text for activity.
 *
 * @return HTML status text for the buddy or NULL. Must be g_free()'d.
 */
gchar *sipe_core_buddy_status(struct sipe_core_public *sipe_public,
			      const gchar *uri,
			      guint activity,
			      const gchar *status_text);

void sipe_core_buddy_got_status(struct sipe_core_public *sipe_public,
				const gchar *uri,
				guint activity);

/**
 * Trigger generation of buddy information label/text pairs
 *
 * @param sipe_public Sipe core public data structure.
 * @param uri         SIP URI of the buddy
 * @param status_text backend-specific buddy status text for ID.
 * @param is_online   backend considers buddy to be online.
 * @param tooltip     opaque backend identifier for tooltip info. This is the
 *                    parameter given to @c sipe_backend_buddy_tooltip_add()
 */
struct sipe_backend_buddy_tooltip;
void sipe_core_buddy_tooltip_info(struct sipe_core_public *sipe_public,
				  const gchar *uri,
				  const gchar *status_name,
				  gboolean is_online,
				  struct sipe_backend_buddy_tooltip *tooltip);

/**
 * Add a buddy
 *
 * @param sipe_public Sipe core public data structure
 * @param uri         SIP URI of the buddy
 * @param group_name  backend-specific group name
 */
void sipe_core_buddy_add(struct sipe_core_public *sipe_public,
			 const gchar *uri,
			 const gchar *group_name);

/**
 * Remove a buddy
 *
 * @param sipe_public Sipe core public data structure
 * @param uri         SIP URI of the buddy
 * @param group_name  backend-specific group name
 */
void sipe_core_buddy_remove(struct sipe_core_public *sipe_public,
			    const gchar *uri,
			    const gchar *group_name);

void sipe_core_contact_allow_deny(struct sipe_core_public *sipe_public,
				  const gchar *who,
				  gboolean allow);
void sipe_core_group_set_alias(struct sipe_core_public *sipe_public,
			       const gchar *who,
			       const gchar *alias);

/**
 * Setup core data
 */
struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    gboolean sso,
					    const gchar *login_domain,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg);
void sipe_core_deallocate(struct sipe_core_public *sipe_public);

/**
 * Check if SIP authentication scheme requires a password
 *
 * NOTE: this can be called *BEFORE* @c sipe_core_allocate()!
 *
 * @param authentication SIP transport authentication type
 * @param sso            TRUE if user selected Single-Sign On
 *
 * @return TRUE if password is required
 */
gboolean sipe_core_transport_sip_requires_password(guint authentication,
						   gboolean sso);

/**
 * Connect to SIP server
 */
void sipe_core_transport_sip_connect(struct sipe_core_public *sipe_public,
				     guint transport,
				     guint authentication,
				     const gchar *server,
				     const gchar *port);

/**
 * Get SIP server host name
 *
 * @param sipe_public Sipe core public data structure
 *
 * @return server host name (may be @c NULL if not fully connected yet)
 */
const gchar *sipe_core_transport_sip_server_name(struct sipe_core_public *sipe_public);

/**
 * Invite to chat
 */
void sipe_core_chat_invite(struct sipe_core_public *sipe_public,
			   struct sipe_chat_session *chat_session,
			   const char *name);

/**
 * Rejoin a chat after connection re-establishment
 */
void sipe_core_chat_rejoin(struct sipe_core_public *sipe_public,
			   struct sipe_chat_session *chat_session);

/**
 * Leave a chat
 */
void sipe_core_chat_leave(struct sipe_core_public *sipe_public,
			  struct sipe_chat_session *chat_session);

/**
 * Send message to chat
 */
void sipe_core_chat_send(struct sipe_core_public *sipe_public,
			 struct sipe_chat_session *chat_session,
			 const char *what);

/**
 * Check chat lock status
 */
typedef enum {
	SIPE_CHAT_LOCK_STATUS_NOT_ALLOWED = 0,
	SIPE_CHAT_LOCK_STATUS_UNLOCKED,
	SIPE_CHAT_LOCK_STATUS_LOCKED
} sipe_chat_lock_status;
sipe_chat_lock_status sipe_core_chat_lock_status(struct sipe_core_public *sipe_public,
						 struct sipe_chat_session *chat_session);

/**
 * Lock chat
 */
void sipe_core_chat_modify_lock(struct sipe_core_public *sipe_public,
				struct sipe_chat_session *chat_session,
				const gboolean locked);

/**
 * Create new session with Focus URI
 *
 * @param sipe_public (in) SIPE core data.
 * @param focus_uri (in) focus URI string
 *
 * @return new SIP session
 */
struct sip_session *
sipe_core_conf_create(struct sipe_core_public *sipe_public,
		      const gchar *focus_uri);

/* buddy menu callback: parameter == chat_session */
void sipe_core_conf_make_leader(struct sipe_core_public *sipe_public,
				gpointer parameter,
				const gchar *buddy_name);
void sipe_core_conf_remove_from(struct sipe_core_public *sipe_public,
				gpointer parameter,
				const gchar *buddy_name);

/* call control (CSTA) */
void sipe_core_buddy_make_call(struct sipe_core_public *sipe_public,
			       const gchar *phone);

/* media */
void sipe_core_media_initiate_call(struct sipe_core_public *sipe_public,
				   const char *participant,
				   gboolean with_video);
/**
 * Connects to a conference call specified by given chat session
 *
 * @param sipe_public (in) SIPE core data.
 * @param chat_session (in) chat session structure
 */
void sipe_core_media_connect_conference(struct sipe_core_public *sipe_public,
					struct sipe_chat_session *chat_session);

/**
 * Checks whether there is a media call in progress
 *
 * @param sipe_public (in) SIPE core data.
 *
 * @return @c TRUE if media call is in progress
 */
gboolean sipe_core_media_in_call(struct sipe_core_public *sipe_public);

/**
 * Initiates a call with given phone number
 *
 * @param sipe_public (in) SIPE core data.
 * @parem phone_number (in) a mobile or landline phone number, i.e. +46123456
 */
void sipe_core_media_phone_call(struct sipe_core_public *sipe_public,
				const gchar *phone_number);

/**
 * Checks voice quality by making a call to the test service
 *
 * @param sipe_public (in) SIPE core data.
 */
void sipe_core_media_test_call(struct sipe_core_public *sipe_public);

/* file transfer */
struct sipe_file_transfer *sipe_core_ft_allocate(struct sipe_core_public *sipe_public);
void sipe_core_ft_deallocate(struct sipe_file_transfer *ft);
void sipe_core_ft_cancel(struct sipe_file_transfer *ft);
void sipe_core_ft_incoming_init(struct sipe_file_transfer *ft);
void sipe_core_ft_outgoing_init(struct sipe_file_transfer *ft,
				const gchar *filename, gsize size,
				const gchar *who);

void sipe_core_tftp_incoming_start(struct sipe_file_transfer *ft,
				   gsize total_size);
gboolean sipe_core_tftp_incoming_stop(struct sipe_file_transfer *ft);
void sipe_core_tftp_outgoing_start(struct sipe_file_transfer *ft,
				   gsize total_size);
gboolean sipe_core_tftp_outgoing_stop(struct sipe_file_transfer *ft);
gssize sipe_core_tftp_read(struct sipe_file_transfer *ft, guchar **buffer,
			   gsize bytes_remaining, gsize bytes_available);
gssize sipe_core_tftp_write(struct sipe_file_transfer *ft, const guchar *buffer,
			    gsize size);
/* group chat */
gboolean sipe_core_groupchat_query_rooms(struct sipe_core_public *sipe_public);
void sipe_core_groupchat_join(struct sipe_core_public *sipe_public,
			      const gchar *uri);

/* IM */
void sipe_core_im_send(struct sipe_core_public *sipe_public,
		       const gchar *who,
		       const gchar *what);
void sipe_core_im_close(struct sipe_core_public *sipe_public,
			const gchar *who);

/* user */
void sipe_core_user_feedback_typing(struct sipe_core_public *sipe_public,
				    const gchar *to,
				    gboolean typing);

void sipe_core_user_ask_cb(gpointer key, gboolean accepted);

/* groups */
void sipe_core_group_rename(struct sipe_core_public *sipe_public,
			    const gchar *old_name,
			    const gchar *new_name);

void sipe_core_group_remove(struct sipe_core_public *sipe_public,
			    const gchar *name);

/* buddies */
void sipe_core_buddy_group(struct sipe_core_public *sipe_public,
			   const gchar *who,
			   const gchar *old_group_name,
			   const gchar *new_group_name);

struct sipe_backend_search_token;
void sipe_core_buddy_search(struct sipe_core_public *sipe_public,
			    struct sipe_backend_search_token *token,
			    const gchar *given_name,
			    const gchar *surname,
			    const gchar *email,
			    const gchar *company,
			    const gchar *country);

void sipe_core_buddy_get_info(struct sipe_core_public *sipe_public,
			      const gchar *who);

void sipe_core_buddy_new_chat(struct sipe_core_public *sipe_public,
			      const gchar *who);
void sipe_core_buddy_send_email(struct sipe_core_public *sipe_public,
				const gchar *who);

struct sipe_backend_buddy_menu;
struct sipe_backend_buddy_menu *sipe_core_buddy_create_menu(struct sipe_core_public *sipe_public,
							    const gchar *buddy_name,
							    struct sipe_backend_buddy_menu *menu);

void sipe_core_buddy_menu_free(struct sipe_core_public *sipe_public);

/* status */
void sipe_core_status_set(struct sipe_core_public *sipe_public,
			  guint activity,
			  const gchar *note);
void sipe_core_status_idle(struct sipe_core_public *sipe_public);

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
