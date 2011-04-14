/**
 * @file sipe-core.h
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
 * Activity
 *   - core:    maps this to OCS protocol values
 *   - backend: maps this to backend status values
 */
typedef enum
{
	SIPE_ACTIVITY_UNSET = 0,
	SIPE_ACTIVITY_ONLINE,
	SIPE_ACTIVITY_INACTIVE,
	SIPE_ACTIVITY_BUSY,
	SIPE_ACTIVITY_BUSYIDLE,
	SIPE_ACTIVITY_DND,
	SIPE_ACTIVITY_BRB,
	SIPE_ACTIVITY_AWAY,
	SIPE_ACTIVITY_LUNCH,
	SIPE_ACTIVITY_OFFLINE,
	SIPE_ACTIVITY_ON_PHONE,
	SIPE_ACTIVITY_IN_CONF,
	SIPE_ACTIVITY_IN_MEETING,
	SIPE_ACTIVITY_OOF,
	SIPE_ACTIVITY_URGENT_ONLY,
	SIPE_ACTIVITY_NUM_TYPES
} sipe_activity;

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
 * Flags
 */
#define SIPE_CORE_FLAG_KRB5 0x00000001 /* user enabled Kerberos 5     */
#define SIPE_CORE_FLAG_SSO  0x00000002 /* user enabled Single-Sign On */

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
	guint keepalive_timeout;
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

gboolean sipe_utils_is_avconf_uri(const gchar *uri);

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

/* buddy actions */
/**
 * Get status text for buddy.
 *
 * @param sipe_public Sipe core public data structure.
 * @param name        backend-specific buddy name.
 * @param activity    activity value for buddy
 * @param status_text backend-specific buddy status text for activity.
 *
 * @return HTML status text for the buddy or NULL. Must be g_free()'d.
 */
gchar *sipe_core_buddy_status(struct sipe_core_public *sipe_public,
			      const gchar *name,
			      const sipe_activity activity,
			      const gchar *status_text);

void sipe_core_buddy_got_status(struct sipe_core_public *sipe_public,
				const gchar* uri,
				const gchar *status_id);

/**
 * Return a list with buddy information label/text pairs
 *
 * @param sipe_public Sipe core public data structure.
 * @param name        backend-specific buddy name.
 * @param status_text backend-specific buddy status text for ID.
 * @param is_online   backend considers buddy to be online.
 *
 * @return GSList of struct sipe_buddy_info or NULL. Must be freed by caller.
 */
struct sipe_buddy_info {    /* must be g_free()'d */
	const gchar *label;
	gchar *text;        /* must be g_free()'d */
};
GSList *sipe_core_buddy_info(struct sipe_core_public *sipe_public,
			     const gchar *name,
			     const gchar *status_name,
			     gboolean is_online);

void sipe_core_contact_allow_deny(struct sipe_core_public *sipe_public,
				  const gchar *who, gboolean allow);
void sipe_core_group_set_user(struct sipe_core_public *sipe_public,
			      const gchar * who);

/**
 * Setup core data
 */
struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    const gchar *login_domain,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg);
void sipe_core_deallocate(struct sipe_core_public *sipe_public);

/**
 * Connect to SIP server
 */
void sipe_core_transport_sip_connect(struct sipe_core_public *sipe_public,
				     guint transport,
				     const gchar *server,
				     const gchar *port);
void sipe_core_transport_sip_keepalive(struct sipe_core_public *sipe_public);

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

/* user */
void sipe_core_user_feedback_typing(struct sipe_core_public *sipe_public,
				    const gchar *to);

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
