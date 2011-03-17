/**
 * @file sipe-im.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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

/* Forward declarations */
struct sip_dialog;
struct sip_session;
struct sipe_core_private;

#ifdef HAVE_GMIME
/* pls. don't add multipart/related - it's not used in IM modality */
#define SDP_ACCEPT_TYPES  "text/plain text/html image/gif multipart/alternative application/im-iscomposing+xml application/ms-imdn+xml text/x-msmsgsinvite"
#else
/* this is a rediculous hack as Pidgin's MIME implementastion doesn't support (or have bug) in multipart/alternative */
/* OCS/OC won't use multipart/related so we don't advertase it */
#define SDP_ACCEPT_TYPES  "text/plain text/html image/gif application/im-iscomposing+xml application/ms-imdn+xml text/x-msmsgsinvite"
#endif

/**
 * Send invitation and initial message to IM session
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the IM conversation(s)
 * @param who          URI of the invitee
 * @param msg_body     message body or NULL
 * @param content_type message body MIME type
 * @param referred_by  value for Referred-By or NULL
 * @param is_triggered triggered invite or not
 */
void sipe_im_invite(struct sipe_core_private *sipe_private,
		    struct sip_session *session,
		    const gchar *who,
		    const gchar *msg_body,
		    const gchar *content_type,
		    const gchar *referred_by,
		    const gboolean is_triggered);

/**
 * Process queue IM messages
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the IM conversation(s)
 */
void sipe_im_process_queue(struct sipe_core_private *sipe_private,
			   struct sip_session *session);

/**
 * Cancel unconfirmed IM messages
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the IM conversation(s)
 * @param callid       Call ID of the conversation
 * @param with         URI of the remote party
 */
void sipe_im_cancel_unconfirmed(struct sipe_core_private *sipe_private,
				struct sip_session *session,
				const gchar *callid,
				const gchar *with);

/**
 * Re-enqueue unconfirmed IM messages
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the IM conversation(s)
 * @param callid       Call ID of the conversation
 * @param with         URI of the remote party
 */
void sipe_im_reenqueue_unconfirmed(struct sipe_core_private *sipe_private,
				   struct sip_session *session,
				   const gchar *callid,
				   const gchar *with);

typedef void (*unconfirmed_callback)(struct sipe_core_private *sipe_private,
				     struct sip_session *session,
				     const gchar *callid,
				     const gchar *with);

/**
 * Close dangling IM session
 *
 * @param sipe_private (in) SIPE core data.
 * @param session      (in) pointer to session
 * @param dialog       (in) pointer to dialog
 * @param with         (in) URI of dialog partner
 * @param callback     (in) callback for unconfirmed message
 */
void sipe_im_cancel_dangling(struct sipe_core_private *sipe_private,
			     struct sip_session *session,
			     struct sip_dialog *dialog,
			     const gchar *with,
			     unconfirmed_callback callback);

/**
 * Sets a topic for IM conversation
 *
 * @param sipe_private (in) SIPE core data
 * @param session      (in) pointer to session
 * @param topic        (in) string describing conversation topic
 */
void sipe_im_topic(struct sipe_core_private *sipe_private,
		   struct sip_session *session,
		   const gchar *topic);

/**
 * Processes INFO message with application/xml+conversationinfo content type
 *
 * @param sipe_private (in) SIPE core data
 * @param msg          (in) SIP INFO message
 */
void process_incoming_info_conversation(struct sipe_core_private *sipe_private,
					struct sipmsg *msg);
