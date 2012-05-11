/**
 * @file sipe-conf.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-10 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipmsg;
struct sip_session;
struct sipe_core_private;

/**
 * Creates conference.
 */
void
sipe_conf_add(struct sipe_core_private *sipe_private,
	      const gchar* who);

/**
 * Processes incoming INVITE with
 * Content-Type: application/ms-conf-invite+xml
 * i.e. invitation to join conference.
 *
 * Server 2007+ functionality.
 */
void
process_incoming_invite_conf(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg);

/**
 * Create new session with Focus URI
 *
 * @param chat_session non-NULL if we rejoin a conference
 * @param focus_uri    non-NULL if we create a new conference
 *
 * @return new SIP session
 */
struct sip_session *
sipe_conf_create(struct sipe_core_private *sipe_private,
		 struct sipe_chat_session *chat_session,
		 const gchar *focus_uri);

/**
 * Process of conference state
 * Content-Type: application/conference-info+xml
 */
void
sipe_process_conference(struct sipe_core_private *sipe_private,
			struct sipmsg * msg);

/**
 * Invites counterparty to join conference.
 */
void
sipe_invite_conf(struct sipe_core_private *sipe_private,
		 struct sip_session *session,
		 const gchar* who);

/**
 * Modify User Role.
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */
void
sipe_conf_modify_user_role(struct sipe_core_private *sipe_private,
			   struct sip_session *session,
			   const gchar* who);

/**
 * Ejects user from conference.
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */
void
sipe_conf_delete_user(struct sipe_core_private *sipe_private,
		      struct sip_session *session,
		      const gchar* who);

/**
 * Invokes when we are ejected from conference
 * for example or conference has been timed out.
 */
void
sipe_conf_immcu_closed(struct sipe_core_private *sipe_private,
		       struct sip_session *session);

/**
 * Removes a session waiting to be accepted or declined by the user.
 *
 * @param sipe_private SIPE core data
 * @param msg SIP CANCEL message. If NULL is passed, all sessions not accepted
 *            will be canceled
 */
void
sipe_conf_cancel_unaccepted(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg);

/**
 * Invokes when we leave conversation.
 * Usually by closing chat wingow.
 */
void
conf_session_close(struct sipe_core_private *sipe_private,
		   struct sip_session *session);

/**
 * Invoked to process message delivery notification
 * in conference.
 */
void
sipe_process_imdn(struct sipe_core_private *sipe_private,
		  struct sipmsg *msg);
