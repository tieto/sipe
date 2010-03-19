/**
 * @file sipe-conf.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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
struct sipmsg;
struct sip_session;
struct sipe_account_data;

/**
 * Creates conference.
 */
void 
sipe_conf_add(struct sipe_account_data *sip,
	      const gchar* who);

/**
 * Processes incoming INVITE with 
 * Content-Type: application/ms-conf-invite+xml
 * i.e. invitation to join conference.
 *
 * Server 2007+ functionality.
 */
void
process_incoming_invite_conf(struct sipe_account_data *sip,
			     struct sipmsg *msg);
			     
/** Invite us to the focus */
void
sipe_invite_conf_focus(struct sipe_account_data *sip,
		       struct sip_session *session);
			     
/** 
 * Process of conference state
 * Content-Type: application/conference-info+xml
 */
void
sipe_process_conference(struct sipe_account_data *sip,
			struct sipmsg * msg);
			
/**
 * Invites counterparty to join conference.
 */			
void 
sipe_invite_conf(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar* who);

/** 
 * Modify User Role.
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */	
void
sipe_conf_modify_user_role(struct sipe_account_data *sip,
			   struct sip_session *session,
			   const gchar* who);

/** 
 * Modify Conference Lock.
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */				   
void
sipe_conf_modify_conference_lock(struct sipe_account_data *sip,
				 struct sip_session *session,
				 const gboolean locked);
				 
/** 
 * Ejects user from conference.
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */				 
void
sipe_conf_delete_user(struct sipe_account_data *sip,
		      struct sip_session *session,
		      const gchar* who);

/** 
 * Invokes when we are ejected from conference
 * for example or conference has been timed out.
 */
void
sipe_conf_immcu_closed(struct sipe_account_data *sip,
		       struct sip_session *session);      
	
/** 
 * Invokes when we leave conversation.
 * Usually by closing chat wingow.
 */
void
conf_session_close(struct sipe_account_data *sip,
		   struct sip_session *session);

/** 
 * Invoked to process message delivery notification
 * in conference.
 */		   
void
sipe_process_imdn(struct sipe_account_data *sip,
		  struct sipmsg *msg);
