 /**
 * @file sipe-groupchat.h
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

/* Forward declarations */
struct sipmsg;
struct sip_dialog;
struct sip_session;
struct sipe_chat_session;
struct sipe_core_private;

void sipe_groupchat_free(struct sipe_core_private *sipe_private);
void sipe_groupchat_init(struct sipe_core_private *sipe_private);
void sipe_groupchat_invite_failed(struct sipe_core_private *sipe_private,
				  struct sip_session *session);
void sipe_groupchat_invite_response(struct sipe_core_private *sipe_private,
				    struct sip_dialog *dialog,
				    struct sipmsg *response);
void process_incoming_info_groupchat(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg,
				     struct sip_session *session);
void sipe_groupchat_send(struct sipe_core_private *sipe_private,
			 struct sipe_chat_session *chat_session,
			 const gchar *what);
void sipe_groupchat_leave(struct sipe_core_private *sipe_private,
			  struct sipe_chat_session *chat_session);
void sipe_groupchat_rejoin(struct sipe_core_private *sipe_private,
			   struct sipe_chat_session *chat_session);
