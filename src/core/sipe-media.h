/**
 * @file sipe-media.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 Jakub Adam <jakub.adam@ktknet.cz>
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
struct sipe_core_private;
struct sipe_media_call_private;

/**
 * Handles incoming SIP INVITE message to start a media session.
 *
 * @param sipe_private (in) SIPE core data.
 * @param msg (in) a SIP INVITE message
 */
void process_incoming_invite_call(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg);

/**
 * Handles incoming SIP CANCEL message.
 *
 * @param sipe_private (in) SIPE core data.
 * @param msg (in) a SIP CANCEL message
 */
void process_incoming_cancel_call(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg);

/**
 * Hangs up a media session and closes all allocated resources.
 *
 * @param sipe_private (in) media call data.
 */
void sipe_media_hangup(struct sipe_media_call_private *call_private);

/**
 * Call before SIP account logs of the server. Function hangs up the call and
 * notifies remote participant according to the actual state of call
 * negotiation.
 *
 * @param call_private (in) media call data
 */
void sipe_media_handle_going_offline(struct sipe_media_call_private *call_private);

/**
 * Checks whether the given media is a conference call.
 *
 * @return @c TRUE if call is a conference, @c FALSE when it is a PC2PC call.
 */
gboolean sipe_media_is_conference_call(struct sipe_media_call_private *call_private);

/**
 * Checks whether SIP message belongs to the session of the given media call.
 *
 * Test is done on the basis of the Call-ID of the message.
 *
 * @param call_private (in) media call data
 * @param msg (in) a SIP message
 *
 * @return @c TRUE if the SIP message belongs to the media session.
 */
gboolean is_media_session_msg(struct sipe_media_call_private *call_private,
			      struct sipmsg *msg);

/**
 * Sends a request to mras URI for the credentials to the A/V edge server.
 * Given @c sipe_core_private must have non-NULL mras_uri. When the valid
 * response is received, media_relay_username, media_relay_password and
 * media_relays attributes of the sipe core are filled.
 *
 * @param sipe_private (in) SIPE core data.
 */
void sipe_media_get_av_edge_credentials(struct sipe_core_private *sipe_private);

/**
 * Deallocates the opaque list of media relay structures
 *
 * @param list (in) GSList to free
 */
void sipe_media_relay_list_free(GSList *list);
