/**
 * @file sipe-media.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 Jakub Adam <jakub.adam@ktknet.cz>
 * Copyright (C) 2016-2017 SIPE Project <http://sipe.sourceforge.net/>
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
struct sdpmsg;
struct sipmsg;
struct sipe_core_private;
struct sipe_media_call_private;
struct sipe_media_stream;

typedef void (* sipe_media_stream_read_callback)(struct sipe_media_stream *stream,
						 guint8 *buffer, gsize len);

/**
 * Creates a new media call.
 *
 * @param sipe_private (in) SIPE core data.
 * @param with (in) SIP URI of the second participant.
 * @param msg (in) SIP INVITE message from the second participant or NULL if we
 *            are the call initiator.
 * @param ice_version (in) version of ICE protocol to use when establishing the
 *                    connection path.
 * @param flags (in) bitwise-or'd media call flags.
 *
 * @return a new @c sipe_media_call structure or @c NULL on error.
 */
struct sipe_media_call *
sipe_media_call_new(struct sipe_core_private *sipe_private, const gchar* with,
		    struct sipmsg *msg, SipeIceVersion ice_version,
		    SipeMediaCallFlags flags);

struct sipe_media_call *
sipe_media_call_find(struct sipe_core_private *sipe_private, const gchar *with);

/**
 * Adds a new media stream to a call.
 *
 * @param call (in) a media call.
 * @param id (in) a string identifier for the media stream.
 * @param type (in) a type of stream's content (audio, video, data, ...).
 * @param ice_version (in) a version of ICE to use when negotiating the
 *                    connection.
 * @param initiator (in) @c TRUE if our client is the initiator of the stream.
 * @param ssrc_count (in) number of RTP Synchronization source identifiers to
 *                   allocate for the stream.
 *
 * @return a new @c sipe_media_stream structure or @c NULL on error.
 */
struct sipe_media_stream *
sipe_media_stream_add(struct sipe_media_call *call, const gchar *id,
		      SipeMediaType type, SipeIceVersion ice_version,
		      gboolean initiator, guint32 ssrc_count);

/**
 * Handles incoming SIP INVITE message to start a media session.
 *
 * @param sipe_private (in) SIPE core data.
 * @param msg (in) a SIP INVITE message
 * @param sdp (in) media session description string
 *
 * @return @c sipe_media_call structure created or updated by @c msg.
 *         The function returns @c NULL on error or if the call was rejected.
 */
struct sipe_media_call *
process_incoming_invite_call(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     const gchar *sdp);

/**
 * Handles incoming SIP INVITE message to start a media session.
 *
 * @param sipe_private (in) SIPE core data.
 * @param msg (in) a SIP INVITE message
 * @param smsg (in) parsed media session description; the function takes
 *             ownership of the sdpmsg structure and will free it when no longer
 *             needed.
 *
 * @return @c sipe_media_call structure created or updated by @c msg.
 *         The function returns @c NULL on error or if the call was rejected.
 */
struct sipe_media_call *
process_incoming_invite_call_parsed_sdp(struct sipe_core_private *sipe_private,
					struct sipmsg *msg,
					struct sdpmsg *smsg);

/**
 * Handles incoming SIP CANCEL message.
 *
 * @param call_private (in) SIPE media call data.
 * @param msg (in) a SIP CANCEL message
 */
void process_incoming_cancel_call(struct sipe_media_call_private *call_private,
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
 * @param sipe_private (in) SIPE core data.
 */
void sipe_media_handle_going_offline(struct sipe_core_private *sipe_private);

/**
 * Checks whether the given media is a conference call.
 *
 * @return @c TRUE if call is a conference, @c FALSE when it is a PC2PC call.
 */
gboolean sipe_media_is_conference_call(struct sipe_media_call_private *call_private);

/**
 * Retrieves the sipe core structure the given call is associated to.
 *
 * @param call (in) media call data
 *
 * @return @c sipe_core_private structure.
 */
struct sipe_core_private *
sipe_media_get_sipe_core_private(struct sipe_media_call *call);

/**
 * Retrieves a SIP dialog associated with the call.
 *
 * @param call (in) media call data
 *
 * @return a @c sip_dialog structure associated with @c call.
 */
struct sip_dialog *
sipe_media_get_sip_dialog(struct sipe_media_call *call);

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
 * Turns @c call's next INVITE into a MIME multipart message with @c body as
 * the extra part.
 *
 * @param call (in) media call data
 * @param invite_content_type (in) MIME media type of the resulting message,
 *                            e.g. "multipart/alternative" or "multipart/mixed"
 * @param body (in) content to add as the second part of the INVITE message;
 *             @c call takes ownership of @c body and will free it after use
 */
void
sipe_media_add_extra_invite_section(struct sipe_media_call *call,
				    const gchar *invite_content_type,
				    gchar *body);

/**
 * Adds application-specific SDP attribute to the stream. This will be sent as
 * a part of our SIP INVITE alongside standard media description, formatted as:
 *
 *  a=name[:value]
 *
 * @param stream (in) media stream data
 * @param name (in) attribute name
 * @param value (in) optional value of the attribute
 */
void
sipe_media_stream_add_extra_attribute(struct sipe_media_stream *stream,
				      const gchar *name, const gchar *value);

/**
 * Schedules asynchronous read of @c len bytes from @c stream into @c buffer.
 * When enough data becomes available in the stream, the buffer is filled and
 * @c callback gets invoked.
 *
 * It's possible to call sipe_media_stream_read_async() multiple times; every
 * request is placed into a FIFO queue. Media core does not call @c read_cb of
 * @c stream while there is some asynchronous read in progress.
 *
 * @param stream (in) media stream data
 * @param buffer (in) an empty data buffer
 * @param len (in) length of @c buffer
 * @param callback (in) a function to call when @c buffer gets filled with
 *                 input data
 */
void
sipe_media_stream_read_async(struct sipe_media_stream *stream,
			     gpointer buffer, gsize len,
			     sipe_media_stream_read_callback callback);

/**
 * Writes @c len bytes from @c buffer into @c stream.
 *
 * If @c stream is not in writable state, Sipe will store the data in
 * an internal queue which gets emptied once the stream becomes writable again.
 * Users should check the stream state using sipe_media_stream_is_writable()
 * before sending excessive data into the stream.
 *
 * @param stream (in) media stream data
 * @param buffer (in) data to send
 * @param len (in) length of @c buffer
 *
 * @return @c TRUE when @c buffer was written into the stream as a whole,
 *         @c FALSE when some data had to be queued for later (and thus
 *         the stream is now in unwritable state).
 */
gboolean
sipe_media_stream_write(struct sipe_media_stream *stream,
			gpointer buffer, gsize len);

/**
 * Checks whether a @c SIPE_MEDIA_APPLICATION stream is in writable state.
 *
 * @param stream (in) media stream data
 *
 * @return @c TRUE if @c stream is writable, otherwise @c FALSE.
 */
gboolean
sipe_media_stream_is_writable(struct sipe_media_stream *stream);

/**
 * Associates user data with the media stream.
 *
 * @param stream (in) media stream data
 * @param data (in) user data
 * @param free_func (in) function to free @c data when @c stream is destroyed
 */
void
sipe_media_stream_set_data(struct sipe_media_stream *stream, gpointer data,
			   GDestroyNotify free_func);

/**
 * Returns user data associated with the media stream.
 *
 * @param stream (in) media stream data
 *
 * @return user data
 */
gpointer
sipe_media_stream_get_data(struct sipe_media_stream *stream);

/**
 * Deallocates the opaque list of media relay structures
 *
 * @param list (in) GSList to free
 */
void sipe_media_relay_list_free(GSList *list);
