/**
 * @file sipe-ft-lync.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2016 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ft-lync.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipmsg.h"
#include "sdpmsg.h"

struct sipe_file_transfer_lync {
	struct sipe_file_transfer public;

	gchar *sdp;
	gchar *file_name;
	gchar *id;
	gsize file_size;
	guint request_id;

	guint bytes_left_in_chunk;

	guint8 buffer[2048];
	guint buffer_len;
	guint buffer_read_pos;

	int backend_pipe[2];
	int backend_pipe_write_source_id;

	struct sipe_core_private *sipe_private;
	struct sipe_media_call *call;

	void (*call_reject_parent_cb)(struct sipe_media_call *call,
				      gboolean local);
};
#define SIPE_FILE_TRANSFER         ((struct sipe_file_transfer *) ft_private)
#define SIPE_FILE_TRANSFER_PRIVATE ((struct sipe_file_transfer_lync *) ft)

typedef enum {
	SIPE_XDATA_DATA_CHUNK = 0x00,
	SIPE_XDATA_START_OF_STREAM = 0x01,
	SIPE_XDATA_END_OF_STREAM = 0x02
} SipeXDataMessages;

#define XDATA_HEADER_SIZE sizeof (guint8) + sizeof (guint16)

static void
sipe_file_transfer_lync_free(struct sipe_file_transfer_lync *ft_private)
{
	int our_pipe_end;

	our_pipe_end = sipe_backend_ft_is_incoming(SIPE_FILE_TRANSFER) ? 1 : 0;

	if (ft_private->backend_pipe[our_pipe_end] != 0) {
		// Backend is responsible for closing the pipe's other end.
		close(ft_private->backend_pipe[our_pipe_end]);
	}

	g_free(ft_private->file_name);
	g_free(ft_private->sdp);
	g_free(ft_private->id);

	if (ft_private->backend_pipe_write_source_id) {
		g_source_remove(ft_private->backend_pipe_write_source_id);
	}

	g_free(ft_private);
}

static void
send_ms_filetransfer_msg(char *body, struct sipe_file_transfer_lync *ft_private,
			 TransCallback callback)
{
	sip_transport_info(sipe_media_get_sipe_core_private(ft_private->call),
			   "Content-Type: application/ms-filetransfer+xml\r\n",
			   body,
			   sipe_media_get_sip_dialog(ft_private->call),
			   callback);

	g_free(body);
}

static void
send_ms_filetransfer_response(struct sipe_file_transfer_lync *ft_private,
			      const gchar *code, const gchar *reason,
			      TransCallback callback)
{
	static const gchar *RESPONSE_STR =
			"<response xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" requestId=\"%d\" code=\"%s\" %s%s%s/>";

	send_ms_filetransfer_msg(g_strdup_printf(RESPONSE_STR,
						 ft_private->request_id, code,
						 reason ? "reason=\"" : "",
						 reason ? reason : "",
						 reason ? "\"" : ""),
				 ft_private, callback);
}

static void
mime_mixed_cb(gpointer user_data, const GSList *fields, const gchar *body,
	      gsize length)
{
	struct sipe_file_transfer_lync *ft_private = user_data;
	const gchar *ctype = sipe_utils_nameval_find(fields, "Content-Type");

	/* Lync 2010 file transfer */
	if (g_str_has_prefix(ctype, "application/ms-filetransfer+xml")) {
		sipe_xml *xml = sipe_xml_parse(body, length);

		if (xml) {
			const sipe_xml *node;

			ft_private->request_id = sipe_xml_int_attribute(xml,
									"requestId",
									ft_private->request_id);

			node = sipe_xml_child(xml, "publishFile/fileInfo/name");
			if (node) {
				g_free(ft_private->file_name);
				ft_private->file_name = sipe_xml_data(node);
			}

			node = sipe_xml_child(xml, "publishFile/fileInfo/id");
			if (node) {
				g_free(ft_private->id);
				ft_private->id = sipe_xml_data(node);
			}

			node = sipe_xml_child(xml, "publishFile/fileInfo/size");
			if (node) {
				gchar *size_str = sipe_xml_data(node);
				if (size_str) {
					ft_private->file_size = atoi(size_str);
					g_free(size_str);
				}
			}

			sipe_xml_free(xml);
		}
	} else if (g_str_has_prefix(ctype, "application/sdp")) {
		g_free(ft_private->sdp);
		ft_private->sdp = g_strndup(body, length);
	}
}

static void
candidate_pairs_established_cb(struct sipe_media_stream *stream)
{
	struct sipe_file_transfer_lync *ft_private;
	static const gchar *DOWNLOAD_FILE_REQUEST =
		"<request xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" requestId=\"%d\">"
			"<downloadFile>"
				"<fileInfo>"
					"<id>%s</id>"
					"<name>%s</name>"
				"</fileInfo>"
			"</downloadFile>"
		"</request>";

	g_return_if_fail(sipe_strequal(stream->id, "data"));

	ft_private = sipe_media_stream_get_data(stream);

	send_ms_filetransfer_response(ft_private, "success", NULL, NULL);

	send_ms_filetransfer_msg(g_strdup_printf(DOWNLOAD_FILE_REQUEST,
						 ++ft_private->request_id,
						 ft_private->id,
						 ft_private->file_name),
				 ft_private, NULL);
}

static gboolean
create_pipe(int pipefd[2])
{
#ifdef _WIN32
#error "Pipes not implemented for Windows"
/* Those interested in porting the code may use Pidgin's wpurple_input_pipe() in
 * win32dep.c as an inspiration. */
#else
	if (pipe(pipefd) != 0) {
		return FALSE;
	}

	/* @TODO: ignoring potential error return - how to handle? */
	(void) fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
	(void) fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);

	return TRUE;
#endif
}

static void
xdata_start_of_stream_cb(struct sipe_media_stream *stream,
			 guint8 *buffer, gsize len)
{
	struct sipe_file_transfer_lync *ft_private =
			sipe_media_stream_get_data(stream);
	struct sipe_backend_fd *fd;

	buffer[len] = 0;
	SIPE_DEBUG_INFO("Received new stream for requestId : %s", buffer);

	if (!create_pipe(ft_private->backend_pipe)) {
		SIPE_DEBUG_ERROR_NOFORMAT("Couldn't create backend pipe");
		sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER);
		return;
	}

	fd = sipe_backend_fd_from_int(ft_private->backend_pipe[0]);
	sipe_backend_ft_start(SIPE_FILE_TRANSFER, fd, NULL, 0);
	sipe_backend_fd_free(fd);
}

static void
xdata_end_of_stream_cb(SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
		       guint8 *buffer, gsize len)
{
	buffer[len] = 0;
	SIPE_DEBUG_INFO("Received end of stream for requestId : %s", buffer);
}

static void
xdata_got_header_cb(struct sipe_media_stream *stream,
		    guint8 *buffer,
		    SIPE_UNUSED_PARAMETER gsize len)
{
	struct sipe_file_transfer_lync *ft_private =
			sipe_media_stream_get_data(stream);

	guint8 type = buffer[0];
	guint16 size = (buffer[1] << 8) + buffer[2]; /* stored as big-endian */

	switch (type) {
		case SIPE_XDATA_START_OF_STREAM:
			sipe_media_stream_read_async(stream,
						     ft_private->buffer, size,
						     xdata_start_of_stream_cb);
			break;
		case SIPE_XDATA_DATA_CHUNK:
			SIPE_DEBUG_INFO("Received new data chunk of size %d",
					size);
			ft_private->bytes_left_in_chunk = size;
			break;
			/* We'll read the data when read_cb is called again. */
		case SIPE_XDATA_END_OF_STREAM:
			sipe_media_stream_read_async(stream,
						     ft_private->buffer, size,
						     xdata_end_of_stream_cb);
			break;
	}
}

static void
read_cb(struct sipe_media_stream *stream)
{
	struct sipe_file_transfer_lync *ft_private =
			sipe_media_stream_get_data(stream);

	if (ft_private->buffer_read_pos < ft_private->buffer_len) {
		/* Have data in buffer, write them to the backend. */

		gpointer buffer;
		size_t len;
		ssize_t written;

		buffer = ft_private->buffer + ft_private->buffer_read_pos;
		len = ft_private->buffer_len - ft_private->buffer_read_pos;
		written = write(ft_private->backend_pipe[1], buffer, len);

		if (written > 0) {
			ft_private->buffer_read_pos += written;
		} else if (written < 0 && errno != EAGAIN) {
			SIPE_DEBUG_ERROR_NOFORMAT("Error while writing into "
						  "backend pipe");
			sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER);
			return;
		}
	} else if (ft_private->bytes_left_in_chunk != 0) {
		/* Have data from the sender, replenish our buffer with it. */

		ft_private->buffer_len = MIN(ft_private->bytes_left_in_chunk,
					     sizeof (ft_private->buffer));

		ft_private->buffer_len =
				sipe_backend_media_stream_read(stream,
							       ft_private->buffer,
							       ft_private->buffer_len);

		ft_private->bytes_left_in_chunk -= ft_private->buffer_len;
		ft_private->buffer_read_pos = 0;

		SIPE_DEBUG_INFO("Read %d bytes. %d left in this chunk.",
				ft_private->buffer_len, ft_private->bytes_left_in_chunk);
	} else {
		/* No data available. This is either stream start, beginning of
		 * chunk, or stream end. */

		sipe_media_stream_read_async(stream, ft_private->buffer,
					     XDATA_HEADER_SIZE,
					     xdata_got_header_cb);
	}
}

static void
ft_lync_incoming_init(struct sipe_file_transfer *ft,
		      SIPE_UNUSED_PARAMETER const gchar *filename,
		      SIPE_UNUSED_PARAMETER gsize size,
		      SIPE_UNUSED_PARAMETER const gchar *who)
{
	struct sipe_media_call *call = SIPE_FILE_TRANSFER_PRIVATE->call;

	if (call) {
		sipe_backend_media_accept(call->backend_private, TRUE);
	}
}

static void
ft_lync_request_denied(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_lync *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sipe_media_call *call;

	g_return_if_fail(ft_private);

	call = ft_private->call;

	if (call && call->backend_private) {
		sipe_backend_media_reject(call->backend_private, TRUE);
	}
}

static struct sipe_file_transfer_lync *
ft_private_from_call(struct sipe_media_call *call)
{
	struct sipe_media_stream *stream =
			sipe_core_media_get_stream_by_id(call, "data");
	g_return_val_if_fail(stream, NULL);

	return sipe_media_stream_get_data(stream);
}

static void
send_transfer_progress(struct sipe_file_transfer_lync *ft_private)
{
	static const gchar *FILETRANSFER_PROGRESS =
			"<notify xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" notifyId=\"%d\">"
				"<fileTransferProgress>"
					"<transferId>%d</transferId>"
					"<bytesReceived>"
						"<from>0</from>"
						"<to>%d</to>"
					"</bytesReceived>"
				"</fileTransferProgress>"
			"</notify>";

	send_ms_filetransfer_msg(g_strdup_printf(FILETRANSFER_PROGRESS,
						 rand(),
						 ft_private->request_id,
						 ft_private->file_size - 1),
				 ft_private, NULL);
}

static gboolean
ft_lync_end(struct sipe_file_transfer *ft)
{
	send_transfer_progress(SIPE_FILE_TRANSFER_PRIVATE);

	return TRUE;
}

static void
call_reject_cb(struct sipe_media_call *call, gboolean local)
{
	struct sipe_file_transfer_lync *ft_private = ft_private_from_call(call);
	g_return_if_fail(ft_private);

	if (ft_private->call_reject_parent_cb) {
		ft_private->call_reject_parent_cb(call, local);
	}

	if (!local) {
		sipe_backend_ft_cancel_remote(&ft_private->public);
	}
}

static void
ft_lync_incoming_cancelled(struct sipe_file_transfer *ft)
{
	static const gchar *FILETRANSFER_CANCEL_REQUEST =
			"<request xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" requestId=\"%d\"/>"
				"<cancelTransfer>"
					"<transferId>%d</transferId>"
					"<fileInfo>"
						"<id>%s</id>"
						"<name>%s</name>"
					"</fileInfo>"
				"</cancelTransfer>"
			"</request>";

	struct sipe_file_transfer_lync *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sipe_media_stream *stream;

	send_ms_filetransfer_msg(g_strdup_printf(FILETRANSFER_CANCEL_REQUEST,
						 ft_private->request_id + 1,
						 ft_private->request_id,
						 ft_private->id,
						 ft_private->file_name),
				 ft_private,
				 NULL);

	stream = sipe_core_media_get_stream_by_id(ft_private->call, "data");
	if (stream) {
		stream->read_cb = NULL;
	}

	sipe_backend_media_hangup(ft_private->call->backend_private, FALSE);
}

void
process_incoming_invite_ft_lync(struct sipe_core_private *sipe_private,
				struct sipmsg *msg)
{
	struct sipe_file_transfer_lync *ft_private;
	struct sipe_media_call *call;
	struct sipe_media_stream *stream;

	ft_private = g_new0(struct sipe_file_transfer_lync, 1);
	sipe_mime_parts_foreach(sipmsg_find_header(msg, "Content-Type"),
				msg->body, mime_mixed_cb, ft_private);

	if (!ft_private->file_name || !ft_private->file_size || !ft_private->sdp) {
		sip_transport_response(sipe_private, msg, 488, "Not Acceptable Here", NULL);
		sipe_file_transfer_lync_free(ft_private);
		return;
	}

	call = process_incoming_invite_call(sipe_private, msg,
					    sdpmsg_parse_msg(ft_private->sdp));
	if (!call) {
		sip_transport_response(sipe_private, msg, 500, "Server Internal Error", NULL);
		sipe_file_transfer_lync_free(ft_private);
		return;
	}

	ft_private->call = call;

	ft_private->public.ft_init = ft_lync_incoming_init;
	ft_private->public.ft_request_denied = ft_lync_request_denied;
	ft_private->public.ft_cancelled = ft_lync_incoming_cancelled;
	ft_private->public.ft_end = ft_lync_end;

	ft_private->call_reject_parent_cb = call->call_reject_cb;
	call->call_reject_cb = call_reject_cb;

	stream = sipe_core_media_get_stream_by_id(call, "data");
	stream->candidate_pairs_established_cb = candidate_pairs_established_cb;
	stream->read_cb = read_cb;
	sipe_media_stream_add_extra_attribute(stream, "recvonly", NULL);
	sipe_media_stream_set_data(stream, ft_private,
				   (GDestroyNotify)sipe_file_transfer_lync_free);

	sipe_backend_ft_incoming(SIPE_CORE_PUBLIC, SIPE_FILE_TRANSFER,
				 call->with, ft_private->file_name,
				 ft_private->file_size);
}

static void
process_response_incoming(struct sipe_file_transfer_lync *ft_private,
			  sipe_xml *xml)
{
	const gchar *attr;
	guint request_id = sipe_xml_int_attribute(xml, "requestId", 0);

	if (request_id != ft_private->request_id) {
		return;
	}

	attr = sipe_xml_attribute(xml, "code");
	if (sipe_strequal(attr, "failure")) {
		const gchar *reason = sipe_xml_attribute(xml, "reason");
		if (sipe_strequal(reason, "requestCancelled")) {
			sipe_backend_ft_cancel_remote(SIPE_FILE_TRANSFER);
		}
	}
}

static void
write_chunk(struct sipe_media_stream *stream,
	    guint8 type, guint16 len, const gchar *buffer)
{
	guint16 len_be = GUINT16_TO_BE(len);

	sipe_media_stream_write(stream, &type, sizeof (guint8));
	sipe_media_stream_write(stream, (guint8 *)&len_be, sizeof (guint16));
	sipe_media_stream_write(stream, (guint8 *)buffer, len);
}

static gboolean
send_file_chunk(SIPE_UNUSED_PARAMETER GIOChannel *source,
		SIPE_UNUSED_PARAMETER GIOCondition condition,
		gpointer data)
{
	struct sipe_file_transfer_lync *ft_private = data;
	struct sipe_media_call *call = ft_private->call;
	struct sipe_media_stream *stream;
	gssize bytes_read;

	stream = sipe_core_media_get_stream_by_id(call, "data");
	if (!stream) {
		SIPE_DEBUG_ERROR_NOFORMAT("Couldn't find data stream");
		sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER);
		ft_private->backend_pipe_write_source_id = 0;
		return FALSE; /* G_SOURCE_REMOVE */
	}

	if (!sipe_media_stream_is_writable(stream)) {
		return TRUE; /* G_SOURCE_CONTINUE */
	}

	bytes_read = read(ft_private->backend_pipe[0],
			  ft_private->buffer, sizeof (ft_private->buffer));
	if (bytes_read > 0) {
		write_chunk(stream, SIPE_XDATA_DATA_CHUNK,
			    bytes_read, (const gchar *)ft_private->buffer);
	} else if (bytes_read == 0) {
		/* EOF, write end of stream */
		gchar *request_id_str;

		request_id_str = g_strdup_printf("%u", ft_private->request_id);
		write_chunk(stream, SIPE_XDATA_END_OF_STREAM,
			    strlen(request_id_str), request_id_str);
		g_free(request_id_str);

		return FALSE; /* G_SOURCE_REMOVE */
	}

	return TRUE; /* G_SOURCE_CONTINUE */
}

static void
start_writing(struct sipe_file_transfer_lync *ft_private)
{
	struct sipe_media_stream *stream;
	gchar *request_id_str;
	struct sipe_backend_fd *fd;
	GIOChannel *channel;

	stream = sipe_core_media_get_stream_by_id(ft_private->call, "data");
	if (!stream) {
		return;
	}

	if (!create_pipe(ft_private->backend_pipe)) {
		SIPE_DEBUG_ERROR_NOFORMAT("Couldn't create backend pipe");
		sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER);
		return;
	}

	request_id_str = g_strdup_printf("%u", ft_private->request_id);
	write_chunk(stream, SIPE_XDATA_START_OF_STREAM,
		    strlen(request_id_str), request_id_str);
	g_free(request_id_str);

	channel = g_io_channel_unix_new(ft_private->backend_pipe[0]);
	ft_private->backend_pipe_write_source_id = g_io_add_watch(channel,
								  G_IO_IN | G_IO_HUP,
								  send_file_chunk,
								  ft_private);
	g_io_channel_unref(channel);

	fd = sipe_backend_fd_from_int(ft_private->backend_pipe[1]);
	sipe_backend_ft_start(SIPE_FILE_TRANSFER, fd, NULL, 0);
	sipe_backend_fd_free(fd);
}

static void
process_request(struct sipe_file_transfer_lync *ft_private, sipe_xml *xml)
{
	static const gchar *DOWNLOAD_PENDING_RESPONSE =
			"<response xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" "
			  "requestId=\"%u\" code=\"pending\"/>";

	if (sipe_xml_child(xml, "downloadFile")) {
		ft_private->request_id =
				atoi(sipe_xml_attribute(xml, "requestId"));

		send_ms_filetransfer_msg(g_strdup_printf(DOWNLOAD_PENDING_RESPONSE,
							 ft_private->request_id),
					 ft_private, NULL);

		start_writing(ft_private);
	}
}

static void
process_notify(struct sipe_file_transfer_lync *ft_private, sipe_xml *xml)
{
	static const gchar *DOWNLOAD_SUCCESS_RESPONSE =
		"<response xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" "
		  "requestId=\"%u\" code=\"success\"/>";

	const sipe_xml *progress_node = sipe_xml_child(xml, "fileTransferProgress");

	if (progress_node) {
		gchar *to_str = sipe_xml_data(sipe_xml_child(progress_node, "bytesReceived/to"));

		if (atoi(to_str) == (int)(ft_private->file_size - 1)) {
			send_ms_filetransfer_msg(g_strdup_printf(DOWNLOAD_SUCCESS_RESPONSE,
								 ft_private->request_id),
						 ft_private, NULL);
			sipe_backend_media_hangup(ft_private->call->backend_private, TRUE);
		}
		g_free(to_str);
	}
}

void
process_incoming_info_ft_lync(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	struct sipe_media_call *call;
	struct sipe_file_transfer_lync *ft_private;
	sipe_xml *xml;

	call = g_hash_table_lookup(sipe_private->media_calls,
				   sipmsg_find_header(msg, "Call-ID"));
	if (!call) {
		return;
	}

	ft_private = ft_private_from_call(call);
	if (!ft_private) {
		return;
	}

	xml = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xml) {
		return;
	}

	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	if (sipe_backend_ft_is_incoming(SIPE_FILE_TRANSFER)) {
		if (sipe_strequal(sipe_xml_name(xml), "response")) {
			process_response_incoming(ft_private, xml);
		}
	} else {
		if (sipe_strequal(sipe_xml_name(xml), "request")) {
			process_request(ft_private, xml);
		} else if (sipe_strequal(sipe_xml_name(xml), "notify")) {
			process_notify(ft_private, xml);
		}
	}

	sipe_xml_free(xml);
}

static void
append_publish_file_invite(struct sipe_media_call *call,
			   struct sipe_file_transfer_lync *ft_private)
{
	static const gchar *PUBLISH_FILE_REQUEST =
			"Content-Type: application/ms-filetransfer+xml\r\n"
			"Content-Transfer-Encoding: 7bit\r\n"
			"Content-Disposition: render; handling=optional\r\n"
			"\r\n"
			"<request xmlns=\"http://schemas.microsoft.com/rtc/2009/05/filetransfer\" "
			  "requestId=\"%u\">"
				"<publishFile>"
					"<fileInfo>"
						"<id>{6244F934-2EB1-443F-8E2C-48BA64AF463D}</id>"
						"<name>%s</name>"
						"<size>%u</size>"
					"</fileInfo>"
				"</publishFile>"
			"</request>\r\n";
	gchar *body;

	ft_private->request_id =
			++ft_private->sipe_private->ms_filetransfer_request_id;

	body = g_strdup_printf(PUBLISH_FILE_REQUEST, ft_private->request_id,
			       ft_private->file_name, ft_private->file_size);

	sipe_media_add_extra_invite_section(call, "multipart/mixed", body);
}

static void
ft_lync_outgoing_init(struct sipe_file_transfer *ft, const gchar *filename,
		      gsize size, SIPE_UNUSED_PARAMETER const gchar *who)
{
	struct sipe_core_private *sipe_private =
			SIPE_FILE_TRANSFER_PRIVATE->sipe_private;
	struct sipe_file_transfer_lync *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sipe_media_call *call;
	struct sipe_media_stream *stream;

	ft_private->file_name = g_strdup(filename);
	ft_private->file_size = size;

	call = sipe_media_call_new(sipe_private, who, NULL, SIPE_ICE_RFC_5245,
				   SIPE_MEDIA_CALL_NO_UI);

	ft_private->call = call;

	ft_private->call_reject_parent_cb = call->call_reject_cb;
	call->call_reject_cb = call_reject_cb;

	stream = sipe_media_stream_add(call, "data", SIPE_MEDIA_APPLICATION,
				       SIPE_ICE_RFC_5245, TRUE, 0);
	if (!stream) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Error occurred"),
					  _("Error creating data stream"));

		sipe_backend_media_hangup(call->backend_private, FALSE);
		sipe_backend_ft_cancel_local(ft);
		return;
	}

	sipe_media_stream_add_extra_attribute(stream, "sendonly", NULL);
	sipe_media_stream_add_extra_attribute(stream, "mid", "1");
	sipe_media_stream_set_data(stream, ft,
				   (GDestroyNotify)sipe_file_transfer_lync_free);
	append_publish_file_invite(call, ft_private);
}

struct sipe_file_transfer *
sipe_file_transfer_lync_new_outgoing(struct sipe_core_private *sipe_private)
{
	struct sipe_file_transfer_lync *ft_private;

	ft_private = g_new0(struct sipe_file_transfer_lync, 1);

	ft_private->sipe_private = sipe_private;
	ft_private->public.ft_init = ft_lync_outgoing_init;

	return SIPE_FILE_TRANSFER;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
