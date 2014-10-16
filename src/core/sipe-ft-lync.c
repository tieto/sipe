/**
 * @file sipe-ft-lync.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipmsg.h"

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

	struct sipe_media_call *call;
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
	if (ft_private->backend_pipe[1] != 0) {
		// Backend is responsible for closing the pipe's read end.
		close(ft_private->backend_pipe[1]);
	}

	g_free(ft_private->file_name);
	g_free(ft_private->sdp);
	g_free(ft_private->id);
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
		const sipe_xml *node;

		const gchar *request_id_str = sipe_xml_attribute(xml, "requestId");
		if (request_id_str) {
			ft_private->request_id = atoi(request_id_str);
		}

		node = sipe_xml_child(xml, "publishFile/fileInfo/name");
		if (node) {
			ft_private->file_name = sipe_xml_data(node);
		}

		node = sipe_xml_child(xml, "publishFile/fileInfo/id");
		if (node) {
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
	} else if (g_str_has_prefix(ctype, "application/sdp")) {
		ft_private->sdp = g_strndup(body, length);
	}
}

static void
candidate_pair_established_cb(SIPE_UNUSED_PARAMETER struct sipe_media_call *call,
			      struct sipe_media_stream *stream)
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

	fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
	fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);

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
	guint16 size = GUINT16_FROM_BE(*(guint16 *)(buffer + sizeof (guint8)));

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
ft_lync_deallocate(struct sipe_file_transfer *ft)
{
	struct sipe_media_call *call = SIPE_FILE_TRANSFER_PRIVATE->call;

	if (call) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
	}
	sipe_file_transfer_lync_free(SIPE_FILE_TRANSFER_PRIVATE);
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

	/* Replace multipart message body with the selected SDP part and
	 * initialize media session as if invited to a media call. */
	g_free(msg->body);
	msg->body = ft_private->sdp;
	msg->bodylen = strlen(msg->body);
	ft_private->sdp = NULL;

	ft_private->call = process_incoming_invite_call(sipe_private, msg);
	if (!ft_private->call) {
		sip_transport_response(sipe_private, msg, 500, "Server Internal Error", NULL);
		sipe_file_transfer_lync_free(ft_private);
		return;
	}

	call = ft_private->call;
	call->candidate_pair_established_cb = candidate_pair_established_cb;

	ft_private->public.ft_init = ft_lync_incoming_init;
	ft_private->public.ft_end = ft_lync_end;
	ft_private->public.ft_deallocate = ft_lync_deallocate;

	stream = sipe_core_media_get_stream_by_id(call, "data");
	stream->read_cb = read_cb;
	sipe_media_stream_add_extra_attribute(stream, "recvonly", NULL);
	sipe_media_stream_set_data(stream, ft_private, NULL);

	sipe_backend_ft_incoming(SIPE_CORE_PUBLIC, SIPE_FILE_TRANSFER,
				 call->with, ft_private->file_name,
				 ft_private->file_size);
}

void
process_incoming_info_ft_lync(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	sip_transport_response(sipe_private, msg, 200, "OK", NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
