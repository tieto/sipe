/**
 * @file purple-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 Jakub Adam <jakub.adam@ktknet.cz>
 * Copyright (C) 2010 Tomáš Hrabčík <tomas.hrabcik@tieto.com>
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

#include <string.h>
#include <fcntl.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "protocol.h"
#define PURPLE_XFER_TO_SIPE_CORE_PUBLIC        ((struct sipe_core_public *) purple_connection_get_protocol_data(purple_account_get_connection(purple_xfer_get_account(xfer))))
#else
#include "ft.h"
#define PurpleXferStatus                       PurpleXferStatusType
#define PURPLE_XFER_TO_SIPE_CORE_PUBLIC        ((struct sipe_core_public *) purple_account_get_connection(xfer->account)->proto_data)
#define PURPLE_XFER_TYPE_RECEIVE               PURPLE_XFER_RECEIVE
#define PURPLE_XFER_TYPE_SEND                  PURPLE_XFER_SEND
#define purple_xfer_get_fd(xfer)               xfer->fd
#define purple_xfer_get_protocol_data(xfer)    xfer->data
#define purple_xfer_get_status(xfer)           purple_xfer_get_status(xfer)
#define purple_xfer_get_xfer_type(xfer)        purple_xfer_get_type(xfer)
#define purple_xfer_get_watcher(xfer)          xfer->watcher
#define purple_xfer_set_protocol_data(xfer, d) xfer->data = d
#define purple_xfer_set_watcher(xfer, w)       xfer->watcher = w
#endif

#ifdef _WIN32
/* wrappers for write() & friends for socket handling */
#include "win32/win32dep.h"
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

#define FT_TO_PURPLE_XFER                      ((PurpleXfer *) ft->backend_private)
#define PURPLE_XFER_TO_SIPE_FILE_TRANSFER      ((struct sipe_file_transfer *) purple_xfer_get_protocol_data(xfer))

void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const char *errmsg)
{
	PurpleXfer *xfer = FT_TO_PURPLE_XFER;
	purple_xfer_error(purple_xfer_get_xfer_type(xfer),
			  purple_xfer_get_account(xfer),
			  purple_xfer_get_remote_user(xfer),
			  errmsg);
}

const gchar *sipe_backend_ft_get_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft)
{
	return strerror(errno);
}

void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft)
{
	PurpleXfer *xfer = FT_TO_PURPLE_XFER;
	PurpleXferStatus status = purple_xfer_get_status(xfer);

	// If file transfer is not finished, cancel it
	if (   status != PURPLE_XFER_STATUS_DONE
		&& status != PURPLE_XFER_STATUS_CANCEL_LOCAL
		&& status != PURPLE_XFER_STATUS_CANCEL_REMOTE) {
		purple_xfer_set_cancel_recv_fnc(xfer, NULL);
		purple_xfer_set_cancel_send_fnc(xfer, NULL);
		purple_xfer_cancel_remote(xfer);
	}
}

gssize sipe_backend_ft_read(struct sipe_file_transfer *ft,
			    guchar *data,
			    gsize size)
{
	gssize bytes_read = read(purple_xfer_get_fd(FT_TO_PURPLE_XFER),
				 data,
				 size);
	if (bytes_read == 0) {
		/* Sender canceled transfer before it was finished */
		return -2;
	} else if (bytes_read == -1) {
		if (errno == EAGAIN)
			return 0;
		else
			return -1;
	}
	return bytes_read;
}

gssize sipe_backend_ft_write(struct sipe_file_transfer *ft,
			     const guchar *data,
			     gsize size)
{
	gssize bytes_written = write(purple_xfer_get_fd(FT_TO_PURPLE_XFER),
				     data,
				     size);
	if (bytes_written == -1) {
		if (errno == EAGAIN)
			return 0;
		else
			return -1;
	}
	return bytes_written;
}

static gboolean
end_transfer_cb(gpointer data)
{
	purple_xfer_end((PurpleXfer *)data);
	return FALSE;
}

void
sipe_backend_ft_set_completed(struct sipe_file_transfer *ft)
{
	purple_xfer_set_completed(FT_TO_PURPLE_XFER, TRUE);
	g_timeout_add(0, end_transfer_cb, FT_TO_PURPLE_XFER);
}

void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft)
{
	purple_xfer_cancel_local(FT_TO_PURPLE_XFER);
}

void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft)
{
	purple_xfer_cancel_remote(FT_TO_PURPLE_XFER);
}

static void
ft_free_xfer_struct(PurpleXfer *xfer)
{
	if (purple_xfer_get_watcher(xfer)) {
		purple_input_remove(purple_xfer_get_watcher(xfer));
		purple_xfer_set_watcher(xfer, 0);
	}

	purple_xfer_set_protocol_data(xfer, NULL);
}

static void
ft_request_denied(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;
	if (ft->ft_request_denied) {
		ft->ft_request_denied(ft);
	}

	ft_free_xfer_struct(xfer);
}

static void
ft_cancelled(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;

	if (ft->ft_cancelled &&
	    purple_xfer_get_status(xfer) == PURPLE_XFER_STATUS_CANCEL_LOCAL) {
		ft->ft_cancelled(ft);
	}

	ft_free_xfer_struct(xfer);
}

static void
ft_init(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;
	g_return_if_fail(ft->ft_init);

	ft->ft_init(ft,
		    purple_xfer_get_filename(xfer),
		    purple_xfer_get_size(xfer),
		    purple_xfer_get_remote_user(xfer));
}

static void
ft_start(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;

	if (purple_xfer_get_xfer_type(xfer) == PURPLE_XFER_TYPE_RECEIVE) {
		/* Set socket to non-blocking mode */
		int flags = fcntl(purple_xfer_get_fd(xfer), F_GETFL, 0);
		if (flags == -1) {
			flags = 0;
		}
		/* @TODO: ignoring potential error return - how to handle? */
		(void) fcntl(purple_xfer_get_fd(xfer), F_SETFL, flags | O_NONBLOCK);
	}

	if (ft->ft_start) {
		ft->ft_start(ft, purple_xfer_get_size(xfer));
	}
}

static void
ft_end(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;

	if (!ft->ft_end || ft->ft_end(ft)) {
		/* We're done with this transfer */
		ft_free_xfer_struct(xfer);
	} else if (purple_xfer_get_xfer_type(xfer) == PURPLE_XFER_TYPE_RECEIVE) {
		/* Remove incomplete file from failed transfer. */
		unlink(purple_xfer_get_local_filename(xfer));
	}
}

static gssize
ft_read(guchar **buffer,
#if PURPLE_VERSION_CHECK(3,0,0)
			size_t buffer_size,
#endif
			PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;
	g_return_val_if_fail(ft->ft_read, 0);
	return ft->ft_read(ft, buffer, purple_xfer_get_bytes_remaining(xfer),
#if PURPLE_VERSION_CHECK(3,0,0)
			   buffer_size
#else
			   xfer->current_buffer_size
#endif
	);
}

static gssize
ft_write(const guchar *buffer, size_t size, PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;
	gssize bytes_written = 0;

	g_return_val_if_fail(ft->ft_write, 0);

	bytes_written = ft->ft_write(ft, buffer, size);

	if ((purple_xfer_get_bytes_remaining(xfer) - bytes_written) == 0)
		purple_xfer_set_completed(xfer, TRUE);

	return bytes_written;
}

static PurpleXfer *
create_xfer(PurpleAccount *account, PurpleXferType type, const char *who,
	    struct sipe_file_transfer *ft)
{
	PurpleXfer *xfer = purple_xfer_new(account, type, who);
	if (xfer) {
		ft->backend_private = (struct sipe_backend_file_transfer *)xfer;

		purple_xfer_set_protocol_data(xfer, ft);
		purple_xfer_set_init_fnc(xfer, ft_init);
		purple_xfer_set_request_denied_fnc(xfer, ft_request_denied);
		purple_xfer_set_cancel_send_fnc(xfer, ft_cancelled);
		purple_xfer_set_cancel_recv_fnc(xfer, ft_cancelled);
		purple_xfer_set_start_fnc(xfer, ft_start);
		purple_xfer_set_end_fnc(xfer, ft_end);
	}

	return xfer;
}

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleXfer *xfer = create_xfer(purple_private->account,
				       PURPLE_XFER_TYPE_RECEIVE, who, ft);
	if (xfer) {
		purple_xfer_set_filename(xfer, file_name);
		purple_xfer_set_size(xfer, file_size);

		purple_xfer_request(xfer);
	}
}

void
sipe_backend_ft_outgoing(struct sipe_core_public *sipe_public,
			 struct sipe_file_transfer *ft,
			 const gchar *who,
			 const gchar *file_name)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleXfer *xfer = create_xfer(purple_private->account,
				       PURPLE_XFER_TYPE_SEND, who, ft);
	if (xfer) {
		if (file_name != NULL)
			purple_xfer_request_accepted(xfer, file_name);
		else
			purple_xfer_request(xfer);
	}
}

static void
connect_cb(gpointer data, gint fd, SIPE_UNUSED_PARAMETER const gchar *error_message)
{
	struct sipe_file_transfer *ft = data;

	if (fd < 0) {
		purple_xfer_cancel_local(FT_TO_PURPLE_XFER);
		return;
	}

	purple_xfer_start(FT_TO_PURPLE_XFER, fd, NULL, 0);
}

void
sipe_backend_ft_start(struct sipe_file_transfer *ft, struct sipe_backend_fd *fd,
		      const char* ip, unsigned port)
{
	PurpleXferType type = purple_xfer_get_xfer_type(FT_TO_PURPLE_XFER);
	if (type == PURPLE_XFER_TYPE_SEND && ft->ft_write) {
		purple_xfer_set_write_fnc(FT_TO_PURPLE_XFER, ft_write);
	} else if (type == PURPLE_XFER_TYPE_RECEIVE && ft->ft_read) {
		purple_xfer_set_read_fnc(FT_TO_PURPLE_XFER, ft_read);
	}

	if (ip && port && !sipe_backend_ft_is_incoming(ft)) {
		/* Purple accepts ip & port only for incoming file transfers.
		 * If we want to send file with Sender-Connect = TRUE negotiated,
		 * we have to open the connection ourselves and pass the file
		 * descriptor to purple_xfer_start. */
		purple_proxy_connect(NULL,
				     purple_xfer_get_account(FT_TO_PURPLE_XFER),
				     ip,
				     port,
				     connect_cb,
				     ft);
		return;
	}

	purple_xfer_start(FT_TO_PURPLE_XFER, fd ? fd->fd : -1, ip, port);
}

void sipe_purple_ft_send_file(PurpleConnection *gc,
			      const char *who,
			      const char *file)
{
	sipe_core_ft_create_outgoing(PURPLE_GC_TO_SIPE_CORE_PUBLIC, who, file);
}

gboolean
sipe_backend_ft_is_incoming(struct sipe_file_transfer *ft)
{
	return(purple_xfer_get_xfer_type(FT_TO_PURPLE_XFER) == PURPLE_XFER_TYPE_RECEIVE);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
