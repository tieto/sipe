/**
 * @file purple-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 Jakub Adam <jakub.adam@tieto.com>
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
#include <time.h>

#include <glib.h>

#include "connection.h"
#include "eventloop.h"
#include "ft.h"
#include "network.h"
#include "request.h"

#ifdef _WIN32
/* for network */
#include "win32/libc_interface.h"
#include <nspapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h> /* SIOCGIFCONF for Solaris */
#endif
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

struct sipe_backend_file_transfer {
	PurpleXfer *xfer;
	PurpleNetworkListenData *listener;
	int listenfd;
};
#define PURPLE_XFER_TO_SIPE_FILE_TRANSFER ((struct sipe_file_transfer *) xfer->data)
#define PURPLE_XFER_TO_SIPE_CORE_PUBLIC   ((struct sipe_core_public *) xfer->account->gc->proto_data)

void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const char *errmsg)
{
	PurpleXfer *xfer = ft->backend_private->xfer;
 	purple_xfer_error(purple_xfer_get_type(xfer),
			  xfer->account, xfer->who,
			  errmsg);
}

const gchar *sipe_backend_ft_get_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft)
{
	return strerror(errno);
}

void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft)
{
	struct sipe_backend_file_transfer *backend_ft = ft->backend_private;
	PurpleXfer *xfer = backend_ft->xfer;
	PurpleXferStatusType status = purple_xfer_get_status(xfer);

	if (backend_ft->listenfd >= 0) {
		SIPE_DEBUG_INFO("sipe_ft_free_xfer_struct: closing listening socket %d",
				backend_ft->listenfd);
		close(backend_ft->listenfd);
	}
	if (backend_ft->listener)
		purple_network_listen_cancel(backend_ft->listener);

	// If file transfer is not finished, cancel it
	if (   status != PURPLE_XFER_STATUS_DONE
		&& status != PURPLE_XFER_STATUS_CANCEL_LOCAL
		&& status != PURPLE_XFER_STATUS_CANCEL_REMOTE) {
		purple_xfer_set_cancel_recv_fnc(xfer, NULL);
		purple_xfer_set_cancel_send_fnc(xfer, NULL);
		purple_xfer_cancel_remote(xfer);
	}

	g_free(backend_ft);
}

gssize sipe_backend_ft_read(struct sipe_file_transfer *ft,
			    guchar *data,
			    gsize size)
{
	gssize bytes_read = read(ft->backend_private->xfer->fd, data, size);
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
	gssize bytes_written = write(ft->backend_private->xfer->fd,
				     data, size);
	if (bytes_written == -1) {
		if (errno == EAGAIN)
			return 0;
		else
			return -1;
	}
	return bytes_written;
}

void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft)
{
	purple_xfer_cancel_local(ft->backend_private->xfer);
}

void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft)
{
	purple_xfer_cancel_remote(ft->backend_private->xfer);
}

static void
sipe_purple_ft_free_xfer_struct(PurpleXfer *xfer)
{
	struct sipe_file_transfer *ft = PURPLE_XFER_TO_SIPE_FILE_TRANSFER;

	if (ft) {
		if (xfer->watcher) {
			purple_input_remove(xfer->watcher);
			xfer->watcher = 0;
		}
		sipe_core_ft_deallocate(ft);
		xfer->data = NULL;
	}
}

static void
sipe_purple_ft_request_denied(PurpleXfer *xfer)
{
	if (xfer->type == PURPLE_XFER_RECEIVE)
		sipe_core_ft_cancel(PURPLE_XFER_TO_SIPE_FILE_TRANSFER);
	sipe_purple_ft_free_xfer_struct(xfer);
}

static void
sipe_purple_ft_incoming_init(PurpleXfer *xfer)
{
	sipe_core_ft_incoming_init(PURPLE_XFER_TO_SIPE_FILE_TRANSFER);
}

static void
sipe_purple_ft_incoming_start(PurpleXfer *xfer)
{
	sipe_core_ft_incoming_start(PURPLE_XFER_TO_SIPE_FILE_TRANSFER,
				    xfer->size);
}

static void
sipe_purple_ft_incoming_stop(PurpleXfer *xfer)
{
	if (sipe_core_ft_incoming_stop(PURPLE_XFER_TO_SIPE_FILE_TRANSFER)) {
		/* We're done with this transfer */
		sipe_purple_ft_free_xfer_struct(xfer);
	} else {
		unlink(xfer->local_filename);
	}
}

static gssize
sipe_purple_ft_read(guchar **buffer, PurpleXfer *xfer)
{
	return sipe_core_ft_read(PURPLE_XFER_TO_SIPE_FILE_TRANSFER,
				 buffer,
				 purple_xfer_get_bytes_remaining(xfer),
				 xfer->current_buffer_size);
}

static void
sipe_purple_ft_outgoing_init(PurpleXfer *xfer)
{
	sipe_core_ft_outgoing_init(PURPLE_XFER_TO_SIPE_FILE_TRANSFER,
				   purple_xfer_get_filename(xfer),
				   purple_xfer_get_size(xfer),
				   xfer->who); 
}

static void
sipe_purple_ft_outgoing_start(PurpleXfer *xfer)
{
	/* Set socket to non-blocking mode */
	int flags = fcntl(xfer->fd, F_GETFL, 0);
	if (flags == -1)
		flags = 0;
	fcntl(xfer->fd, F_SETFL, flags | O_NONBLOCK);

	sipe_core_ft_outgoing_start(PURPLE_XFER_TO_SIPE_FILE_TRANSFER,
				    xfer->size); 
}

static void
sipe_purple_ft_outgoing_stop(PurpleXfer *xfer)
{
	if (sipe_core_ft_outgoing_stop(PURPLE_XFER_TO_SIPE_FILE_TRANSFER)) {
		/* We're done with this transfer */
		sipe_purple_ft_free_xfer_struct(xfer);
	}
}

static gssize
sipe_purple_ft_write(const guchar *buffer, size_t size, PurpleXfer *xfer)
{
	gssize bytes_written = sipe_core_ft_write(PURPLE_XFER_TO_SIPE_FILE_TRANSFER,
						  buffer,
						  size);

	if ((xfer->bytes_remaining - bytes_written) == 0)
		purple_xfer_set_completed(xfer, TRUE);

	return bytes_written;
}

//******************************************************************************

static void sipe_backend_private_init(struct sipe_file_transfer *ft,
				      PurpleXfer *xfer)
{
	struct sipe_backend_file_transfer *backend_ft = g_new0(struct sipe_backend_file_transfer, 1);

	ft->backend_private = backend_ft;
	backend_ft->xfer = xfer;
	backend_ft->listenfd = -1;

	xfer->data = ft;
}

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleXfer *xfer;

	xfer = purple_xfer_new(purple_private->account,
			       PURPLE_XFER_RECEIVE,
			       who);

	if (xfer) {
		sipe_backend_private_init(ft, xfer);

		purple_xfer_set_filename(xfer, file_name);
		purple_xfer_set_size(xfer, file_size);

		purple_xfer_set_init_fnc(xfer,  sipe_purple_ft_incoming_init);
		purple_xfer_set_start_fnc(xfer, sipe_purple_ft_incoming_start);
		purple_xfer_set_end_fnc(xfer,   sipe_purple_ft_incoming_stop);
		purple_xfer_set_request_denied_fnc(xfer, sipe_purple_ft_request_denied);
		purple_xfer_set_read_fnc(xfer,  sipe_purple_ft_read);
		purple_xfer_set_cancel_send_fnc(xfer, sipe_purple_ft_free_xfer_struct);
		purple_xfer_set_cancel_recv_fnc(xfer, sipe_purple_ft_free_xfer_struct);

		purple_xfer_request(xfer);
	}
}

static
void sipe_purple_ft_client_connected(gpointer data, gint listenfd,
			      SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_file_transfer *ft = data;
	struct sipe_backend_file_transfer *backend_ft = ft->backend_private;
	PurpleXfer *xfer = backend_ft->xfer;
	struct sockaddr_in saddr;
	socklen_t slen = sizeof (saddr);

	int fd = accept(listenfd, (struct sockaddr*)&saddr, &slen);

	purple_input_remove(xfer->watcher);
	xfer->watcher = 0;
	close(listenfd);
	backend_ft->listenfd = -1;

	if (fd < 0) {
		sipe_backend_ft_error(ft, _("Socket read failed"));
		sipe_backend_ft_cancel_local(ft);
	} else {
		purple_xfer_start(xfer, fd, NULL, 0);
	}
}

static
void sipe_purple_ft_listen_socket_created(int listenfd, gpointer data)
{
	struct sipe_file_transfer *ft = data;
	struct sipe_backend_file_transfer *backend_ft = ft->backend_private;
	struct sockaddr_in addr;
	socklen_t socklen = sizeof (addr);

	backend_ft->listener = NULL;
	backend_ft->listenfd = listenfd;

	getsockname(listenfd, (struct sockaddr*)&addr, &socklen);

	backend_ft->xfer->watcher = purple_input_add(listenfd,
						     PURPLE_INPUT_READ,
						     sipe_purple_ft_client_connected,
						     ft);

	sipe_core_ft_incoming_accept(ft,
				     backend_ft->xfer->who,
				     listenfd,
				     ntohs(addr.sin_port));
}

gboolean sipe_backend_ft_incoming_accept(struct sipe_file_transfer *ft,
					 const gchar *ip,
					 unsigned short port_min,
					 unsigned short port_max)
{
	struct sipe_backend_file_transfer *backend_ft = ft->backend_private;

	if (ip && (port_min == port_max)) {
		purple_xfer_start(backend_ft->xfer, -1, ip, port_min);
	} else {
		backend_ft->listener = purple_network_listen_range(port_min,
								   port_max,
								   SOCK_STREAM,
								   sipe_purple_ft_listen_socket_created,
								   ft);
		if (!backend_ft->listener)
			return FALSE;
	}
	return(TRUE);
}

void sipe_purple_ft_send_file(PurpleConnection *gc,
			      const char *who,
			      const char *file)
{
	PurpleXfer *xfer = sipe_purple_ft_new_xfer(gc, who);

	if (xfer) {
		if (file != NULL)
			purple_xfer_request_accepted(xfer, file);
		else
			purple_xfer_request(xfer);
	}
}

PurpleXfer *sipe_purple_ft_new_xfer(PurpleConnection *gc, const char *who)
{
	PurpleXfer *xfer = NULL;

	if (PURPLE_CONNECTION_IS_VALID(gc)) {
		xfer = purple_xfer_new(purple_connection_get_account(gc),
				       PURPLE_XFER_SEND, who);

		if (xfer) {
			struct sipe_file_transfer *ft = sipe_core_ft_allocate(PURPLE_GC_TO_SIPE_CORE_PUBLIC);

			sipe_backend_private_init(ft, xfer);

			purple_xfer_set_init_fnc(xfer,  sipe_purple_ft_outgoing_init);
			purple_xfer_set_start_fnc(xfer, sipe_purple_ft_outgoing_start);
			purple_xfer_set_end_fnc(xfer,   sipe_purple_ft_outgoing_stop);
			purple_xfer_set_request_denied_fnc(xfer, sipe_purple_ft_request_denied);
			purple_xfer_set_write_fnc(xfer, sipe_purple_ft_write);
			purple_xfer_set_cancel_send_fnc(xfer, sipe_purple_ft_free_xfer_struct);
			purple_xfer_set_cancel_recv_fnc(xfer, sipe_purple_ft_free_xfer_struct);
		}
	}

	return xfer;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
