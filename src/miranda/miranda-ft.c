/**
 * @file miranda-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_database.h"
#include "m_protomod.h"
#include "m_netlib.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"
#include "miranda-private.h"

#define FT_SIPE_DEBUG_INFO(fmt, ...)        sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    "[FT:%08x] %s: " fmt, ft, __func__, __VA_ARGS__)
#define FT_SIPE_DEBUG_INFO_NOFORMAT(msg)    sipe_backend_debug(SIPE_DEBUG_LEVEL_INFO,    "[FT:%08x] %s: %s", ft, __func__, msg)

#define FT_INITIAL_BUFFER_SIZE 4096
#define FT_MAX_BUFFER_SIZE     65535

typedef enum
{
	SIPE_MIRANDA_XFER_STATUS_UNKNOWN = 0,   /**< Unknown, the xfer may be null. */
//        SIPE_MIRANDA_XFER_STATUS_NOT_STARTED,   /**< It hasn't started yet. */
//        SIPE_MIRANDA_XFER_STATUS_ACCEPTED,      /**< Receive accepted, but destination file not selected yet */
	SIPE_MIRANDA_XFER_STATUS_STARTED,       /**< purple_xfer_start has been called. */
	SIPE_MIRANDA_XFER_STATUS_DONE,          /**< The xfer completed successfully. */
	SIPE_MIRANDA_XFER_STATUS_CANCEL_LOCAL,  /**< The xfer was cancelled by us. */
        SIPE_MIRANDA_XFER_STATUS_CANCEL_REMOTE  /**< The xfer was cancelled by the other end, or we couldn't connect. */
} sipe_miranda_xfer_status;

struct sipe_backend_file_transfer {
	gboolean incoming;
	HANDLE fd;
	SIPPROTO *pr;
	struct sipe_file_transfer *ft;
	gsize file_size;
	size_t bytes_sent;
	size_t bytes_remaining;
	size_t current_buffer_size;
	struct sipe_miranda_sel_entry *watcher;
	gchar *filename;
	gchar *local_filename;
	FILE *dest_fp;
	HANDLE hContact;
	time_t start_time;
	time_t end_time;
	GByteArray *buffer;
	PROTOFILETRANSFERSTATUS st;
	sipe_miranda_xfer_status status;
};

static void
update_progress(struct sipe_backend_file_transfer *xfer)
{
#if 0
        ZeroMemory(pfts, sizeof(PROTOFILETRANSFERSTATUS));
        pfts->flags = PFTS_UTF | (ft->sending ? PFTS_SENDING : PFTS_RECEIVING); /* Standard FT is Ansi only */
        if (ft->sending)
                pfts->pszFiles = ft->pszFiles;
        else
                pfts->pszFiles = NULL;  /* FIXME */
        pfts->currentFileTime = ft->dwThisFileDate;

#endif
	xfer->st.flags = (xfer->incoming ? PFTS_RECEIVING : PFTS_SENDING);
	xfer->st.szWorkingDir = "none";
	xfer->st.szCurrentFile = xfer->filename;
	xfer->st.totalFiles = 1;
	xfer->st.totalBytes = xfer->file_size;
	xfer->st.totalProgress = xfer->bytes_sent;
	xfer->st.currentFileNumber = 1;
	xfer->st.currentFileSize = xfer->file_size;
	xfer->st.currentFileProgress = xfer->bytes_sent;

	ProtoBroadcastAck(xfer->pr->proto.m_szModuleName,
			  xfer->hContact,
			  ACKTYPE_FILE,
			  ACKRESULT_DATA,
			  (HANDLE)xfer,
			  (LPARAM)&xfer->st);
}

static void
increase_buffer_size(struct sipe_backend_file_transfer *xfer)
{
	xfer->current_buffer_size = MIN(xfer->current_buffer_size * 1.5,
			FT_MAX_BUFFER_SIZE);
}

void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const gchar *errmsg)
{
	gchar *msg;

	FT_SIPE_DEBUG_INFO("file transfer error: <%s>", errmsg);

	if (ft->backend_private->incoming)
	{
		msg = g_strdup_printf("Incoming file transfer failed");
	} else {
		msg = g_strdup_printf("Outgoing file transfer failed");
	}

	sipe_miranda_AddEvent(ft->backend_private->pr, ft->backend_private->hContact, SIPE_EVENTTYPE_ERROR_NOTIFY, time(NULL), DBEF_UTF, strlen(msg), (PBYTE)msg);
	g_free(msg);

}

const gchar *sipe_backend_ft_get_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft)
{
	_NIF();
	return strerror(errno); /* FIXME: Only valid for the file side i think */
}

static void
free_xfer_struct(struct sipe_backend_file_transfer *xfer)
{
	struct sipe_file_transfer *ft = xfer->ft;

	if (ft) {
		if (xfer->watcher) {
			sipe_miranda_input_remove(xfer->watcher);
			xfer->watcher = 0;
		}
		sipe_core_ft_deallocate(ft);
		xfer->ft = NULL;
	}
}

static void
cancel_remote(struct sipe_backend_file_transfer *xfer)
{
	struct sipe_file_transfer *ft = xfer->ft;
	gchar *msg;
	FT_SIPE_DEBUG_INFO_NOFORMAT("");

	if (!xfer) return;

	xfer->status = SIPE_MIRANDA_XFER_STATUS_CANCEL_REMOTE;
        xfer->end_time = time(NULL);

	msg = g_strdup_printf("File transfer cancelled by peer");
	sipe_miranda_AddEvent(ft->backend_private->pr, ft->backend_private->hContact, SIPE_EVENTTYPE_ERROR_NOTIFY, time(NULL), DBEF_UTF, strlen(msg), (PBYTE)msg);
	g_free(msg);

	free_xfer_struct(xfer);

	if (xfer->watcher != 0) {
		sipe_miranda_input_remove(xfer->watcher);
		xfer->watcher = 0;
	}

	if (xfer->fd)
		Netlib_CloseHandle(xfer->fd);

	if (xfer->dest_fp != NULL) {
		fclose(xfer->dest_fp);
		xfer->dest_fp = NULL;
	}

	xfer->bytes_remaining = 0;
	g_free(xfer->filename);
/*	g_free(xfer);  FIXME: needs refcounting like purple i guess */
}

void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft)
{
	struct sipe_backend_file_transfer *xfer = ft->backend_private;

	/* If file transfer is not finished, cancel it */
	if (xfer->status != SIPE_MIRANDA_XFER_STATUS_DONE
	    && xfer->status != SIPE_MIRANDA_XFER_STATUS_CANCEL_LOCAL
	    && xfer->status != SIPE_MIRANDA_XFER_STATUS_CANCEL_REMOTE)
	{
		cancel_remote(xfer);
        }

}

gssize sipe_backend_ft_read(struct sipe_file_transfer *ft,
			    guchar *data,
			    gsize size)
{
	gssize bytes_read;

	FT_SIPE_DEBUG_INFO("reading up to <%d> bytes", size);
	bytes_read = Netlib_Recv(ft->backend_private->fd, data, size, MSG_NODUMP);
	FT_SIPE_DEBUG_INFO("came back from read <%d>", bytes_read);
	if (bytes_read == 0) {
		/* Sender canceled transfer before it was finished */
		FT_SIPE_DEBUG_INFO_NOFORMAT("no read cause sender cancelled");
		return -2;
	} else if (bytes_read == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			return 0;
		} else {
			FT_SIPE_DEBUG_INFO("Error reading <%d>", err);
			return -1;
		}
	}
	FT_SIPE_DEBUG_INFO("read <%d> bytes [%02x:%c]", bytes_read, *data, *data);
	return bytes_read;
}

gssize sipe_backend_ft_write(struct sipe_file_transfer *ft,
			     const guchar *data,
			     gsize size)
{
	int bytes_written;
	FT_SIPE_DEBUG_INFO("writing <%d> bytes", size);
	bytes_written = Netlib_Send(ft->backend_private->fd, data, size, MSG_NODUMP );
	if (bytes_written == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			return 0;
		} else {
			FT_SIPE_DEBUG_INFO("Error writing <%u>", err);
			return -1;
		}
	}
	FT_SIPE_DEBUG_INFO("wrote <%d> bytes", bytes_written);
	return bytes_written;
}

static void
cancel_local(struct sipe_backend_file_transfer *xfer)
{
	struct sipe_file_transfer *ft = xfer->ft;
	gchar *msg;
	FT_SIPE_DEBUG_INFO_NOFORMAT("");

	xfer->status = SIPE_MIRANDA_XFER_STATUS_CANCEL_LOCAL;
	xfer->end_time = time(NULL);

	msg = g_strdup_printf("File transfer cancelled");
	sipe_miranda_AddEvent(ft->backend_private->pr, ft->backend_private->hContact, SIPE_EVENTTYPE_ERROR_NOTIFY, time(NULL), DBEF_UTF, strlen(msg), (PBYTE)msg);
	g_free(msg);

	free_xfer_struct(xfer);

	if (xfer->watcher != 0) {
		sipe_miranda_input_remove(xfer->watcher);
		xfer->watcher = 0;
	}

	if (xfer->fd)
		Netlib_CloseHandle(xfer->fd);

	if (xfer->dest_fp != NULL) {
		fclose(xfer->dest_fp);
		xfer->dest_fp = NULL;
	}

	xfer->bytes_remaining = 0;

	g_free(xfer->filename);
	g_free(xfer);
}

void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft)
{
	cancel_local(ft->backend_private);
}

void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft)
{
	cancel_remote(ft->backend_private);
}

static struct sipe_backend_file_transfer *
new_xfer(SIPPROTO *pr,
	 struct sipe_file_transfer *ft,
	 HANDLE hContact)
{
	struct sipe_backend_file_transfer *xfer = g_new0(struct sipe_backend_file_transfer, 1);

	xfer->current_buffer_size = FT_INITIAL_BUFFER_SIZE;
	xfer->buffer = g_byte_array_sized_new(FT_INITIAL_BUFFER_SIZE);
	xfer->ft = ft;
	xfer->hContact = hContact;
	xfer->pr = pr;

	xfer->st.cbSize = sizeof(PROTOFILETRANSFERSTATUS);
	xfer->st.hContact = hContact;

	return xfer;
}

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size)
{
	SIPPROTO *pr = sipe_public->backend_private;
	PROTORECVFILET pre = {0};
	CCSDATA ccs;
	HANDLE hContact;

	FT_SIPE_DEBUG_INFO("Incoming ft <%08x> from <%s> file <%s> size <%d>", ft, who, file_name, file_size);
	hContact = sipe_backend_buddy_find( sipe_public, who, NULL );
	if (!hContact)
	{
		FT_SIPE_DEBUG_INFO("Adding miranda contact for incoming transfer from <%s>", who);
		hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
		CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
		DBWriteContactSettingByte( hContact, "CList", "NotOnList", 1 );
		sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, who ); // name
	}

	ft->backend_private = new_xfer(pr, ft, hContact);
	ft->backend_private->incoming = TRUE;
	ft->backend_private->file_size = file_size;
	ft->backend_private->bytes_remaining = file_size;
	ft->backend_private->bytes_sent = 0;
	ft->backend_private->filename = g_strdup(file_name);

	pre.flags = PREF_TCHAR;
	pre.timestamp = time(NULL);
	pre.tszDescription = mir_a2t(file_name);
	pre.fileCount = 1;
	pre.ptszFiles = &pre.tszDescription;
	pre.lParam = (LPARAM)ft;

        ccs.szProtoService = PSR_FILE;
        ccs.hContact = hContact;
        ccs.wParam = 0;
        ccs.lParam = (LPARAM)&pre;
        CallService(MS_PROTO_CHAINRECV, 0, (LPARAM)&ccs);

}

gboolean
sipe_backend_ft_incoming_accept(struct sipe_file_transfer *ft,
				const gchar *ip,
				unsigned short port_min,
				unsigned short port_max)
{
	_NIF();
	return FALSE;
}

static void
set_completed(struct sipe_backend_file_transfer *xfer, gboolean completed)
{
	if (completed == TRUE) {
		char *msg = NULL;

		xfer->status = SIPE_MIRANDA_XFER_STATUS_DONE;

		if (xfer->filename != NULL)
		{
			char *filename = g_markup_escape_text(xfer->filename, -1);
			if (xfer->local_filename && xfer->incoming)
			{
				char *local = g_markup_escape_text(xfer->local_filename, -1);
				msg = g_strdup_printf("Transfer of file <A HREF=\"file://%s\">%s</A> complete",
				                      local, filename);
				g_free(local);
			}
			else
				msg = g_strdup_printf("Transfer of file %s complete",
				                      filename);
			g_free(filename);
		}
		else
			msg = g_strdup("File transfer complete");

		sipe_miranda_AddEvent(xfer->pr, xfer->hContact, SIPE_EVENTTYPE_ERROR_NOTIFY, time(NULL), DBEF_UTF, strlen(msg), (PBYTE)msg);
		sipe_miranda_SendBroadcast(xfer->pr, xfer->hContact, ACKTYPE_FILE, ACKRESULT_SUCCESS, (HANDLE)xfer, 0);

		g_free(msg);
	}

	update_progress(xfer);
}

static void
do_transfer(struct sipe_backend_file_transfer *xfer)
{

	guchar *buffer = NULL;
	gssize r = 0;
	struct sipe_file_transfer *ft = xfer->ft;

	FT_SIPE_DEBUG_INFO("incoming <%d>", xfer->incoming);
	if (xfer->incoming) {
		FT_SIPE_DEBUG_INFO_NOFORMAT("incoming branch");
		r = sipe_core_tftp_read(xfer->ft, &buffer, xfer->bytes_remaining,
					xfer->current_buffer_size);
		if (r > 0) {
			size_t wc;
			wc = fwrite(buffer, 1, r, xfer->dest_fp);

			if (wc != r) {
				SIPE_DEBUG_ERROR("Unable to write whole buffer.");
				cancel_local(xfer);
				g_free(buffer);
				return;
			}

			if ((xfer->file_size > 0) && ((xfer->bytes_sent+r) >= xfer->file_size))
				set_completed(xfer, TRUE);

		} else if(r < 0) {
			cancel_remote(xfer);
			g_free(buffer);
			return;
		}
	} else {
		size_t result = 0;
		size_t s = MIN(xfer->bytes_remaining, xfer->current_buffer_size);
		gboolean read = TRUE;
		FT_SIPE_DEBUG_INFO("outgoing branch, size <%u>", s);

		/* this is so the prpl can keep the connection open
		   if it needs to for some odd reason. */
		if (s == 0) {
			if (xfer->watcher) {
				sipe_miranda_input_remove(xfer->watcher);
				xfer->watcher = 0;
			}
			return;
		}

		if (xfer->buffer) {
			if (xfer->buffer->len < s) {
				s -= xfer->buffer->len;
				read = TRUE;
			} else {
				read = FALSE;
			}
		}

		if (read) {
			buffer = g_malloc(s);
			result = fread(buffer, 1, s, xfer->dest_fp);
			if (result != s) {
				FT_SIPE_DEBUG_INFO_NOFORMAT("Unable to read whole buffer.");
				cancel_local(xfer);
				g_free(buffer);
				return;
			}
		}

		if (xfer->buffer) {
			g_byte_array_append(xfer->buffer, buffer, result);
			g_free(buffer);
			buffer = xfer->buffer->data;
			result = xfer->buffer->len;
		}

		s = MIN(xfer->bytes_remaining, result);
		r = sipe_core_tftp_write(xfer->ft, buffer, s);

		if ((xfer->bytes_remaining - r) == 0)
			set_completed(xfer, TRUE);

		if (r >= 0 && (xfer->bytes_sent+r) >= xfer->file_size && xfer->status != SIPE_MIRANDA_XFER_STATUS_DONE)
			set_completed(xfer, TRUE);

		if (r == -1) {
			cancel_remote(xfer);

			if (!xfer->buffer)
				/* We don't free buffer if priv->buffer is set, because in
				   that case buffer doesn't belong to us. */
				g_free(buffer);
			return;
		} else if (r == result) {
			/*
			 * We managed to write the entire buffer.  This means our
			 * network is fast and our buffer is too small, so make it
			 * bigger.
			 */
			increase_buffer_size(xfer);
		}

		if (xfer->buffer) {
			/*
			 * Remove what we wrote
			 * If we wrote the whole buffer the byte array will be empty
			 * Otherwise we'll keep what wasn't sent for next time.
			 */
			buffer = NULL;
			g_byte_array_remove_range(xfer->buffer, 0, r);
		}
	}

	FT_SIPE_DEBUG_INFO_NOFORMAT("back to common code");
	if (r > 0) {
		if (xfer->file_size > 0)
			xfer->bytes_remaining -= r;

		xfer->bytes_sent += r;

		g_free(buffer);
		update_progress(xfer);
	}

	if (xfer->status == SIPE_MIRANDA_XFER_STATUS_DONE)
	{
		xfer->end_time = time(NULL);
		if (xfer->incoming)
		{
			if (sipe_core_tftp_incoming_stop(xfer->ft)) {
		                /* We're done with this transfer */
				free_xfer_struct(xfer);
		        } else {
				_unlink(xfer->local_filename);
			}
		} else {
			if (sipe_core_tftp_outgoing_stop(xfer->ft)) {
				/* We're done with this transfer */
				free_xfer_struct(xfer);
			}
		}

		if (xfer->watcher != 0) {
			sipe_miranda_input_remove(xfer->watcher);
			xfer->watcher = 0;
		}

		if (xfer->fd)
			Netlib_CloseHandle(xfer->fd);

		if (xfer->dest_fp != NULL) {
			fclose(xfer->dest_fp);
			xfer->dest_fp = NULL;
		}

		g_free(xfer->filename);
		g_free(xfer);
	}
}

static void
transfer_cb(gpointer data, gint source, sipe_miranda_input_condition condition)
{
	struct sipe_backend_file_transfer *xfer = data;
	SIPE_DEBUG_INFO_NOFORMAT("");
	do_transfer(xfer);
}

static void
begin_transfer(struct sipe_file_transfer *ft)
{
	struct sipe_backend_file_transfer *xfer = ft->backend_private;
	SIPPROTO *pr = xfer->pr;

	xfer->dest_fp = fopen(xfer->local_filename, xfer->incoming ? "wb" : "rb");
	if (xfer->dest_fp == NULL) {
		int err = errno;
		gchar *msg;
		if (xfer->incoming)
		{
			msg = g_strdup_printf("Error reading %s: \n%s.\n", xfer->local_filename, g_strerror(err));
		} else {
			msg = g_strdup_printf("Error writing %s: \n%s.\n", xfer->local_filename, g_strerror(err));
		}
		sipe_miranda_AddEvent(ft->backend_private->pr, ft->backend_private->hContact, SIPE_EVENTTYPE_ERROR_NOTIFY, time(NULL), DBEF_UTF, strlen(msg), (PBYTE)msg);
		g_free(msg);
		FT_SIPE_DEBUG_INFO("error opening local file: %s",  g_strerror(errno));
		cancel_local(xfer);
		return;
	}

	fseek(xfer->dest_fp, xfer->bytes_sent, SEEK_SET);

	xfer->start_time = time(NULL);

	LOCK;
	FT_SIPE_DEBUG_INFO("incoming <%d> size <%d>", ft->backend_private->incoming, ft->backend_private->file_size);
	if (ft->backend_private->incoming)
		sipe_core_tftp_incoming_start(ft, ft->backend_private->file_size);
	else {
		/* Set socket to nonblocking */
		SOCKET sock = CallService(MS_NETLIB_GETSOCKET, (WPARAM)xfer->fd, (LPARAM)0);
		unsigned long parm = 1;

		if (ioctlsocket(sock, FIONBIO, &parm) == SOCKET_ERROR)
		{
			FT_SIPE_DEBUG_INFO("Error ioctlsocket <%d>", WSAGetLastError());
		}
		
		FT_SIPE_DEBUG_INFO("outgoing ft <%08x> size <%d>", ft, ft->backend_private->file_size);
		sipe_core_tftp_outgoing_start(ft, ft->backend_private->file_size);
	}
	UNLOCK;

	if (xfer->fd)
		xfer->watcher = sipe_miranda_input_add(xfer->fd, xfer->incoming?SIPE_MIRANDA_INPUT_READ:SIPE_MIRANDA_INPUT_WRITE, transfer_cb, xfer);

	FT_SIPE_DEBUG_INFO("watcher [%08x]", xfer->watcher);
}

static void
ft_connected_callback(HANDLE fd, void* data, const gchar *reason)
{
	struct sipe_file_transfer *ft = (struct sipe_file_transfer *)data;
	struct sipe_backend_file_transfer *xfer = ft->backend_private;
	SIPPROTO *pr = ft->backend_private->pr;

	if (!fd)
	{
		cancel_local(xfer);
	} else {
		ft->backend_private->fd = fd;
		begin_transfer(ft);
	}

}

void
sipe_backend_ft_start(struct sipe_file_transfer *ft, struct sipe_backend_fd *fd,
                      const char* ip, unsigned port)
{
	ft->backend_private->status = SIPE_MIRANDA_XFER_STATUS_STARTED;

	if (ip && port)
	{
		FT_SIPE_DEBUG_INFO("Should connect to <%s:%d>", ip, port);
		sipe_miranda_connect(ft->backend_private->pr, ip, port, FALSE, 5, ft_connected_callback, ft);
		return;
	}

	FT_SIPE_DEBUG_INFO("Should use incoming fd <%08x>", fd);
	ft->backend_private->fd = fd;
	begin_transfer(ft);
}

gboolean
sipe_backend_ft_is_incoming(struct sipe_file_transfer *ft)
{
	FT_SIPE_DEBUG_INFO("ft <%08x> incoming <%d>", ft, ft->backend_private->incoming);
	return ft->backend_private->incoming;
}

HANDLE
sipe_miranda_SendFile( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szDescription, PROTOCHAR** ppszFiles )
{
	struct sipe_file_transfer *ft = sipe_core_ft_allocate(pr->sip);
	DBVARIANT dbv;

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		int result;
		struct __stat64 buf;

		LOCK;
		ft->backend_private = new_xfer(pr, ft, hContact);
		ft->backend_private->incoming = FALSE;
		result = _tstat64( ppszFiles[0], &buf );
		if (result != 0)
		{
			FT_SIPE_DEBUG_INFO("Could not stat file, error<%d>", result);
			ft->backend_private->file_size = 0;
		}
		else
		{
			ft->backend_private->file_size = buf.st_size;
			ft->backend_private->bytes_remaining = ft->backend_private->file_size;
			ft->backend_private->bytes_sent = 0;
		}
		FT_SIPE_DEBUG_INFO("SendFile: desc <%ls> name <%s> size <%d> to <%s>", szDescription, TCHAR2CHAR(ppszFiles[0]), ft->backend_private->file_size, dbv.pszVal);
		ft->backend_private->local_filename = g_strdup(TCHAR2CHAR(ppszFiles[0]));
		ft->backend_private->filename = g_path_get_basename(ft->backend_private->local_filename);
		FT_SIPE_DEBUG_INFO("set filename to <%s>", ft->backend_private->filename);
		sipe_core_ft_outgoing_init(ft, ft->backend_private->filename, ft->backend_private->file_size, dbv.pszVal);
		sipe_miranda_SendBroadcast(pr, hContact, ACKTYPE_FILE, ACKRESULT_CONNECTING, (HANDLE)ft->backend_private, 0);
		UNLOCK;

		DBFreeVariant( &dbv );
	}

	return ft->backend_private;
}

int
sipe_miranda_RecvFile( SIPPROTO *pr, HANDLE hContact, PROTOFILEEVENT* evt )
{
        CCSDATA ccs = { hContact, PSR_FILE, 0, (LPARAM)evt };
        return CallService(MS_PROTO_RECVFILET, 0, (LPARAM)&ccs);
}

HANDLE
sipe_miranda_FileAllow( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szPath )
{
	struct sipe_file_transfer *ft = (struct sipe_file_transfer *)hTransfer;
	FT_SIPE_DEBUG_INFO("Incoming ft <%08x> allowed", ft);
	ft->backend_private->local_filename = g_strdup_printf("%s%s", TCHAR2CHAR(szPath), ft->backend_private->filename);
	sipe_miranda_SendBroadcast(pr, hContact, ACKTYPE_FILE, ACKRESULT_CONNECTING, (HANDLE)ft->backend_private, 0);
	sipe_core_ft_incoming_init(ft);
	return ft->backend_private;
}

int
sipe_miranda_FileDeny( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szReason )
{
	struct sipe_file_transfer *ft = (struct sipe_file_transfer *)hTransfer;
	FT_SIPE_DEBUG_INFO("FileDeny: reason <%s>", szReason);
	if (ft->backend_private->incoming)
		sipe_core_ft_cancel(ft);
	free_xfer_struct(ft->backend_private);
	return 0;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
