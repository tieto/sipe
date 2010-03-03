/**
 * @file sipe-ft.c
 *
 * pidgin-sipe
 *
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
#include <glib/gprintf.h>

#include "connection.h"
#include "eventloop.h"
#include "ft.h"
#include "network.h"
#include "request.h"

#ifdef _WIN32
/* for network */
#include "libc_interface.h"
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

#include "core-depurple.h" /* Temporary for the core de-purple transition */

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-crypt.h"
#include "sipe-dialog.h"
#include "sipe-digest.h"
#include "sipe-nls.h"
#include "sipe-ft.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe.h"

#define SIPE_FT_KEY_LENGTH          24
#define SIPE_FT_CHUNK_HEADER_LENGTH  3

/*
 * DO NOT CHANGE THE FOLLOWING CONSTANTS!!!
 *
 * It seems that Microsoft Office Communicator client will accept
 * file transfer invitations *only* within this port range!
 *
 * If a firewall is active on your system you need to open these ports if
 * you want to *send* files to other users. Receiving files uses an ougoing
 * connection and should therefore automatically penetrate your firewall.
 */
#define SIPE_FT_TCP_PORT_MIN 6891
#define SIPE_FT_TCP_PORT_MAX 6901

struct _sipe_file_transfer {
	guchar encryption_key[SIPE_FT_KEY_LENGTH];
	guchar hash_key[SIPE_FT_KEY_LENGTH];
	gchar *invitation_cookie;
	unsigned auth_cookie;
	struct sipe_account_data *sip;
	struct sip_dialog *dialog;
	gpointer cipher_context;
	gpointer hmac_context;

	PurpleNetworkListenData *listener;
	int listenfd;

	gsize bytes_remaining_chunk;
	guchar* encrypted_outbuf;
	guchar* outbuf_ptr;
	gsize outbuf_size;
};
typedef struct _sipe_file_transfer sipe_file_transfer;

static void send_filetransfer_accept(PurpleXfer* xfer);
static void send_filetransfer_cancel(PurpleXfer* xfer);
static ssize_t do_read(PurpleXfer *xfer, guchar *buf, size_t len);
static gboolean read_fully(PurpleXfer *xfer, guchar *buf, size_t len);
static gssize read_line(PurpleXfer *xfer, gchar *buffer, gssize size);
static gpointer sipe_cipher_context_init(const guchar *enc_key);
static gpointer sipe_hmac_context_init(const guchar *hash_key);
static gchar *sipe_hmac_finalize(gpointer hmac_context);
static void generate_key(guchar *buffer, gsize size);
static void set_socket_nonblock(int fd, gboolean state);
static void sipe_ft_listen_socket_created(int listenfd, gpointer data);

//******************************************************************************
// I/O operations for PurpleXfer structure
//******************************************************************************

static void
sipe_ft_incoming_init(PurpleXfer *xfer)
{
	send_filetransfer_accept(xfer);
}

static void
sipe_ft_free_xfer_struct(PurpleXfer *xfer)
{
	sipe_file_transfer *ft = xfer->data;
	if (ft) {
		struct sipe_account_data *sip = PURPLE_XFER_TO_SIPE_ACCOUNT_DATA;

		g_hash_table_remove(sip->filetransfers,ft->invitation_cookie);

		if (xfer->watcher) {
			purple_input_remove(xfer->watcher);
			xfer->watcher = 0;
		}
		if (ft->listenfd >= 0) {
			SIPE_DEBUG_INFO("sipe_ft_free_xfer_struct: closing listening socket %d", ft->listenfd);
			close(ft->listenfd);
		}
		if (ft->listener)
			purple_network_listen_cancel(ft->listener);
		if (ft->cipher_context)
			sipe_crypt_ft_destroy(ft->cipher_context);

		if (ft->hmac_context)
			sipe_digest_ft_destroy(ft->hmac_context);

		g_free(ft->encrypted_outbuf);
		g_free(ft->invitation_cookie);
		g_free(ft);
		xfer->data = NULL;
	}
}

static void
sipe_ft_request_denied(PurpleXfer *xfer)
{
	if (xfer->type == PURPLE_XFER_RECEIVE)
		send_filetransfer_cancel(xfer);
	sipe_ft_free_xfer_struct(xfer);
}

static
void raise_ft_error(PurpleXfer *xfer, const char *errmsg)
{
 	purple_xfer_error(purple_xfer_get_type(xfer),
			  xfer->account, xfer->who,
			  errmsg);
}

static
void raise_ft_strerror(PurpleXfer *xfer, const char *errmsg)
{
	gchar *tmp = g_strdup_printf("%s: %s", errmsg, strerror(errno));
	raise_ft_error(xfer, tmp);
	g_free(tmp);
}

static
void raise_ft_error_and_cancel(PurpleXfer *xfer, const char *errmsg)
{
	raise_ft_error(xfer, errmsg);
	purple_xfer_cancel_local(xfer);
}

static
void raise_ft_socket_read_error_and_cancel(PurpleXfer *xfer)
{
	raise_ft_error_and_cancel(xfer, _("Socket read failed"));
}

static
void raise_ft_socket_write_error_and_cancel(PurpleXfer *xfer)
{
	raise_ft_error_and_cancel(xfer, _("Socket write failed"));
}

static void
sipe_ft_incoming_start(PurpleXfer *xfer)
{
	sipe_file_transfer *ft;
	static const gchar VER[] = "VER MSN_SECURE_FTP\r\n";
	static const gchar TFR[] = "TFR\r\n";
	const gsize BUFFER_SIZE = 50;
	gchar buf[BUFFER_SIZE];
	struct sipe_account_data *sip;
	gchar* request;
	const gsize FILE_SIZE_OFFSET = 4;
	gsize file_size;

	ft = xfer->data;

	if (write(xfer->fd,VER,strlen(VER)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}
	if (read_line(xfer, buf, BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	sip = PURPLE_XFER_TO_SIPE_ACCOUNT_DATA;

	request = g_strdup_printf("USR %s %u\r\n", sip->username, ft->auth_cookie);
	if (write(xfer->fd,request,strlen(request)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		g_free(request);
		return;
	}
	g_free(request);

	if (read_line(xfer, buf, BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	file_size = g_ascii_strtoull(buf + FILE_SIZE_OFFSET,NULL,10);
	if (file_size != xfer->size) {
		raise_ft_error_and_cancel(xfer,
					  _("File size is different from the advertised value."));
		return;
	}

	if (write(xfer->fd,TFR,strlen(TFR)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	ft->bytes_remaining_chunk = 0;

	ft->cipher_context = sipe_cipher_context_init(ft->encryption_key);
	ft->hmac_context   = sipe_hmac_context_init(ft->hash_key);
}

static void
sipe_ft_incoming_stop(PurpleXfer *xfer)
{
	static const gchar BYE[] = "BYE 16777989\r\n";
	gsize BUFFER_SIZE = 50;
	char buffer[BUFFER_SIZE];
	const gssize MAC_OFFSET = 4;
	const gssize CRLF_LEN = 2;
	gssize macLen;
	sipe_file_transfer *ft;
	gchar *mac;
	gchar *mac1;

	if (write(xfer->fd,BYE,strlen(BYE)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	macLen = read_line(xfer, buffer, BUFFER_SIZE);

	if (macLen < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	} else if (macLen < (MAC_OFFSET + CRLF_LEN)) {
		raise_ft_error_and_cancel(xfer, _("Received MAC is corrupted"));
		return;
	}

	// Check MAC
	ft = xfer->data;
	mac  = g_strndup(buffer + MAC_OFFSET, macLen - MAC_OFFSET - CRLF_LEN);
	mac1 = sipe_hmac_finalize(ft->hmac_context);
	if (!sipe_strequal(mac, mac1)) {
		unlink(xfer->local_filename);
		raise_ft_error_and_cancel(xfer,
					  _("Received file is corrupted"));
	}
	g_free(mac1);
	g_free(mac);

	sipe_ft_free_xfer_struct(xfer);
}

static gssize
sipe_ft_read(guchar **buffer, PurpleXfer *xfer)
{
	gsize bytes_to_read;
	ssize_t bytes_read;

	sipe_file_transfer *ft = xfer->data;

	if (ft->bytes_remaining_chunk == 0) {
		guchar hdr_buf[SIPE_FT_CHUNK_HEADER_LENGTH];

		/* read chunk header */
		if (!read_fully(xfer, hdr_buf, sizeof(hdr_buf))) {
			raise_ft_strerror(xfer, _("Socket read failed"));
			return -1;
		}

		/* chunk header format:
		 *
		 *  0:  00   unknown             (always zero?)
		 *  1:  LL   chunk size in bytes (low byte)
		 *  2:  HH   chunk size in bytes (high byte)
		 *
		 * Convert size from little endian to host order
		 */
		ft->bytes_remaining_chunk = hdr_buf[1] + (hdr_buf[2] << 8);
	}

	bytes_to_read = MIN(purple_xfer_get_bytes_remaining(xfer),
			    xfer->current_buffer_size);
	bytes_to_read = MIN(bytes_to_read, ft->bytes_remaining_chunk);

	*buffer = g_malloc(bytes_to_read);
	if (!*buffer) {
		raise_ft_error(xfer, _("Out of memory"));
		SIPE_DEBUG_ERROR("sipe_ft_read: can't allocate %" G_GSIZE_FORMAT " bytes for receive buffer",
				 bytes_to_read);
		return -1;
	}

	bytes_read = do_read(xfer, *buffer, bytes_to_read);
	if (bytes_read < 0) {
		raise_ft_strerror(xfer, _("Socket read failed"));
		return -1;
	}

	if (bytes_read > 0) {
		guchar *decrypted = g_malloc(bytes_read);

		if (!decrypted) {
			raise_ft_error(xfer, _("Out of memory"));
			SIPE_DEBUG_ERROR("sipe_ft_read: can't allocate %" G_GSIZE_FORMAT " bytes for decryption buffer",
					 (gsize)bytes_read);
			g_free(*buffer);
			*buffer = NULL;
			return -1;
		}
		sipe_crypt_ft_stream(ft->cipher_context, *buffer, bytes_read, decrypted);
		g_free(*buffer);
		*buffer = decrypted;

		sipe_digest_ft_update(ft->hmac_context, decrypted, bytes_read);

		ft->bytes_remaining_chunk -= bytes_read;
	}

	return bytes_read;
}

static gssize
sipe_ft_write(const guchar *buffer, size_t size, PurpleXfer *xfer)
{
	ssize_t bytes_written;
	sipe_file_transfer *ft = xfer->data;

	/* When sending data via server with ForeFront installed, block bigger than
	 * this default causes ending of transmission. Hard limit block to this value
	 * when libpurple sends us more data. */
	const gsize DEFAULT_BLOCK_SIZE = 2045;
	if (size > DEFAULT_BLOCK_SIZE)
		size = DEFAULT_BLOCK_SIZE;

	if (ft->bytes_remaining_chunk == 0) {
		ssize_t bytes_read;
		guchar local_buf[16];
		guchar hdr_buf[SIPE_FT_CHUNK_HEADER_LENGTH];

		memset(local_buf, 0, sizeof local_buf);

		// Check if receiver did not cancel the transfer before it is finished
		bytes_read = read(xfer->fd,local_buf,sizeof (local_buf));
		if (bytes_read == -1 && errno != EAGAIN) {
			raise_ft_strerror(xfer, _("Socket read failed"));
			return -1;
		} else if (bytes_read > 0
					&& (g_str_has_prefix((gchar*)local_buf,"CCL\r\n")
					|| g_str_has_prefix((gchar*)local_buf,"BYE 2164261682\r\n"))) {
			return -1;
		}

		if (ft->outbuf_size < size) {
			g_free(ft->encrypted_outbuf);
			ft->outbuf_size = size;
			ft->encrypted_outbuf = g_malloc(ft->outbuf_size);
			if (!ft->encrypted_outbuf) {
				raise_ft_error(xfer, _("Out of memory"));
				SIPE_DEBUG_ERROR("sipe_ft_write: can't allocate %" G_GSIZE_FORMAT " bytes for send buffer",
						 ft->outbuf_size);
				return -1;
			}
		}

		ft->bytes_remaining_chunk = size;
		ft->outbuf_ptr = ft->encrypted_outbuf;
		sipe_crypt_ft_stream(ft->cipher_context, buffer, size,
					     ft->encrypted_outbuf);
		sipe_digest_ft_update(ft->hmac_context, buffer, size);

		/* chunk header format:
		 *
		 *  0:  00   unknown             (always zero?)
		 *  1:  LL   chunk size in bytes (low byte)
		 *  2:  HH   chunk size in bytes (high byte)
		 *
		 * Convert size from host order to little endian
		 */
		hdr_buf[0] = 0;
		hdr_buf[1] = (ft->bytes_remaining_chunk & 0x00FF);
		hdr_buf[2] = (ft->bytes_remaining_chunk & 0xFF00) >> 8;

		/* write chunk header */
		if (write(xfer->fd, hdr_buf, sizeof(hdr_buf)) == -1) {
			raise_ft_strerror(xfer, _("Socket write failed"));
			return -1;
		}
	}

	bytes_written = write(xfer->fd, ft->outbuf_ptr, ft->bytes_remaining_chunk);
	if (bytes_written == -1) {
		if (errno == EAGAIN)
			bytes_written = 0;
		else {
			raise_ft_strerror(xfer, _("Socket write failed"));
		}
	}

	if (bytes_written > 0) {
		ft->bytes_remaining_chunk -= bytes_written;
		ft->outbuf_ptr += bytes_written;
	}

	if ((xfer->bytes_remaining - bytes_written) == 0)
		purple_xfer_set_completed(xfer, TRUE);

	return bytes_written;
}

static void
sipe_ft_outgoing_init(PurpleXfer *xfer)
{
	struct sip_dialog *dialog;
	sipe_file_transfer *ft = xfer->data;

	gchar *body = g_strdup_printf("Application-Name: File Transfer\r\n"
				      "Application-GUID: {5D3E02AB-6190-11d3-BBBB-00C04F795683}\r\n"
				      "Invitation-Command: INVITE\r\n"
				      "Invitation-Cookie: %s\r\n"
				      "Application-File: %s\r\n"
				      "Application-FileSize: %lu\r\n"
				      //"Connectivity: N\r\n" TODO
				      "Encryption: R\r\n", // TODO: non encrypted file transfer support
				      ft->invitation_cookie,
				      purple_xfer_get_filename(xfer),
				      (long unsigned) purple_xfer_get_size(xfer));

	struct sipe_account_data *sip = PURPLE_XFER_TO_SIPE_ACCOUNT_DATA;
	struct sip_session *session = sipe_session_find_or_add_im(sip, xfer->who);

	g_hash_table_insert(sip->filetransfers,g_strdup(ft->invitation_cookie),xfer);

	// Queue the message
	sipe_session_enqueue_message(session, body, "text/x-msmsgsinvite");

	dialog = sipe_dialog_find(session, xfer->who);
	if (dialog && !dialog->outgoing_invite) {
		ft->dialog = dialog;
		sipe_im_process_queue(sip, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sip, session, xfer->who, body, "text/x-msmsgsinvite", NULL, FALSE);
	}

	g_free(body);
}

static void
sipe_ft_outgoing_start(PurpleXfer *xfer)
{
	sipe_file_transfer *ft;
	static const gchar VER[] = "VER MSN_SECURE_FTP\r\n";
	const gsize BUFFER_SIZE = 50;
	gchar buf[BUFFER_SIZE];
	gchar** parts;
	unsigned auth_cookie_received;
	gboolean users_match;
	gchar *tmp;
	ssize_t bytes_written;

	set_socket_nonblock(xfer->fd, TRUE);

	ft = xfer->data;

	if (read_line(xfer, buf, BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	if (!sipe_strequal(buf,VER)) {
		raise_ft_error_and_cancel(xfer,_("File transfer initialization failed."));
		SIPE_DEBUG_INFO("File transfer VER string incorrect, received: %s expected: %s",
				buf, VER);
		return;
	}

	if (write(xfer->fd,VER,strlen(VER)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	if (read_line(xfer, buf, BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	parts = g_strsplit(buf, " ", 3);

	auth_cookie_received = g_ascii_strtoull(parts[2],NULL,10);

	// xfer->who has 'sip:' prefix, skip these four characters
	users_match = sipe_strcase_equal(parts[1], (xfer->who + 4));
	g_strfreev(parts);

	SIPE_DEBUG_INFO("File transfer authentication: %s Expected: USR %s %u",
			buf, xfer->who + 4, ft->auth_cookie);

	if (!users_match || (ft->auth_cookie != auth_cookie_received)) {
		raise_ft_error_and_cancel(xfer,
					  _("File transfer authentication failed."));
		return;
	}

	tmp = g_strdup_printf("FIL %lu\r\n",(long unsigned) xfer->size);
	bytes_written = write(xfer->fd, tmp, strlen(tmp));
	g_free(tmp);

	if (bytes_written == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	// TFR
	if (read_line(xfer,buf,BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	ft->bytes_remaining_chunk = 0;

	ft->cipher_context = sipe_cipher_context_init(ft->encryption_key);
	ft->hmac_context   = sipe_hmac_context_init(ft->hash_key);
}

static void
sipe_ft_outgoing_stop(PurpleXfer *xfer)
{
	sipe_file_transfer *ft = xfer->data;
	gsize BUFFER_SIZE = 50;
	char buffer[BUFFER_SIZE];
	gchar *mac;
	gsize mac_strlen;

	// BYE
	if (read_line(xfer, buffer, BUFFER_SIZE) < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	mac = sipe_hmac_finalize(ft->hmac_context);
	g_sprintf(buffer, "MAC %s \r\n", mac);
	g_free(mac);

	mac_strlen = strlen(buffer);
	// There must be this zero byte between mac and \r\n
	buffer[mac_strlen - 3] = 0;

	if (write(xfer->fd,buffer,mac_strlen) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	sipe_ft_free_xfer_struct(xfer);
}

//******************************************************************************

void sipe_ft_incoming_transfer(PurpleAccount *account, struct sipmsg *msg, const GSList *body)
{
	PurpleXfer *xfer;
	struct sipe_account_data *sip = PURPLE_ACCOUNT_TO_SIPE_ACCOUNT_DATA;
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_session *session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		gchar *from = parse_from(sipmsg_find_header(msg, "From"));
		session = sipe_session_find_im(sip, from);
		g_free(from);
	}

	if (!session) {
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_ft_incoming_transfer: can't find session for remote party");
		return;
	}

	xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE, session->with);

	if (xfer) {
		size_t file_size;
		sipe_file_transfer *ft = g_new0(sipe_file_transfer, 1);
		ft->invitation_cookie = g_strdup(sipe_utils_nameval_find(body, "Invitation-Cookie"));
		ft->sip = sip;
		ft->dialog = sipe_dialog_find(session, session->with);
		ft->listenfd = -1;
		generate_key(ft->encryption_key, SIPE_FT_KEY_LENGTH);
		generate_key(ft->hash_key, SIPE_FT_KEY_LENGTH);
		xfer->data = ft;

		purple_xfer_set_filename(xfer, sipe_utils_nameval_find(body, "Application-File"));

		file_size = g_ascii_strtoull(sipe_utils_nameval_find(body, "Application-FileSize"),NULL,10);
		purple_xfer_set_size(xfer, file_size);

		purple_xfer_set_init_fnc(xfer, sipe_ft_incoming_init);
		purple_xfer_set_start_fnc(xfer,sipe_ft_incoming_start);
		purple_xfer_set_end_fnc(xfer,sipe_ft_incoming_stop);
		purple_xfer_set_request_denied_fnc(xfer, sipe_ft_request_denied);
		purple_xfer_set_read_fnc(xfer,sipe_ft_read);
		purple_xfer_set_cancel_send_fnc(xfer,sipe_ft_free_xfer_struct);
		purple_xfer_set_cancel_recv_fnc(xfer,sipe_ft_free_xfer_struct);

		g_hash_table_insert(sip->filetransfers,g_strdup(ft->invitation_cookie),xfer);

		purple_xfer_request(xfer);
	}
}

void sipe_ft_incoming_accept(PurpleAccount *account, const GSList *body)
{
	struct sipe_account_data *sip = PURPLE_ACCOUNT_TO_SIPE_ACCOUNT_DATA;
	const gchar *inv_cookie = sipe_utils_nameval_find(body, "Invitation-Cookie");
	PurpleXfer *xfer = g_hash_table_lookup(sip->filetransfers,inv_cookie);

	if (xfer) {
		const gchar *ip           = sipe_utils_nameval_find(body, "IP-Address");
		const gchar *port_str     = sipe_utils_nameval_find(body, "Port");
		const gchar *auth_cookie  = sipe_utils_nameval_find(body, "AuthCookie");
		const gchar *enc_key_b64  = sipe_utils_nameval_find(body, "Encryption-Key");
		const gchar *hash_key_b64 = sipe_utils_nameval_find(body, "Hash-Key");

		sipe_file_transfer *ft = xfer->data;

		if (auth_cookie)
			ft->auth_cookie = g_ascii_strtoull(auth_cookie,NULL,10);
		if (enc_key_b64) {
			gsize ret_len;
			guchar *enc_key = g_base64_decode(enc_key_b64, &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft->encryption_key,enc_key,SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(xfer,
							  _("Received encryption key has wrong size."));
				g_free(enc_key);
				return;
			}
			g_free(enc_key);
		}
		if (hash_key_b64) {
			gsize ret_len;
			guchar *hash_key = g_base64_decode(hash_key_b64, &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft->hash_key,hash_key,SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(xfer,
							  _("Received hash key has wrong size."));
				g_free(hash_key);
				return;
			}
			g_free(hash_key);
		}

		if (ip && port_str) {
			purple_xfer_start(xfer, -1, ip, g_ascii_strtoull(port_str,NULL,10));
		} else {
			ft->listener = purple_network_listen_range(SIPE_FT_TCP_PORT_MIN,
								   SIPE_FT_TCP_PORT_MAX,
								   SOCK_STREAM,
								   sipe_ft_listen_socket_created,
								   xfer);
			if (!ft->listener) {
				raise_ft_error_and_cancel(xfer,
							  _("Could not create listen socket"));
				return;
			}
		}
	}
}

void sipe_ft_incoming_cancel(PurpleAccount *account, GSList *body)
{
	gchar *inv_cookie = g_strdup(sipe_utils_nameval_find(body, "Invitation-Cookie"));

	struct sipe_account_data *sip = PURPLE_ACCOUNT_TO_SIPE_ACCOUNT_DATA;
	PurpleXfer *xfer = g_hash_table_lookup(sip->filetransfers,inv_cookie);

	purple_xfer_cancel_remote(xfer);
}

static void send_filetransfer_accept(PurpleXfer* xfer)
{
	sipe_file_transfer* ft = xfer->data;
	struct sip_dialog *dialog = ft->dialog;

	gchar *b64_encryption_key = g_base64_encode(ft->encryption_key, 24);
	gchar *b64_hash_key = g_base64_encode(ft->hash_key, 24);

	gchar *body = g_strdup_printf("Invitation-Command: ACCEPT\r\n"
				      "Request-Data: IP-Address:\r\n"
				      "Invitation-Cookie: %s\r\n"
				      "Encryption-Key: %s\r\n"
				      "Hash-Key: %s\r\n"
				      /*"IP-Address: %s\r\n"
					"Port: 6900\r\n"
					"PortX: 11178\r\n"
					"Auth-Cookie: 11111111\r\n"
					"Sender-Connect: TRUE\r\n"*/,
				      ft->invitation_cookie,
				      b64_encryption_key,
				      b64_hash_key
                                      /*,sipe_backend_network_ip_address()*/
		);

	send_sip_request(ft->sip->private, "MESSAGE", dialog->with, dialog->with,
			 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
			 body, dialog, NULL);

	g_free(body);
	g_free(b64_encryption_key);
	g_free(b64_hash_key);
}

static void send_filetransfer_cancel(PurpleXfer* xfer) {
	sipe_file_transfer* ft = xfer->data;
	struct sip_dialog* dialog = ft->dialog;

	gchar *body = g_strdup_printf("Invitation-Command: CANCEL\r\n"
				      "Invitation-Cookie: %s\r\n"
					  "Cancel-Code: REJECT\r\n",
				      ft->invitation_cookie);

	send_sip_request(ft->sip->private, "MESSAGE", dialog->with, dialog->with,
			 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
			 body, dialog, NULL);

	g_free(body);
}

static ssize_t
do_read(PurpleXfer *xfer, guchar *buf, size_t len)
{
	ssize_t bytes_read = read(xfer->fd, buf, len);
	if (bytes_read == 0) {
		// Sender canceled transfer before it was finished
		return -2;
	} else if (bytes_read == -1) {
		if (errno == EAGAIN)
			return 0;
		else
			return -1;
	}
	return bytes_read;
}

static gboolean
read_fully(PurpleXfer *xfer, guchar *buf, size_t len)
{
	const gulong READ_TIMEOUT = 10000000;
	gulong time_spent = 0;

	while (len) {
		ssize_t bytes_read = do_read(xfer, buf, len);
		if (bytes_read == 0) {
			g_usleep(100000);
			time_spent += 100000;
		} else if (bytes_read < 0 || time_spent > READ_TIMEOUT) {
			return FALSE;
		} else {
			len -= bytes_read;
			buf += bytes_read;
			time_spent = 0;
		}
	}
	return TRUE;
}

static gssize read_line(PurpleXfer *xfer, gchar *buffer, gssize size)
{
	gssize pos = 0;

	memset(buffer,0,size);
	do {
		if (!read_fully(xfer, (guchar*) buffer + pos, 1))
			return -1;
	} while (buffer[pos] != '\n' && ++pos != (size - 1));

	if (pos == (size - 1) && buffer[pos - 1] != '\n') {
		// Buffer too short
		return -2;
	}

	return pos;
}

static gpointer sipe_cipher_context_init(const guchar *enc_key)
{
	/*
	 *      Decryption of file from SIPE file transfer
	 *
	 *      Decryption:
	 *  1.) SHA1-Key = SHA1sum (Encryption-Key); Do SHA1 digest from Encryption-Key, return 20 bytes SHA1-Key.
	 *  2.) Decrypt-Data = RC4 (Encrypt-Data, substr(SHA1-Key, 0, 15)); Decryption of encrypted data, used 16 bytes SHA1-Key;
	 */

	guchar k2[SIPE_DIGEST_SHA1_LENGTH];

	/* 1.) SHA1 sum	*/
        sipe_digest_sha1(enc_key, SIPE_FT_KEY_LENGTH, k2);

	/* 2.) RC4 decryption */
	return sipe_crypt_ft_start(k2);
}

static gpointer sipe_hmac_context_init(const guchar *hash_key)
{
	/*
	 * 	Count MAC digest
	 *
	 *  	HMAC digest:
	 *  1.) SHA1-Key = SHA1sum (Hash-Key); Do SHA1 digest from Hash-Key, return 20 bytes SHA1-Key.
	 *  2.) MAC = HMAC_SHA1 (Decrypt-Data, substr(HMAC-Key,0,15)); Digest of decrypted file and SHA1-Key (used again only 16 bytes)
	 */

	guchar k2[SIPE_DIGEST_SHA1_LENGTH];

	/* 1.) SHA1 sum	*/
	sipe_digest_sha1(hash_key, SIPE_FT_KEY_LENGTH, k2);

	/* 2.) HMAC (initialization only) */
	return sipe_digest_ft_start(k2);
}

static gchar* sipe_hmac_finalize(gpointer hmac_context)
{
	guchar hmac_digest[SIPE_DIGEST_FILETRANSFER_LENGTH];

	/*  MAC = Digest of decrypted file and SHA1-Key (used again only 16 bytes) */
	sipe_digest_ft_end(hmac_context, hmac_digest);

	return g_base64_encode(hmac_digest, sizeof (hmac_digest));
}

static void generate_key(guchar *buffer, gsize size)
{
	gsize i;
	for (i = 0; i != size; ++i)
		buffer[i] = rand();
}

static void set_socket_nonblock(int fd, gboolean state)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		flags = 0;

	if (state == TRUE)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	else
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

void sipe_ft_send_file(PurpleConnection *gc, const char *who, const char *file)
{
	PurpleXfer *xfer = sipe_ft_new_xfer(gc, who);

	if (xfer) {
		if (file != NULL)
			purple_xfer_request_accepted(xfer, file);
		else
			purple_xfer_request(xfer);
	}
}

PurpleXfer * sipe_ft_new_xfer(PurpleConnection *gc, const char *who)
{
	PurpleXfer *xfer = NULL;

	if (PURPLE_CONNECTION_IS_VALID(gc)) {
		xfer = purple_xfer_new(purple_connection_get_account(gc),
				       PURPLE_XFER_SEND, who);

		if (xfer) {
			struct sipe_account_data *sip = PURPLE_GC_TO_SIPE_ACCOUNT_DATA;

			sipe_file_transfer *ft = g_new0(sipe_file_transfer, 1);
			ft->invitation_cookie = g_strdup_printf("%u", rand() % 1000000000);
			ft->sip = sip;

			xfer->data = ft;

			purple_xfer_set_init_fnc(xfer, sipe_ft_outgoing_init);
			purple_xfer_set_start_fnc(xfer, sipe_ft_outgoing_start);
			purple_xfer_set_end_fnc(xfer, sipe_ft_outgoing_stop);
			purple_xfer_set_request_denied_fnc(xfer, sipe_ft_request_denied);
			purple_xfer_set_write_fnc(xfer, sipe_ft_write);
			purple_xfer_set_cancel_send_fnc(xfer, sipe_ft_free_xfer_struct);
			purple_xfer_set_cancel_recv_fnc(xfer, sipe_ft_free_xfer_struct);
		}
	}

	return xfer;
}

static
void sipe_ft_client_connected(gpointer p_xfer, gint listenfd,
								SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sockaddr_in saddr;
	socklen_t slen = sizeof (saddr);

	int fd = accept(listenfd, (struct sockaddr*)&saddr, &slen);

	PurpleXfer *xfer = p_xfer;
	sipe_file_transfer *ft = xfer->data;

	purple_input_remove(xfer->watcher);
	xfer->watcher = 0;
	close(listenfd);
	ft->listenfd = -1;

	if (fd < 0) {
		raise_ft_socket_read_error_and_cancel(xfer);
	} else {
		purple_xfer_start(xfer, fd, NULL, 0);
	}
}

static
void sipe_ft_listen_socket_created(int listenfd, gpointer data)
{
	gchar *body;
	PurpleXfer *xfer = data;
	sipe_file_transfer *ft  = xfer->data;

	struct sockaddr_in addr;

	socklen_t socklen = sizeof (addr);

	ft->listener = NULL;
	ft->listenfd = listenfd;

	getsockname(listenfd, (struct sockaddr*)&addr, &socklen);

	xfer->watcher = purple_input_add(listenfd, PURPLE_INPUT_READ,
					 sipe_ft_client_connected, xfer);

	ft->auth_cookie = rand() % 1000000000;

	body = g_strdup_printf("Invitation-Command: ACCEPT\r\n"
			       "Invitation-Cookie: %s\r\n"
			       "IP-Address: %s\r\n"
			       "Port: %u\r\n"
			       "PortX: 11178\r\n"
			       "AuthCookie: %u\r\n"
			       "Request-Data: IP-Address:\r\n",
			       ft->invitation_cookie,
			       sipe_utils_get_suitable_local_ip(listenfd),
			       ntohs(addr.sin_port),
			       ft->auth_cookie);

	if (!ft->dialog) {
		struct sipe_account_data *sip = PURPLE_XFER_TO_SIPE_ACCOUNT_DATA;
		struct sip_session *session = sipe_session_find_or_add_im(sip, xfer->who);
		ft->dialog = sipe_dialog_find(session, xfer->who);
	}

	if (ft->dialog) {
		send_sip_request(ft->sip->private, "MESSAGE", ft->dialog->with, ft->dialog->with,
				 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
				 body, ft->dialog, NULL);
	}
	g_free(body);
}

GSList * sipe_ft_parse_msg_body(const gchar *body)
{
	GSList *list = NULL;
	gchar **lines = g_strsplit(body, "\r\n", 0);
	if (sipe_utils_parse_lines(&list, lines, ":") == FALSE) {
		sipe_utils_nameval_free(list);
		list = NULL;
	}
	g_strfreev(lines);
	return list;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
