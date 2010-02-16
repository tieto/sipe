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

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <glib/gprintf.h>

#include "sipe.h"
#include "sipe-ft.h"
#include "sipe-dialog.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-utils.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define SIPE_FT_KEY_LENGTH 24

#define SIPE_FT_TCP_PORT_MIN 6891
#define SIPE_FT_TCP_PORT_MAX 6901

struct _sipe_file_transfer {
	guchar encryption_key[SIPE_FT_KEY_LENGTH];
	guchar hash_key[SIPE_FT_KEY_LENGTH];
	gchar *invitation_cookie;
	unsigned auth_cookie;
	struct sipe_account_data *sip;
	struct sip_dialog *dialog;
	PurpleCipherContext *cipher_context;

	gsize bytes_remaining_chunk;
	guchar* encrypted_outbuf;
	guchar* outbuf_ptr;
	gsize outbuf_size;
};
typedef struct _sipe_file_transfer sipe_file_transfer;

static void send_filetransfer_accept(PurpleXfer* xfer);
static void send_filetransfer_cancel(PurpleXfer* xfer);
static gssize read_line(int fd, gchar *buffer, gssize size);
static void sipe_cipher_context_init(PurpleCipherContext **rc4_context, const guchar *enc_key);
static gchar* sipe_get_mac(const guchar *data, size_t data_len, const guchar *hash_key);
static void generate_key(guchar *buffer, gsize size);
static void set_socket_nonblock(int fd, gboolean state);
static void sipe_ft_listen_socket_created(int listenfd, gpointer data);
static const char * sipe_ft_get_suitable_local_ip(int fd);

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
		struct sipe_account_data *sip = xfer->account->gc->proto_data;

		g_hash_table_remove(sip->filetransfers,ft->invitation_cookie);

		if (ft->cipher_context)
			purple_cipher_context_destroy(ft->cipher_context);

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
void raise_ft_error_and_cancel(PurpleXfer *xfer, const char *errmsg)
{
	purple_xfer_error(purple_xfer_get_type(xfer),
			  xfer->account, xfer->who,
			  errmsg);
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

static
void raise_ft_strerror(PurpleXfer *xfer, const char *errmsg)
{
	gchar *tmp = g_strdup_printf("%s: %s", errmsg, strerror(errno));
 	purple_xfer_error(purple_xfer_get_type(xfer),
			  xfer->account,xfer->who,
			  tmp);
	g_free(tmp);
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

	set_socket_nonblock(xfer->fd,FALSE);

	ft = xfer->data;

	if (write(xfer->fd,VER,strlen(VER)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}
	if (read(xfer->fd,buf,strlen(VER)) == -1) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	sip = xfer->account->gc->proto_data;

	request = g_strdup_printf("USR %s %u\r\n", sip->username, ft->auth_cookie);
	if (write(xfer->fd,request,strlen(request)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		g_free(request);
		return;
	}
	g_free(request);

	read_line(xfer->fd, buf, BUFFER_SIZE);

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

	set_socket_nonblock(xfer->fd,TRUE);

	sipe_cipher_context_init(&ft->cipher_context, ft->encryption_key);
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
	FILE *fdread;
	guchar *filebuf;
	sipe_file_transfer *ft;
	gchar *mac;
	gchar *mac1;

	set_socket_nonblock(xfer->fd,FALSE);

	if (write(xfer->fd,BYE,strlen(BYE)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	macLen = read_line(xfer->fd,buffer,BUFFER_SIZE);

	if (macLen < (MAC_OFFSET + CRLF_LEN)) {
		raise_ft_error_and_cancel(xfer,
					  _("Received MAC is corrupted"));
		return;
	}

	fflush(xfer->dest_fp);

	// Check MAC

	fdread = fopen(xfer->local_filename,"rb");
	if (!fdread) {
		raise_ft_error_and_cancel(xfer,
					  _("Unable to open received file."));
		return;
	}

	filebuf = g_malloc(xfer->size);
	if (!filebuf) {
		fclose(fdread);
		raise_ft_error_and_cancel(xfer,
					  _("Can't allocate enough memory for read buffer."));
		return;		
	}

	if (fread(filebuf, 1, xfer->size, fdread) < 1) {
		g_free(filebuf);
		fclose(fdread);
		raise_ft_error_and_cancel(xfer,
					  _("Unable to read received file."));
		return;
	}
	fclose(fdread);

	ft = xfer->data;

	mac  = g_strndup(buffer + MAC_OFFSET, macLen - MAC_OFFSET - CRLF_LEN);
	mac1 = sipe_get_mac(filebuf, xfer->size, ft->hash_key);
	if (!sipe_strequal(mac, mac1)) {
		unlink(xfer->local_filename);
		raise_ft_error_and_cancel(xfer,
					  _("Received file is corrupted"));
	}
	g_free(mac);
	g_free(filebuf);

	sipe_ft_free_xfer_struct(xfer);
}

static gssize
sipe_ft_read(guchar **buffer, PurpleXfer *xfer)
{
	gsize bytes_to_read;
	ssize_t bytes_read;

	sipe_file_transfer *ft = xfer->data;

	if (ft->bytes_remaining_chunk == 0) {
		guchar chunk_buf[3];

		set_socket_nonblock(xfer->fd, FALSE);

		if (read(xfer->fd,chunk_buf,3) == -1) {
			raise_ft_strerror(xfer, _("Socket read failed"));
			return -1;
		}

		ft->bytes_remaining_chunk = chunk_buf[1] + (chunk_buf[2] << 8);
		set_socket_nonblock(xfer->fd, TRUE);
	}

	bytes_to_read = MIN(purple_xfer_get_bytes_remaining(xfer),
							  xfer->current_buffer_size);
	bytes_to_read = MIN(bytes_to_read, ft->bytes_remaining_chunk);

	*buffer = g_malloc0(bytes_to_read);

	bytes_read = read(xfer->fd, *buffer, bytes_to_read);
	if (bytes_read == -1) {
		if (errno == EAGAIN)
			bytes_read = 0;
		else {
			raise_ft_strerror(xfer, _("Socket read failed"));
		}
	}

	ft->bytes_remaining_chunk -= bytes_read;

	if (bytes_read > 0) {
		guchar* decrypted = g_malloc0(bytes_read);
		purple_cipher_context_encrypt(ft->cipher_context, *buffer, bytes_read, decrypted, NULL);
		g_free(*buffer);
		*buffer = decrypted;
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
		guchar chunk_buf[3];

		if (ft->outbuf_size < size) {
			g_free(ft->encrypted_outbuf);
			ft->outbuf_size = size;
			ft->encrypted_outbuf = g_malloc(ft->outbuf_size);
		}

		ft->bytes_remaining_chunk = size;
		ft->outbuf_ptr = ft->encrypted_outbuf;
		purple_cipher_context_encrypt(ft->cipher_context, buffer, size,
										ft->encrypted_outbuf, NULL);

		chunk_buf[0] = 0;
		chunk_buf[1] = ft->bytes_remaining_chunk & 0x00FF;
		chunk_buf[2] = (ft->bytes_remaining_chunk & 0xFF00) >> 8;

		set_socket_nonblock(xfer->fd, FALSE);
		if (write(xfer->fd,chunk_buf,3) == -1) {
			raise_ft_strerror(xfer, _("Socket write failed"));
			return -1;
		}
		set_socket_nonblock(xfer->fd, TRUE);
	}

	bytes_written = write(xfer->fd, ft->outbuf_ptr, ft->bytes_remaining_chunk);
	if (bytes_written == -1) {
		if (errno == EAGAIN)
			bytes_written = 0;
		else {
			raise_ft_strerror(xfer, _("Socket write failed"));
		}
	}

	ft->bytes_remaining_chunk -= bytes_written;
	ft->outbuf_ptr += bytes_written;

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

	struct sipe_account_data *sip = xfer->account->gc->proto_data;
	struct sip_session *session = sipe_session_find_or_add_im(sip, xfer->who);

	g_hash_table_insert(sip->filetransfers,g_strdup(ft->invitation_cookie),xfer);

	// Queue the message
	sipe_session_enqueue_message(session, body, "text/x-msmsgsinvite");
	g_free(body);

	dialog = sipe_dialog_find(session, xfer->who);
	if (dialog && !dialog->outgoing_invite) {
		ft->dialog = dialog;
		sipe_im_process_queue(sip, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sip, session, xfer->who, NULL, NULL, FALSE);
	}
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

	set_socket_nonblock(xfer->fd,FALSE);

	ft = xfer->data;

	if (read(xfer->fd,buf,strlen(VER)) == -1) {
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}
	if (write(xfer->fd,VER,strlen(VER)) == -1) {
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}

	read_line(xfer->fd, buf, BUFFER_SIZE);

	parts = g_strsplit(buf, " ", 3);

	auth_cookie_received = g_ascii_strtoull(parts[2],NULL,10);

	// xfer->who has 'sip:' prefix, skip these four characters
	users_match = sipe_strequal(parts[1], (xfer->who + 4));

	if (!users_match || (ft->auth_cookie != auth_cookie_received)) {
		raise_ft_error_and_cancel(xfer,
					  _("File transfer authentication failed."));
	}

	g_strfreev(parts);

	tmp = g_strdup_printf("FIL %lu\r\n",(long unsigned) xfer->size);
	if (write(xfer->fd, tmp, strlen(tmp)) == -1) {
		g_free(tmp);
		raise_ft_socket_write_error_and_cancel(xfer);
		return;
	}
	g_free(tmp);

	// TFR
	read_line(xfer->fd,buf,BUFFER_SIZE);

	ft->bytes_remaining_chunk = 0;

	set_socket_nonblock(xfer->fd,TRUE);

	sipe_cipher_context_init(&ft->cipher_context, ft->encryption_key);
}

static void
sipe_ft_outgoing_stop(PurpleXfer *xfer)
{
	gsize BUFFER_SIZE = 50;
	char buffer[BUFFER_SIZE];
	guchar *macbuf;
	sipe_file_transfer *ft;
	gchar *mac;
	gsize mac_strlen;

	set_socket_nonblock(xfer->fd,FALSE);

	// BYE
	read_line(xfer->fd, buffer, BUFFER_SIZE);

	macbuf = g_malloc(xfer->size);
	if (!macbuf) {
		raise_ft_error_and_cancel(xfer,
					  _("Can't allocate enough memory for transfer buffer."));
		return;
	}
	fseek(xfer->dest_fp,0,SEEK_SET);
	if (fread(macbuf,xfer->size,1,xfer->dest_fp) < 1) {
		g_free(macbuf);
		raise_ft_socket_read_error_and_cancel(xfer);
		return;
	}

	ft = xfer->data;
	mac = sipe_get_mac(macbuf,xfer->size,ft->hash_key);
	g_free(macbuf);
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

void sipe_ft_incoming_transfer(PurpleAccount *account, struct sipmsg *msg)
{
	PurpleXfer *xfer;
	struct sipe_account_data *sip = account->gc->proto_data;
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_session *session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		gchar *from = parse_from(sipmsg_find_header(msg, "From"));
		session = sipe_session_find_im(sip, from);
		g_free(from);
	}

	xfer = purple_xfer_new(account, PURPLE_XFER_RECEIVE, session->with);

	if (xfer) {
		size_t file_size;
		sipe_file_transfer *ft = g_new0(sipe_file_transfer, 1);
		ft->invitation_cookie = g_strdup(sipmsg_find_header(msg, "Invitation-Cookie"));
		ft->sip = sip;
		ft->dialog = sipe_dialog_find(session, session->with);
		generate_key(ft->encryption_key, SIPE_FT_KEY_LENGTH);
		generate_key(ft->hash_key, SIPE_FT_KEY_LENGTH);
		xfer->data = ft;

		purple_xfer_set_filename(xfer, sipmsg_find_header(msg,"Application-File"));

		file_size = g_ascii_strtoull(sipmsg_find_header(msg,"Application-FileSize"),NULL,10);
		purple_xfer_set_size(xfer, file_size);

		purple_xfer_set_init_fnc(xfer, sipe_ft_incoming_init);
		purple_xfer_set_start_fnc(xfer,sipe_ft_incoming_start);
		purple_xfer_set_end_fnc(xfer,sipe_ft_incoming_stop);
		purple_xfer_set_request_denied_fnc(xfer, sipe_ft_request_denied);
		purple_xfer_set_read_fnc(xfer,sipe_ft_read);
		purple_xfer_set_cancel_send_fnc(xfer,sipe_ft_free_xfer_struct);
		purple_xfer_set_cancel_recv_fnc(xfer,sipe_ft_free_xfer_struct);

		g_hash_table_insert(sip->filetransfers,g_strdup(ft->invitation_cookie),xfer);

		send_sip_response(sip->gc, msg, 200, "OK", NULL);

		purple_xfer_request(xfer);
	}
}

void sipe_ft_incoming_accept(PurpleAccount *account, struct sipmsg *msg)
{
	struct sipe_account_data *sip = account->gc->proto_data;
	gchar *inv_cookie = sipmsg_find_header(msg,"Invitation-Cookie");
	PurpleXfer *xfer = g_hash_table_lookup(sip->filetransfers,inv_cookie);

	if (xfer) {
		/* ip and port_str must be copied, because send_sip_response changes
		 * the headers and we need to use this values afterwards. */
		gchar *ip		= g_strdup(sipmsg_find_header(msg, "IP-Address"));
		gchar *port_str		= g_strdup(sipmsg_find_header(msg, "Port"));
		gchar *auth_cookie	= sipmsg_find_header(msg, "AuthCookie");
		gchar *enc_key_b64	= sipmsg_find_header(msg, "Encryption-Key");
		gchar *hash_key_b64	= sipmsg_find_header(msg, "Hash-Key");

		sipe_file_transfer *ft = xfer->data;

		if (auth_cookie)
			ft->auth_cookie = g_ascii_strtoull(auth_cookie,NULL,10);
		if (enc_key_b64) {
			gsize ret_len;
			guchar *enc_key = purple_base64_decode(enc_key_b64, &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft->encryption_key,enc_key,SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(xfer,
							  _("Received encryption key has wrong size."));
				g_free(enc_key);
				g_free(port_str);
				g_free(ip);
				return;
			}
			g_free(enc_key);
		}
		if (hash_key_b64) {
			gsize ret_len;
			guchar *hash_key = purple_base64_decode(hash_key_b64, &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft->hash_key,hash_key,SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(xfer,
							  _("Received hash key has wrong size."));
				g_free(hash_key);
				g_free(port_str);
				g_free(ip);
				return;
			}
			g_free(hash_key);
		}

		send_sip_response(sip->gc, msg, 200, "OK", NULL);

		if (ip && port_str) {
			purple_xfer_start(xfer, -1, ip, g_ascii_strtoull(port_str,NULL,10));
		} else {
			purple_network_listen_range(SIPE_FT_TCP_PORT_MIN, SIPE_FT_TCP_PORT_MAX,
						    SOCK_STREAM, sipe_ft_listen_socket_created,xfer);
		}

		g_free(port_str);
		g_free(ip);
	}
}

void sipe_ft_incoming_cancel(PurpleAccount *account, struct sipmsg *msg)
{
	gchar *inv_cookie = g_strdup(sipmsg_find_header(msg, "Invitation-Cookie"));

	struct sipe_account_data *sip = account->gc->proto_data;
	PurpleXfer *xfer = g_hash_table_lookup(sip->filetransfers,inv_cookie);

	send_sip_response(sip->gc, msg, 200, "OK", NULL);

	purple_xfer_cancel_remote(xfer);
}

static void send_filetransfer_accept(PurpleXfer* xfer)
{
	sipe_file_transfer* ft = xfer->data;
	struct sip_dialog *dialog = ft->dialog;

	gchar *b64_encryption_key = purple_base64_encode(ft->encryption_key,24);
	gchar *b64_hash_key = purple_base64_encode(ft->hash_key,24);

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
                                      /*,purple_network_get_my_ip(-1)*/
		);

	send_sip_request(ft->sip->gc, "MESSAGE", dialog->with, dialog->with,
			 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
			 body, dialog, NULL);

	g_free(body);
	g_free(b64_encryption_key);
	g_free(b64_hash_key);
}

static void send_filetransfer_cancel(PurpleXfer* xfer) {
	// TODO
	sipe_file_transfer* ft = xfer->data;
	struct sip_dialog* dialog = ft->dialog;

	gchar *body = g_strdup_printf("Invitation-Command: CANCEL\r\n"
				      "Invitation-Cookie: %s\r\n",
				      ft->invitation_cookie);

	send_sip_request(ft->sip->gc, "MESSAGE", dialog->with, dialog->with,
			 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
			 body, dialog, NULL);

	g_free(body);
}

static gssize read_line(int fd, gchar *buffer, gssize size)
{
	gssize pos = 0;

	memset(buffer,0,size);
	do {
		if (read(fd,buffer + pos,1) == -1)
			return -1;
	} while (buffer[pos] != '\n' && ++pos < size);

	return pos;
}

static void sipe_cipher_context_init(PurpleCipherContext **rc4_context, const guchar *enc_key)
{
	/*
	 *      Decryption of file from SIPE file transfer
	 *
	 *      Decryption:
	 *  1.) SHA1-Key = SHA1sum (Encryption-Key); Do SHA1 digest from Encryption-Key, return 20 bytes SHA1-Key.
	 *  2.) Decrypt-Data = RC4 (Encrypt-Data, substr(SHA1-Key, 0, 15)); Decryption of encrypted data, used 16 bytes SHA1-Key;
	 */

	PurpleCipherContext *sha1_context;
	guchar k2[20];

	/* 1.) SHA1 sum	*/
	sha1_context = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(sha1_context, enc_key, SIPE_FT_KEY_LENGTH);
	purple_cipher_context_digest(sha1_context, sizeof(k2), k2, NULL);
	purple_cipher_context_destroy(sha1_context);

	/* 2.) RC4 decryption */
	*rc4_context = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(*rc4_context, "key_len", (gpointer)0x10); // only 16 chars key used
	purple_cipher_context_set_key(*rc4_context, k2);

}

static gchar* sipe_get_mac(const guchar *data, size_t data_len, const guchar *hash_key)
{
	/*
	 * 	Count MAC digest
	 *
	 *  	HMAC digest:
	 *  1.) SHA1-Key = SHA1sum (Hash-Key); Do SHA1 digest from Hash-Key, return 20 bytes SHA1-Key.
	 *  2.) MAC = HMAC_SHA1 (Decrypt-Data, substr(HMAC-Key,0,15)); Digest of decrypted file and SHA1-Key (used again only 16 bytes)
	 */

	PurpleCipherContext *sha1_context;
	PurpleCipherContext *hmac_context;
	guchar hmac_digest[20];
	guchar k2[20];

	/* 1.) SHA1 sum	*/
	sha1_context = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(sha1_context, hash_key, SIPE_FT_KEY_LENGTH);
	purple_cipher_context_digest(sha1_context, sizeof(k2), k2, NULL);
	purple_cipher_context_destroy(sha1_context);

	/* 2.) HMAC check */
	hmac_context = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(hmac_context, "hash", "sha1");
	purple_cipher_context_set_key_with_len(hmac_context, k2, 16);
	purple_cipher_context_append(hmac_context, data, data_len);
	purple_cipher_context_digest(hmac_context, sizeof(hmac_digest), hmac_digest, NULL);
	purple_cipher_context_destroy(hmac_context);

	return purple_base64_encode(hmac_digest, sizeof (hmac_digest));
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
	PurpleXfer *xfer;

	xfer = sipe_ft_new_xfer(gc, who);

	if (file != NULL)
		purple_xfer_request_accepted(xfer, file);
	else
		purple_xfer_request(xfer);
}

PurpleXfer * sipe_ft_new_xfer(PurpleConnection *gc, const char *who)
{
	PurpleAccount *account = purple_connection_get_account(gc);
	PurpleXfer *xfer = purple_xfer_new(account, PURPLE_XFER_SEND, who);

	if (xfer) {
		struct sipe_account_data *sip = purple_connection_get_protocol_data(gc);

		sipe_file_transfer *ft = g_new0(sipe_file_transfer, 1);
		ft->invitation_cookie = g_strdup_printf("%u", rand() % 1000000000);
		ft->sip = sip;

		xfer->data = ft;

		purple_xfer_set_init_fnc(xfer, sipe_ft_outgoing_init);
		purple_xfer_set_start_fnc(xfer,sipe_ft_outgoing_start);
		purple_xfer_set_end_fnc(xfer,sipe_ft_outgoing_stop);
		purple_xfer_set_request_denied_fnc(xfer, sipe_ft_request_denied);
		purple_xfer_set_write_fnc(xfer,sipe_ft_write);
		purple_xfer_set_cancel_send_fnc(xfer,sipe_ft_free_xfer_struct);
		purple_xfer_set_cancel_recv_fnc(xfer,sipe_ft_free_xfer_struct);
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

	purple_input_remove(xfer->watcher);
	xfer->watcher = 0;
	close(listenfd);

	purple_xfer_start(xfer,fd,NULL,0);
}

static
void sipe_ft_listen_socket_created(int listenfd, gpointer data)
{
	gchar *body;
	PurpleXfer *xfer = data;
	sipe_file_transfer *ft  = xfer->data;

	struct sockaddr_in addr;

	socklen_t socklen = sizeof (addr);

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
			       sipe_ft_get_suitable_local_ip(listenfd),
			       ntohs(addr.sin_port),
			       ft->auth_cookie);

	if (!ft->dialog) {
		struct sipe_account_data *sip = xfer->account->gc->proto_data;
		struct sip_session *session = sipe_session_find_or_add_im(sip, xfer->who);
		ft->dialog = sipe_dialog_find(session, xfer->who);
	}

	if (ft->dialog) {
		send_sip_request(ft->sip->gc, "MESSAGE", ft->dialog->with, ft->dialog->with,
				 "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
				 body, ft->dialog, NULL);
	}
	g_free(body);
}

#ifndef _WIN32
#include <net/if.h>
#include <sys/ioctl.h>
#else
#include <nspapi.h>
#endif

/*
 * Calling sizeof(struct ifreq) isn't always correct on
 * Mac OS X (and maybe others).
 */
#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

/*
 * Returns local IP address suitable for connection.
 *
 * purple_network_get_my_ip() will not do this, because it might return an
 * address within 169.254.x.x range that was assigned to interface disconnected
 * from the network (when multiple network adapters are available). This is a
 * copy-paste from libpurple's network.c, only change is that link local addresses
 * are ignored.
 *
 * Maybe this should be fixed in libpurple or some better solution found.
 */
static
const char * sipe_ft_get_suitable_local_ip(int fd)
{
	int source = (fd >= 0) ? fd : socket(PF_INET,SOCK_STREAM, 0);

	if (source >= 0) {
		char buffer[1024];
		static char ip[16];
		char *tmp;
		struct ifconf ifc;
		guint32 lhost = htonl(127 * 256 * 256 * 256 + 1);
		guint32 llocal = htonl((169 << 24) + (254 << 16));

		ifc.ifc_len = sizeof(buffer);
		ifc.ifc_req = (struct ifreq *)buffer;
		ioctl(source, SIOCGIFCONF, &ifc);

		if (fd < 0)
			close(source);

		tmp = buffer;
		while (tmp < buffer + ifc.ifc_len)
		{
			struct ifreq *ifr = (struct ifreq *)tmp;
			tmp += HX_SIZE_OF_IFREQ(*ifr);

			if (ifr->ifr_addr.sa_family == AF_INET)
			{
				struct sockaddr_in *sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
				if (sinptr->sin_addr.s_addr != lhost
				    && (sinptr->sin_addr.s_addr & htonl(0xFFFF0000)) != llocal)
				{
					long unsigned int add = ntohl(sinptr->sin_addr.s_addr);
					g_snprintf(ip, 16, "%lu.%lu.%lu.%lu",
						   ((add >> 24) & 255),
						   ((add >> 16) & 255),
						   ((add >> 8) & 255),
						   add & 255);

					return ip;
				}
			}
		}
	}

	return "0.0.0.0";
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
