/**
 * @file sipe-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-crypt.h"
#include "sipe-dialog.h"
#include "sipe-digest.h"
#include "sipe-ft.h"
#include "sipe-nls.h"
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
 * you want to *send* files to other users. Receiving files uses an outgoing
 * connection and should therefore automatically penetrate your firewall.
 */
#define SIPE_FT_TCP_PORT_MIN 6891
#define SIPE_FT_TCP_PORT_MAX 6901

/**
 * File transport (private part)
 */
struct sipe_file_transfer_private {
	struct sipe_file_transfer public;

	struct sipe_core_private *sipe_private;

	guchar encryption_key[SIPE_FT_KEY_LENGTH];
	guchar hash_key[SIPE_FT_KEY_LENGTH];
	unsigned auth_cookie;
	gchar *invitation_cookie;

	struct sip_dialog *dialog;

	gpointer cipher_context;
	gpointer hmac_context;

	gsize bytes_remaining_chunk;

	guchar *encrypted_outbuf;
	guchar *outbuf_ptr;
	gsize outbuf_size;
};
#define SIPE_FILE_TRANSFER_PUBLIC  ((struct sipe_file_transfer *) ft_private)
#define SIPE_FILE_TRANSFER_PRIVATE ((struct sipe_file_transfer_private *) ft)

static void raise_ft_error(struct sipe_file_transfer_private *ft_private,
			   const gchar *errmsg)
{
	gchar *tmp = g_strdup_printf("%s: %s", errmsg,
				     sipe_backend_ft_get_error(SIPE_FILE_TRANSFER_PUBLIC));
	sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, tmp);
	g_free(tmp);
}

static void raise_ft_error_and_cancel(struct sipe_file_transfer_private *ft_private,
				      const gchar *errmsg)
{
	sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, errmsg);
	sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER_PUBLIC);
}

static void raise_ft_socket_read_error_and_cancel(struct sipe_file_transfer_private *ft_private)
{
	raise_ft_error_and_cancel(ft_private, _("Socket read failed"));
}

static void raise_ft_socket_write_error_and_cancel(struct sipe_file_transfer_private *ft_private)
{
	raise_ft_error_and_cancel(ft_private, _("Socket write failed"));
}

static gboolean read_exact(struct sipe_file_transfer_private *ft_private,
			   guchar *data,
			   gsize size)
{
	const gulong READ_TIMEOUT = 10000000;
	gulong time_spent = 0;

	while (size) {
		gssize bytes_read = sipe_backend_ft_read(SIPE_FILE_TRANSFER_PUBLIC,
							 data, size);
		if (bytes_read == 0) {
			g_usleep(100000);
			time_spent += 100000;
		} else if (bytes_read < 0 || time_spent > READ_TIMEOUT) {
			return FALSE;
		} else {
			size -= bytes_read;
			data += bytes_read;
			time_spent = 0;
		}
	}
	return TRUE;	
}

static gboolean read_line(struct sipe_file_transfer_private *ft_private,
			  guchar *data,
			  gsize size)
{
	gsize pos = 0;

	if (size < 2) return FALSE;

	memset(data, 0, size--);
	do {
		if (!read_exact(ft_private, data + pos, 1))
			return FALSE;
	} while ((data[pos] != '\n') && (++pos < size));

	/* Buffer too short? */
	if ((pos == size) && (data[pos - 1] != '\n')) {
		return FALSE;
	}

	return TRUE;
}

static gboolean write_exact(struct sipe_file_transfer_private *ft_private,
			    const guchar *data,
			    gsize size)
{
	gssize bytes_written = sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC,
						     data, size);
	if ((bytes_written < 0) || ((gsize) bytes_written != size))
		return FALSE;
	return TRUE;
}

static void generate_key(guchar *buffer, gsize size)
{
	gsize i = 0;
	while (i < size) buffer[i++] = rand();
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

static gchar *sipe_hmac_finalize(gpointer hmac_context)
{
	guchar hmac_digest[SIPE_DIGEST_FILETRANSFER_LENGTH];

	/*  MAC = Digest of decrypted file and SHA1-Key (used again only 16 bytes) */
	sipe_digest_ft_end(hmac_context, hmac_digest);

	return g_base64_encode(hmac_digest, sizeof (hmac_digest));
}

struct sipe_file_transfer *sipe_core_ft_allocate(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_file_transfer_private *ft_private =
		g_new0(struct sipe_file_transfer_private, 1);

	ft_private->sipe_private      = sipe_private;
	ft_private->invitation_cookie = g_strdup_printf("%u", rand() % 1000000000);

	return(SIPE_FILE_TRANSFER_PUBLIC);
}

static void sipe_ft_deallocate(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;

	if (ft->backend_private)
		sipe_backend_ft_deallocate(ft);

	if (ft_private->cipher_context)
		sipe_crypt_ft_destroy(ft_private->cipher_context);

	if (ft_private->hmac_context)
		sipe_digest_ft_destroy(ft_private->hmac_context);

	g_free(ft_private->invitation_cookie);
	g_free(ft_private->encrypted_outbuf);
	g_free(ft_private);
}

void sipe_core_ft_deallocate(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sip_dialog *dialog = ft_private->dialog;

	if (dialog)
		dialog->filetransfers = g_slist_remove(dialog->filetransfers, ft_private);

	sipe_ft_deallocate(ft);
}

static void sipe_ft_request(struct sipe_file_transfer_private *ft_private,
			    const gchar *body)
{
	struct sip_dialog *dialog = ft_private->dialog;
	sip_transport_request(ft_private->sipe_private,
			      "MESSAGE",
			      dialog->with,
			      dialog->with,
			      "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n",
			      body,
			      dialog,
			      NULL);
}

void sipe_core_ft_cancel(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;

	gchar *body = g_strdup_printf("Invitation-Command: CANCEL\r\n"
				      "Invitation-Cookie: %s\r\n"
				      "Cancel-Code: REJECT\r\n",
				      ft_private->invitation_cookie);
	sipe_ft_request(ft_private, body);
	g_free(body);
}

void sipe_core_ft_incoming_init(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	gchar *b64_encryption_key = g_base64_encode(ft_private->encryption_key,
						    SIPE_FT_KEY_LENGTH);
	gchar *b64_hash_key = g_base64_encode(ft_private->hash_key,
					      SIPE_FT_KEY_LENGTH);

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
				      ft_private->invitation_cookie,
				      b64_encryption_key,
				      b64_hash_key
                                      /*,sipe_backend_network_ip_address()*/
		);
	sipe_ft_request(ft_private, body);

	g_free(body);
	g_free(b64_hash_key);
	g_free(b64_encryption_key);
}

void sipe_core_ft_incoming_accept(struct sipe_file_transfer *ft,
				  const gchar *who,
				  int fd,
				  unsigned short port)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	gchar *body;

	ft_private->auth_cookie = rand() % 1000000000;

	body = g_strdup_printf("Invitation-Command: ACCEPT\r\n"
			       "Invitation-Cookie: %s\r\n"
			       "IP-Address: %s\r\n"
			       "Port: %u\r\n"
			       "PortX: 11178\r\n"
			       "AuthCookie: %u\r\n"
			       "Request-Data: IP-Address:\r\n",
			       ft_private->invitation_cookie,
			       sipe_utils_get_suitable_local_ip(fd),
			       port,
			       ft_private->auth_cookie);

	if (!ft_private->dialog) {
		struct sip_session *session = sipe_session_find_or_add_im(ft_private->sipe_private,
									  who);
		ft_private->dialog = sipe_dialog_find(session, who);
	}

	if (ft_private->dialog) {
		sipe_ft_request(ft_private, body);
	}
	g_free(body);
}

void sipe_core_ft_incoming_start(struct sipe_file_transfer *ft,
				 gsize total_size)
{
	static const guchar VER[]    = "VER MSN_SECURE_FTP\r\n";
	static const guchar TFR[]    = "TFR\r\n";
	const gsize BUFFER_SIZE      = 50;
	const gsize FILE_SIZE_OFFSET = 4;

	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	guchar buf[BUFFER_SIZE];
	gchar *request;
	gsize file_size;

	if (!write_exact(ft_private, VER, sizeof(VER) - 1)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}
	if (!read_line(ft_private, buf, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}

	request = g_strdup_printf("USR %s %u\r\n",
				  ft_private->sipe_private->username,
				  ft_private->auth_cookie);
	if (!write_exact(ft_private, (guchar *)request, strlen(request))) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		g_free(request);
		return;
	}
	g_free(request);

	if (!read_line(ft_private, buf, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}

	file_size = g_ascii_strtoull((gchar *) buf + FILE_SIZE_OFFSET, NULL, 10);
	if (file_size != total_size) {
		raise_ft_error_and_cancel(ft_private,
					  _("File size is different from the advertised value."));
		return;
	}

	if (!sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC, TFR, sizeof(TFR) - 1)) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		return;
	}

	ft_private->bytes_remaining_chunk = 0;
	ft_private->cipher_context = sipe_cipher_context_init(ft_private->encryption_key);
	ft_private->hmac_context   = sipe_hmac_context_init(ft_private->hash_key);
}

gboolean sipe_core_ft_incoming_stop(struct sipe_file_transfer *ft)
{
	static const guchar BYE[] = "BYE 16777989\r\n";
	const gsize BUFFER_SIZE   = 50;
	const gsize MAC_OFFSET    = 4;

	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	gchar buffer[BUFFER_SIZE];
	gsize mac_len;
	gchar *mac;
	gchar *mac1;

	if (!sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC, BYE, sizeof(BYE) - 1)) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		return FALSE;
	}

	if (!read_line(ft_private, (guchar *) buffer, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return FALSE;
	}

	mac_len = strlen(buffer);
	if (mac_len < (MAC_OFFSET)) {
		raise_ft_error_and_cancel(ft_private,
					  _("Received MAC is corrupted"));
		return FALSE;
	}

	/* Check MAC */
	mac  = g_strndup(buffer + MAC_OFFSET, mac_len - MAC_OFFSET);
	mac1 = sipe_hmac_finalize(ft_private->hmac_context);
	if (!sipe_strequal(mac, mac1)) {
		g_free(mac1);
		g_free(mac);
		raise_ft_error_and_cancel(ft_private,
					  _("Received file is corrupted"));
		return(FALSE);
	}
	g_free(mac1);
	g_free(mac);

	return(TRUE);
}

void sipe_core_ft_outgoing_init(struct sipe_file_transfer *ft,
				const gchar *filename, gsize size,
				const gchar *who)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sipe_core_private *sipe_private = ft_private->sipe_private;
	struct sip_dialog *dialog;

	gchar *body = g_strdup_printf("Application-Name: File Transfer\r\n"
				      "Application-GUID: {5D3E02AB-6190-11d3-BBBB-00C04F795683}\r\n"
				      "Invitation-Command: INVITE\r\n"
				      "Invitation-Cookie: %s\r\n"
				      "Application-File: %s\r\n"
				      "Application-FileSize: %" G_GSIZE_FORMAT "\r\n"
				      //"Connectivity: N\r\n" TODO
				      "Encryption: R\r\n", // TODO: non encrypted file transfer support
				      ft_private->invitation_cookie,
				      filename,
				      size);

	struct sip_session *session = sipe_session_find_or_add_im(sipe_private, who);

	// Queue the message
	sipe_session_enqueue_message(session, body, "text/x-msmsgsinvite");

	dialog = sipe_dialog_find(session, who);
	if (dialog && !dialog->outgoing_invite) {
		sipe_im_process_queue(sipe_private, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sipe_private, session, who, body, "text/x-msmsgsinvite", NULL, FALSE);
		dialog = sipe_dialog_find(session, who);
	}

	dialog->filetransfers = g_slist_append(dialog->filetransfers, ft_private);
	ft_private->dialog = dialog;

	g_free(body);
}

void sipe_core_ft_outgoing_start(struct sipe_file_transfer *ft,
				 gsize total_size)
{
	static const guchar VER[] = "VER MSN_SECURE_FTP\r\n";
	const gsize BUFFER_SIZE  = 50;

	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	guchar buf[BUFFER_SIZE];
	gchar **parts;
	unsigned auth_cookie_received;
	gboolean users_match;

	if (!read_line(ft_private, buf, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}

	if (!sipe_strequal((gchar *)buf, (gchar *)VER)) {
		raise_ft_error_and_cancel(ft_private,
					  _("File transfer initialization failed."));
		SIPE_DEBUG_INFO("File transfer VER string incorrect, received: %s expected: %s",
				buf, VER);
		return;
	}

	if (!write_exact(ft_private, VER, sizeof(VER) - 1)) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		return;
	}

	if (!read_line(ft_private, buf, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}

	parts = g_strsplit((gchar *)buf, " ", 3);
	auth_cookie_received = g_ascii_strtoull(parts[2], NULL, 10);
	/* dialog->with has 'sip:' prefix, skip these four characters */
	users_match = sipe_strcase_equal(parts[1],
					 (ft_private->dialog->with + 4));
	g_strfreev(parts);

	SIPE_DEBUG_INFO("File transfer authentication: %s Expected: USR %s %u",
			buf,
			ft_private->dialog->with + 4,
			ft_private->auth_cookie);

	if (!users_match ||
	    (ft_private->auth_cookie != auth_cookie_received)) {
		raise_ft_error_and_cancel(ft_private,
					  _("File transfer authentication failed."));
		return;
	}

	g_sprintf((gchar *)buf, "FIL %" G_GSIZE_FORMAT "\r\n", total_size);
	if (!write_exact(ft_private, buf, strlen((gchar *)buf))) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		return;
	}

	/* TFR */
	if (!read_line(ft_private ,buf, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return;
	}

	ft_private->bytes_remaining_chunk = 0;
	ft_private->cipher_context = sipe_cipher_context_init(ft_private->encryption_key);
	ft_private->hmac_context   = sipe_hmac_context_init(ft_private->hash_key);
}

gboolean sipe_core_ft_outgoing_stop(struct sipe_file_transfer *ft)
{
	gsize BUFFER_SIZE = 50;

	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	guchar buffer[BUFFER_SIZE];
	gchar *mac;
	gsize mac_len;

	/* BYE */
	if (!read_line(ft_private, buffer, BUFFER_SIZE)) {
		raise_ft_socket_read_error_and_cancel(ft_private);
		return FALSE;
	}

	mac = sipe_hmac_finalize(ft_private->hmac_context);
	g_sprintf((gchar *)buffer, "MAC %s \r\n", mac);
	g_free(mac);

	mac_len = strlen((gchar *)buffer);
	/* There must be this zero byte between mac and \r\n */
	buffer[mac_len - 3] = 0;

	if (!write_exact(ft_private, buffer, mac_len)) {
		raise_ft_socket_write_error_and_cancel(ft_private);
		return FALSE;
	}

	return TRUE;
}

gssize sipe_core_ft_read(struct sipe_file_transfer *ft, guchar **buffer,
			 gsize bytes_remaining, gsize bytes_available)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	gsize  bytes_to_read;
	gssize bytes_read;

	if (ft_private->bytes_remaining_chunk == 0) {
		guchar hdr_buf[SIPE_FT_CHUNK_HEADER_LENGTH];

		/* read chunk header */
		if (!read_exact(ft_private, hdr_buf, sizeof(hdr_buf))) {
			raise_ft_error(ft_private, _("Socket read failed"));
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
		ft_private->bytes_remaining_chunk =
			hdr_buf[1] + (hdr_buf[2] << 8);
	}

	bytes_to_read = MIN(bytes_remaining, bytes_available);
	bytes_to_read = MIN(bytes_to_read, ft_private->bytes_remaining_chunk);

	*buffer = g_malloc(bytes_to_read);
	if (!*buffer) {
		sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, _("Out of memory"));
		SIPE_DEBUG_ERROR("sipe_core_ft_read: can't allocate %" G_GSIZE_FORMAT " bytes for receive buffer",
				 bytes_to_read);
		return -1;
	}

	bytes_read = sipe_backend_ft_read(SIPE_FILE_TRANSFER_PUBLIC, *buffer, bytes_to_read);
	if (bytes_read < 0) {
		raise_ft_error(ft_private, _("Socket read failed"));
		g_free(*buffer);
		*buffer = NULL;
		return -1;
	}

	if (bytes_read > 0) {
		guchar *decrypted = g_malloc(bytes_read);

		if (!decrypted) {
			sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, _("Out of memory"));
			SIPE_DEBUG_ERROR("sipe_core_ft_read: can't allocate %" G_GSIZE_FORMAT " bytes for decryption buffer",
					 (gsize)bytes_read);
			g_free(*buffer);
			*buffer = NULL;
			return -1;
		}
		sipe_crypt_ft_stream(ft_private->cipher_context,
				     *buffer, bytes_read, decrypted);
		g_free(*buffer);
		*buffer = decrypted;

		sipe_digest_ft_update(ft_private->hmac_context,
				      decrypted, bytes_read);

		ft_private->bytes_remaining_chunk -= bytes_read;
	}

	return(bytes_read);
}

gssize sipe_core_ft_write(struct sipe_file_transfer *ft,
			  const guchar *buffer, gsize size)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	gssize bytes_written;

	/* When sending data via server with ForeFront installed, block bigger than
	 * this default causes ending of transmission. Hard limit block to this value
	 * when libpurple sends us more data. */
	const gsize DEFAULT_BLOCK_SIZE = 2045;
	if (size > DEFAULT_BLOCK_SIZE)
		size = DEFAULT_BLOCK_SIZE;

	if (ft_private->bytes_remaining_chunk == 0) {
		gssize bytes_read;
		guchar local_buf[16];
		guchar hdr_buf[SIPE_FT_CHUNK_HEADER_LENGTH];

		memset(local_buf, 0, sizeof local_buf);

		/* Check if receiver did not cancel the transfer
		   before it is finished */
		bytes_read = sipe_backend_ft_read(SIPE_FILE_TRANSFER_PUBLIC,
						  local_buf,
						  sizeof(local_buf));
		if (bytes_read < 0) {
			sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC,
					      _("Socket read failed"));
			return -1;
		} else if ((bytes_read > 0) &&
			   (g_str_has_prefix((gchar *)local_buf, "CCL\r\n") ||
			    g_str_has_prefix((gchar *)local_buf, "BYE 2164261682\r\n"))) {
			return -1;
		}

		if (ft_private->outbuf_size < size) {
			g_free(ft_private->encrypted_outbuf);
			ft_private->outbuf_size = size;
			ft_private->encrypted_outbuf = g_malloc(ft_private->outbuf_size);
			if (!ft_private->encrypted_outbuf) {
				sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC,
						      _("Out of memory"));
				SIPE_DEBUG_ERROR("sipe_core_ft_write: can't allocate %" G_GSIZE_FORMAT " bytes for send buffer",
						 ft_private->outbuf_size);
				return -1;
			}
		}

		ft_private->bytes_remaining_chunk = size;
		ft_private->outbuf_ptr = ft_private->encrypted_outbuf;
		sipe_crypt_ft_stream(ft_private->cipher_context,
				     buffer, size,
				     ft_private->encrypted_outbuf);
		sipe_digest_ft_update(ft_private->hmac_context,
				      buffer, size);

		/* chunk header format:
		 *
		 *  0:  00   unknown             (always zero?)
		 *  1:  LL   chunk size in bytes (low byte)
		 *  2:  HH   chunk size in bytes (high byte)
		 *
		 * Convert size from host order to little endian
		 */
		hdr_buf[0] = 0;
		hdr_buf[1] = (ft_private->bytes_remaining_chunk & 0x00FF);
		hdr_buf[2] = (ft_private->bytes_remaining_chunk & 0xFF00) >> 8;

		/* write chunk header */
		if (!sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC, hdr_buf, sizeof(hdr_buf))) {
			sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC,
					      _("Socket write failed"));
			return -1;
		}
	}

	bytes_written = sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC,
					      ft_private->outbuf_ptr,
					      ft_private->bytes_remaining_chunk);
	if (bytes_written < 0) {
		raise_ft_error(ft_private, _("Socket write failed"));
	} else if (bytes_written > 0) {
		ft_private->bytes_remaining_chunk -= bytes_written;
		ft_private->outbuf_ptr += bytes_written;
	}

	return bytes_written;
}

void sipe_ft_incoming_transfer(struct sipe_core_private *sipe_private,
			       struct sip_dialog *dialog,
			       const GSList *body)
{
	struct sipe_file_transfer_private *ft_private;
	gsize file_size;

	ft_private = g_new0(struct sipe_file_transfer_private, 1);
	ft_private->sipe_private = sipe_private;

	generate_key(ft_private->encryption_key, SIPE_FT_KEY_LENGTH);
	generate_key(ft_private->hash_key, SIPE_FT_KEY_LENGTH);

	ft_private->invitation_cookie = g_strdup(sipe_utils_nameval_find(body, "Invitation-Cookie"));

	ft_private->dialog = dialog;

	file_size = g_ascii_strtoull(sipe_utils_nameval_find(body,
							     "Application-FileSize"),
				     NULL, 10);
	sipe_backend_ft_incoming(SIPE_CORE_PUBLIC,
				 SIPE_FILE_TRANSFER_PUBLIC,
				 dialog->with,
				 sipe_utils_nameval_find(body, "Application-File"),
				 file_size);

	if (ft_private->public.backend_private != NULL) {
		ft_private->dialog->filetransfers = g_slist_append(ft_private->dialog->filetransfers, ft_private);
	} else {
		sipe_ft_deallocate(SIPE_FILE_TRANSFER_PUBLIC);
	}
}

static struct sipe_file_transfer_private *
sipe_find_ft(const struct sip_dialog *dialog, const gchar *inv_cookie)
{
	GSList *ftlist = dialog->filetransfers;
	for (; ftlist != NULL; ftlist = ftlist->next) {
		struct sipe_file_transfer_private *ft_private = ftlist->data;
		if (sipe_strequal(ft_private->invitation_cookie, inv_cookie))
			return ft_private;
	}
	return NULL;
}

void sipe_ft_incoming_accept(struct sip_dialog *dialog, const GSList *body)
{
	const gchar *inv_cookie = sipe_utils_nameval_find(body, "Invitation-Cookie");
	struct sipe_file_transfer_private *ft_private = sipe_find_ft(dialog, inv_cookie);

	if (ft_private) {
		const gchar *ip           = sipe_utils_nameval_find(body, "IP-Address");
		const gchar *port_str     = sipe_utils_nameval_find(body, "Port");
		const gchar *auth_cookie  = sipe_utils_nameval_find(body, "AuthCookie");
		const gchar *enc_key_b64  = sipe_utils_nameval_find(body, "Encryption-Key");
		const gchar *hash_key_b64 = sipe_utils_nameval_find(body, "Hash-Key");

		if (auth_cookie)
			ft_private->auth_cookie = g_ascii_strtoull(auth_cookie,
								   NULL, 10);
		if (enc_key_b64) {
			gsize ret_len;
			guchar *enc_key = g_base64_decode(enc_key_b64,
							  &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft_private->encryption_key,
				       enc_key, SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(ft_private,
							  _("Received encryption key has wrong size."));
				g_free(enc_key);
				return;
			}
			g_free(enc_key);
		}
		if (hash_key_b64) {
			gsize ret_len;
			guchar *hash_key = g_base64_decode(hash_key_b64,
							   &ret_len);
			if (ret_len == SIPE_FT_KEY_LENGTH) {
				memcpy(ft_private->hash_key,
				       hash_key, SIPE_FT_KEY_LENGTH);
			} else {
				raise_ft_error_and_cancel(ft_private,
							  _("Received hash key has wrong size."));
				g_free(hash_key);
				return;
			}
			g_free(hash_key);
		}


		if (ip && port_str) {
			unsigned short port = g_ascii_strtoull(port_str,
							       NULL, 10);

			sipe_backend_ft_incoming_accept(SIPE_FILE_TRANSFER_PUBLIC,
							ip,
							port,
							port);
		} else {
			if (!sipe_backend_ft_incoming_accept(SIPE_FILE_TRANSFER_PUBLIC,
							     NULL,
							     SIPE_FT_TCP_PORT_MIN,
							     SIPE_FT_TCP_PORT_MAX)) {
				raise_ft_error_and_cancel(ft_private,
							  _("Could not create listen socket"));
				return;
			}
		}
	}
}

void sipe_ft_incoming_cancel(struct sip_dialog *dialog, const GSList *body)
{
	const gchar *inv_cookie = sipe_utils_nameval_find(body, "Invitation-Cookie");
	struct sipe_file_transfer_private *ft_private = sipe_find_ft(dialog, inv_cookie);

	if (ft_private)
		sipe_backend_ft_cancel_remote(SIPE_FILE_TRANSFER_PUBLIC);
}

GSList *sipe_ft_parse_msg_body(const gchar *body)
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
