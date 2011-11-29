/**
 * @file sipe-ft-tftp.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-crypt.h"
#include "sipe-dialog.h"
#include "sipe-digest.h"
#include "sipe-ft.h"
#include "sipe-nls.h"
#include "sipe-utils.h"

#define BUFFER_SIZE 50
#define SIPE_FT_CHUNK_HEADER_LENGTH  3

static gboolean
write_exact(struct sipe_file_transfer_private *ft_private, const guchar *data,
	    gsize size)
{
	gssize bytes_written = sipe_backend_ft_write(SIPE_FILE_TRANSFER_PUBLIC,
						     data, size);
	if ((bytes_written < 0) || ((gsize) bytes_written != size))
		return FALSE;
	return TRUE;
}

static gboolean
read_exact(struct sipe_file_transfer_private *ft_private, guchar *data,
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

static gboolean
read_line(struct sipe_file_transfer_private *ft_private, guchar *data,
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


static void
raise_ft_socket_read_error_and_cancel(struct sipe_file_transfer_private *ft_private)
{
	sipe_ft_raise_error_and_cancel(ft_private, _("Socket read failed"));
}

static void
raise_ft_socket_write_error_and_cancel(struct sipe_file_transfer_private *ft_private)
{
	sipe_ft_raise_error_and_cancel(ft_private, _("Socket write failed"));
}

static gpointer
sipe_cipher_context_init(const guchar *enc_key)
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

static gpointer
sipe_hmac_context_init(const guchar *hash_key)
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

static gchar *
sipe_hmac_finalize(gpointer hmac_context)
{
	guchar hmac_digest[SIPE_DIGEST_FILETRANSFER_LENGTH];

	/*  MAC = Digest of decrypted file and SHA1-Key (used again only 16 bytes) */
	sipe_digest_ft_end(hmac_context, hmac_digest);

	return g_base64_encode(hmac_digest, sizeof (hmac_digest));
}

void
sipe_core_tftp_incoming_start(struct sipe_file_transfer *ft, gsize total_size)
{
	static const guchar VER[]    = "VER MSN_SECURE_FTP\r\n";
	static const guchar TFR[]    = "TFR\r\n";
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
		sipe_ft_raise_error_and_cancel(ft_private,
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

gboolean
sipe_core_tftp_incoming_stop(struct sipe_file_transfer *ft)
{
	static const guchar BYE[] = "BYE 16777989\r\n";
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
		sipe_ft_raise_error_and_cancel(ft_private,
					       _("Received MAC is corrupted"));
		return FALSE;
	}

	/* Check MAC */
	mac  = g_strndup(buffer + MAC_OFFSET, mac_len - MAC_OFFSET);
	mac1 = sipe_hmac_finalize(ft_private->hmac_context);
	if (!sipe_strequal(mac, mac1)) {
		g_free(mac1);
		g_free(mac);
		sipe_ft_raise_error_and_cancel(ft_private,
					       _("Received file is corrupted"));
		return(FALSE);
	}
	g_free(mac1);
	g_free(mac);

	return(TRUE);
}

void
sipe_core_tftp_outgoing_start(struct sipe_file_transfer *ft, gsize total_size)
{
	static const guchar VER[] = "VER MSN_SECURE_FTP\r\n";

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
		sipe_ft_raise_error_and_cancel(ft_private,
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
		sipe_ft_raise_error_and_cancel(ft_private,
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

gboolean
sipe_core_tftp_outgoing_stop(struct sipe_file_transfer *ft)
{
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

static void raise_ft_error(struct sipe_file_transfer_private *ft_private,
			   const gchar *errmsg)
{
	gchar *tmp = g_strdup_printf("%s: %s", errmsg,
				     sipe_backend_ft_get_error(SIPE_FILE_TRANSFER_PUBLIC));
	sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, tmp);
	g_free(tmp);
}

gssize
sipe_core_tftp_read(struct sipe_file_transfer *ft, guchar **buffer,
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

gssize
sipe_core_tftp_write(struct sipe_file_transfer *ft, const guchar *buffer,
		     gsize size)
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
		guchar local_buf[16 + 1]; /* space for string terminator */
		guchar hdr_buf[SIPE_FT_CHUNK_HEADER_LENGTH];

		/* Check if receiver did not cancel the transfer
		   before it is finished */
		bytes_read = sipe_backend_ft_read(SIPE_FILE_TRANSFER_PUBLIC,
						  local_buf,
						  sizeof(local_buf) - 1);
		local_buf[sizeof(local_buf) - 1] = '\0';

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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
