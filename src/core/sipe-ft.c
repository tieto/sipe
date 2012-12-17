/**
 * @file sipe-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-12 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-crypt.h"
#include "sipe-dialog.h"
#include "sipe-digest.h"
#include "sipe-ft.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-utils.h"

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

void sipe_ft_raise_error_and_cancel(struct sipe_file_transfer_private *ft_private,
				    const gchar *errmsg)
{
	sipe_backend_ft_error(SIPE_FILE_TRANSFER_PUBLIC, errmsg);
	sipe_backend_ft_cancel_local(SIPE_FILE_TRANSFER_PUBLIC);
}

static void generate_key(guchar *buffer, gsize size)
{
	gsize i = 0;
	while (i < size) buffer[i++] = rand();
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

	if (ft_private->listendata)
		sipe_backend_network_listen_cancel(ft_private->listendata);

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

static void
send_ft_accept(struct sipe_file_transfer_private *ft_private,
	       gboolean send_enc_key,
	       gboolean send_connect_data,
	       gboolean sender_connect)
{
	GString *body = g_string_new("");

	g_string_append_printf(body,
			       "Invitation-Command: ACCEPT\r\n"
			       "Request-Data: IP-Address:\r\n"
			       "Invitation-Cookie: %s\r\n",
			       ft_private->invitation_cookie);

	if (send_enc_key) {
		gchar *b64_encryption_key;
		gchar *b64_hash_key;

		b64_encryption_key = g_base64_encode(ft_private->encryption_key,
						     SIPE_FT_KEY_LENGTH);
		b64_hash_key = g_base64_encode(ft_private->hash_key,
					       SIPE_FT_KEY_LENGTH);

		g_string_append_printf(body,
				       "Encryption-Key: %s\r\n"
				       "Hash-Key: %s\r\n",
				       b64_encryption_key,
				       b64_hash_key);

		g_free(b64_hash_key);
		g_free(b64_encryption_key);
	}

	if (send_connect_data) {
		struct sipe_core_private *sipe_private = ft_private->sipe_private;

		g_string_append_printf(body,
				       "IP-Address: %s\r\n"
				       "Port: %d\r\n"
				       "PortX: 11178\r\n"
				       "AuthCookie: %u\r\n",
				       sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
				       ft_private->port,
				       ft_private->auth_cookie);
	}

	if (sender_connect) {
		g_string_append(body,
				"Sender-Connect: TRUE\r\n");
	}

	sipe_ft_request(ft_private, body->str);

	g_string_free(body, TRUE);
}

static void
listen_socket_created_cb(unsigned short port, gpointer data)
{
	struct sipe_file_transfer *ft = data;

	SIPE_FILE_TRANSFER_PRIVATE->port = port;
	SIPE_FILE_TRANSFER_PRIVATE->auth_cookie = rand() % 1000000000;

	if (sipe_backend_ft_is_incoming(ft))
		send_ft_accept(SIPE_FILE_TRANSFER_PRIVATE, TRUE, TRUE, TRUE);
	else
		send_ft_accept(SIPE_FILE_TRANSFER_PRIVATE, FALSE, TRUE, FALSE);
}

static void
client_connected_cb(struct sipe_backend_fd *fd, gpointer data)
{
	struct sipe_file_transfer *ft = data;

	SIPE_FILE_TRANSFER_PRIVATE->listendata = NULL;

	if (!sipe_backend_fd_is_valid(fd)) {
		sipe_backend_ft_error(ft, _("Socket read failed"));
		sipe_backend_ft_cancel_local(ft);
	} else {
		sipe_backend_ft_start(ft, fd, NULL, 0);
	}

	sipe_backend_fd_free(fd);
}

void sipe_core_ft_incoming_init(struct sipe_file_transfer *ft)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;

	if (ft_private->peer_using_nat) {
		ft_private->listendata =
			sipe_backend_network_listen_range(SIPE_FT_TCP_PORT_MIN,
							  SIPE_FT_TCP_PORT_MAX,
							  listen_socket_created_cb,
							  client_connected_cb,
							  ft);
	} else {
		send_ft_accept(ft_private, TRUE, FALSE, FALSE);
	}
}

void sipe_core_ft_outgoing_init(struct sipe_file_transfer *ft,
				const gchar *filename, gsize size,
				const gchar *who)
{
	struct sipe_file_transfer_private *ft_private = SIPE_FILE_TRANSFER_PRIVATE;
	struct sipe_core_private *sipe_private = ft_private->sipe_private;
	struct sip_dialog *dialog;

	const gchar *ip = sipe_backend_network_ip_address(SIPE_CORE_PUBLIC);
	gchar *body = g_strdup_printf("Application-Name: File Transfer\r\n"
				      "Application-GUID: {5D3E02AB-6190-11d3-BBBB-00C04F795683}\r\n"
				      "Invitation-Command: INVITE\r\n"
				      "Invitation-Cookie: %s\r\n"
				      "Application-File: %s\r\n"
				      "Application-FileSize: %" G_GSIZE_FORMAT "\r\n"
				      "%s"
				      "Encryption: R\r\n", // TODO: non encrypted file transfer support
				      ft_private->invitation_cookie,
				      filename,
				      size,
				      sipe_utils_ip_is_private(ip) ? "Connectivity: N\r\n" : "");

	struct sip_session *session = sipe_session_find_or_add_im(sipe_private, who);

	// Queue the message
	sipe_session_enqueue_message(session, body, "text/x-msmsgsinvite");

	dialog = sipe_dialog_find(session, who);
	if (dialog && !dialog->outgoing_invite) {
		sipe_im_process_queue(sipe_private, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_im_invite(sipe_private, session, who, body, "text/x-msmsgsinvite", NULL, FALSE);
		dialog = sipe_dialog_find(session, who);
	}

	dialog->filetransfers = g_slist_append(dialog->filetransfers, ft_private);
	ft_private->dialog = dialog;

	g_free(body);
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
	ft_private->peer_using_nat = sipe_strequal(sipe_utils_nameval_find(body, "Connectivity"), "N");

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
				sipe_ft_raise_error_and_cancel(ft_private,
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
				sipe_ft_raise_error_and_cancel(ft_private,
							  _("Received hash key has wrong size."));
				g_free(hash_key);
				return;
			}
			g_free(hash_key);
		}


		if (ip && port_str) {
			sipe_backend_ft_start(SIPE_FILE_TRANSFER_PUBLIC, NULL, ip,
					      g_ascii_strtoull(port_str, NULL, 10));
		} else {
			ft_private->listendata =
				sipe_backend_network_listen_range(SIPE_FT_TCP_PORT_MIN,
								  SIPE_FT_TCP_PORT_MAX,
								  listen_socket_created_cb,
								  client_connected_cb,
								  ft_private);
			if (!ft_private->listendata)
				sipe_ft_raise_error_and_cancel(ft_private,
							  _("Could not create listen socket"));
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
