/**
 * @file sipe-tls-tester.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
 *
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
 *
 *
 * TLS handshake implementation (sipe-tls.c) tester
 *
 * Example test setup using OpenSSL:
 *
 * - Setting up the server certificate:
 *
 *    $ openssl req -new -keyout server.pem -out server.req
 *    $ openssl x509 -req -in server.req -signkey server.pem -out server.cert
 *
 * - Running the test server in one shell with same parameters used by Lync:
 *
 *    $ openssl s_server -accept 8443 -debug -msg \
 *              -cert server.cert -key server.pem \
 *              -tls1 -verify 0 -cipher RC4-SHA
 *
 * - Running the test program in another shell:
 *
 *    $ sipe_tls_tester
 *
 *   You can add <host>[:<port>] to connect to a server on another machine
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

#include <glib.h>

#include "sipe-common.h" /* coverity[hfa: FALSE] */
#include "sipe-backend.h"
#include "sipe-cert-crypto.h"
#include "sipe-crypt.h"
#include "sipe-tls.h"

/*
 * Stubs
 */
gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG(%d): %s\n", level, msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	gchar *newformat = g_strdup_printf("DEBUG(%d): %s\n", level, format);

	va_start(ap, format);
	vprintf(newformat, ap);
	va_end(ap);

	g_free(newformat);
}

/*
 * Tester code
 */
struct record {
	gsize length;
	guchar *msg;
};

static guchar *read_tls_record(int fd,
			       gsize *in_length)
{
	GSList *fragments = NULL;
	guchar *merged    = NULL;
	gsize length      = 0;
	static gchar buffer[10000];

	while (1) {
		struct pollfd fds[] = {
			{ fd, POLLIN, 0 }
		};
		int result;
		struct record *record;

		/* Read one chunk */
		result = poll(fds, 1, 500 /* [milliseconds] */);
		if (result < 0) {
			printf("poll failed: %s\n", strerror(errno));
			break;
		}
		if (result == 0) {
			if (!fragments) {
				printf("timeout.\n");
				continue;
			} else {
				printf("reading done.\n");
				break;
			}
		}

		result = read(fd, buffer, sizeof(buffer));
		if (result < 0) {
			printf("read failed: %s\n", strerror(errno));
			break;
		}
		if (result == 0) {
			printf("server closed connection: %s\n",
			       strerror(errno));
			break;
		}

		printf("received %d bytes from server\n", result);
		record = g_new0(struct record, 1);
		record->length  = result;
		record->msg     = g_memdup(buffer, result);
		length         += result;
		fragments = g_slist_append(fragments, record);
	}

	if (fragments) {
		GSList *elem = fragments;
		guchar *p;

		printf("received a total of %" G_GSIZE_FORMAT " bytes.\n",
		       length);

		p = merged = g_malloc(length);
		while (elem) {
			struct record *record = elem->data;

			memcpy(p, record->msg, record->length);
			p += record->length;
			g_free(record->msg);
			g_free(record);

			elem = elem->next;
		}

		g_slist_free(fragments);
	}

	*in_length = length;
	return(merged);
}

static void tls_handshake(struct sipe_tls_state *state,
			  int fd)
{
	printf("TLS handshake starting...\n");

	/* generate next handshake message */
	while (sipe_tls_next(state)) {
		int sent;

		/* handshake completed? */
		if (!state->out_buffer) {
			printf("Handshake completed.\n");
			break;
		}

		/* send buffer to server */
		sent = write(fd, state->out_buffer, state->out_length);
		if (sent < 0) {
			printf("write to server failed: %s\n",
			       strerror(errno));
			break;
		} else if ((unsigned int) sent < state->out_length) {
			printf("could only write %d bytes, out of %" G_GSIZE_FORMAT "\n",
			       sent, state->out_length);
			break;
		}

		/* message sent, drop buffer */
		g_free(state->out_buffer);
		state->out_buffer = NULL;

		state->in_buffer = read_tls_record(fd, &state->in_length);
		if (!state->in_buffer) {
			printf("end of data.\n");
			break;
		}
	}

	printf("TLS handshake done.\n");
}


static int tls_connect(const gchar *param)
{
	gchar **parts = g_strsplit(param, ":", 2);
	int fd = -1;

	if (parts[0]) {
		const gchar *host = parts[0];
		const gchar *port = parts[1] ? parts[1] : "443";
		struct addrinfo hints;
		struct addrinfo *result;
		int status;

		printf("TLS connect to host '%s', port %s...\n",
		       host, port);

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;
		status = getaddrinfo(host, port, &hints, &result);

		if (status == 0) {
			struct addrinfo *rp;

			for (rp = result; rp != NULL; rp = rp->ai_next) {
				int sock = socket(rp->ai_family,
						  rp->ai_socktype,
						  rp->ai_protocol);

				if (sock < 0) continue;

				if (connect(sock,
					    rp->ai_addr,
					    rp->ai_addrlen) >= 0) {
					/* connected */
					printf("connected to host '%s', port %s.\n",
					       host, port);
					fd = sock;
					break;
				}
				fprintf(stderr, "failed to connect: %s\n",
					strerror(errno));

				close(sock);
			}
			freeaddrinfo(result);

			if (rp == NULL) {
				fprintf(stderr, "couldn't connect to host '%s'!\n",
					host);
			}
		} else {
			fprintf(stderr, "couldn't find host '%s': %s\n",
				host, gai_strerror(status));
		}
	} else {
		fprintf(stderr, "corrupted host[:port] '%s'!\n", param);
	}
	g_strfreev(parts);

	return(fd);
}

int main(int argc, char *argv[])
{
	struct sipe_cert_crypto *scc;

	sipe_crypto_init(FALSE);
	srand(time(NULL));

	scc = sipe_cert_crypto_init();
	if (scc) {
		gpointer certificate;
		struct sipe_tls_state *state;

		printf("SIPE cert crypto backend initialized.\n");

		certificate = sipe_cert_crypto_test_certificate(scc);
		state = sipe_tls_start(certificate);
		if (state) {
			int fd;

			printf("SIPE TLS initialized.\n");

			fd = tls_connect((argc > 1) ? argv[1] : "localhost:8443");
			if (fd >= 0) {
				tls_handshake(state, fd);
				close(fd);
			}

			sipe_tls_free(state);
		}

		sipe_cert_crypto_destroy(certificate);
		sipe_cert_crypto_free(scc);
	}
	sipe_crypto_shutdown();

	return(0);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
