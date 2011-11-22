/**
 * @file sipe-tls-tester.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 * - Running the test server in one shell:
 *
 *    $ openssl s_server -accept 8443 -debug -tls1 -cert server.cert \
 *              -key server.pem
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

#include <glib.h>

#include "sipe-common.h"
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
	int fd;

	sipe_crypto_init(FALSE);
	srand(time(NULL));

	fd = tls_connect((argc > 1) ? argv[1] : "localhost:8443");
	if (fd >= 0) {
		struct sipe_tls_state *state = sipe_tls_start(NULL);

		if (state) {
			printf("starting TLS handshake...\n");

			sipe_tls_free(state);
		}

		close(fd);
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
