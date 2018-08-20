/**
 * @file purple-network.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2018 SIPE Project <http://sipe.sourceforge.net/>
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
#include "config.h" /* coverity[hfa: FALSE] */
#endif

#include <string.h>

#include "glib.h"

#include "conversation.h"
#include "network.h"
#include "eventloop.h"

#ifdef _WIN32
/* wrappers for write() & friends for socket handling */
#include "win32/win32dep.h"
#include <nspapi.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "purple-private.h"

struct sipe_backend_listendata {
	sipe_listen_start_cb listen_cb;
	sipe_client_connected_cb connect_cb;

	PurpleNetworkListenData *listener;
	int watcher;

	int listenfd;
	gpointer data;
};

static void
client_connected_cb(struct sipe_backend_listendata *ldata, gint listenfd,
		    SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sockaddr_in saddr;
	socklen_t slen = sizeof (saddr);

	int fd = accept(listenfd, (struct sockaddr*)&saddr, &slen);

	purple_input_remove(ldata->watcher);
	ldata->watcher = 0;
	close(listenfd);
	ldata->listenfd = -1;

	if (fd >= 0) {
		if (ldata->connect_cb) {
			ldata->connect_cb(sipe_backend_fd_from_int(fd), ldata->data);
		} else {
			close(fd);
		}
	}

	g_free(ldata);
}

static void
backend_listen_cb(int listenfd, struct sipe_backend_listendata *ldata)
{
	ldata->listenfd = -1;
	ldata->listener = NULL;
	ldata->listenfd = listenfd;

	if (ldata->listen_cb) {
		/*
		 * NOTE: getsockname() on Windows seems to be picky about the
		 *       buffer location. Use an allocated buffer instead of
		 *       one on the stack,
		 */
		union socket_info {
			struct sockaddr         sa;     /* to avoid casts */
			struct sockaddr_in      sa_in;  /* IPv4 variant   */
			struct sockaddr_in6     sa_in6; /* IPv6 variant   */
			struct sockaddr_storage unused; /* for alignment  */
		} *si = g_new(union socket_info, 1);
		socklen_t si_len = sizeof(*si);
		guint port = htons(0); /* error fallback */

		if (getsockname(listenfd, &si->sa, &si_len) == 0) {
			port = (si->sa.sa_family == AF_INET)  ? si->sa_in.sin_port :
			       (si->sa.sa_family == AF_INET6) ? si->sa_in6.sin6_port :
			       port;
		}
		g_free(si);

		ldata->listen_cb(ntohs(port), ldata->data);
	}

	ldata->watcher = purple_input_add(listenfd, PURPLE_INPUT_READ,
					  (PurpleInputFunction)client_connected_cb,
					  ldata);
}

struct sipe_backend_listendata *
sipe_backend_network_listen_range(unsigned short port_min,
				  unsigned short port_max,
				  sipe_listen_start_cb listen_cb,
				  sipe_client_connected_cb connect_cb,
				  gpointer data)
{
	struct sipe_backend_listendata *ldata;
	ldata = g_new0(struct sipe_backend_listendata, 1);

	ldata->listen_cb = listen_cb;
	ldata->connect_cb = connect_cb;
	ldata->data = data;
	ldata->listener = purple_network_listen_range(port_min, port_max,
#if PURPLE_VERSION_CHECK(3,0,0)
						      /* @TODO: does FT work with IPv6? */
						      AF_INET,
#endif
						      SOCK_STREAM,
#if PURPLE_VERSION_CHECK(3,0,0)
						      /* @TODO: should we allow external mapping? */
						      FALSE,
#endif
						      (PurpleNetworkListenCallback)backend_listen_cb,
						      ldata);

	if (!ldata->listener) {
		g_free(ldata);
		return NULL;
	}

	return ldata;
}

void sipe_backend_network_listen_cancel(struct sipe_backend_listendata *ldata)
{
	g_return_if_fail(ldata);

	if (ldata->listener)
		purple_network_listen_cancel(ldata->listener);
	if (ldata->listenfd)
		close(ldata->listenfd);
	g_free(ldata);
}

struct sipe_backend_fd *
sipe_backend_fd_from_int(int fd)
{
	struct sipe_backend_fd *sipe_fd = g_new(struct sipe_backend_fd, 1);
	sipe_fd->fd = fd;
	return sipe_fd;
}

gboolean
sipe_backend_fd_is_valid(struct sipe_backend_fd *fd)
{
	return fd && fd->fd >= 0;
}

void
sipe_backend_fd_free(struct sipe_backend_fd *fd)
{
	g_free(fd);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
