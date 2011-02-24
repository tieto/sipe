/**
 * @file purple-network.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"
#include "network.h"
#include "eventloop.h"

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

#include <unistd.h>

#include "sipe-common.h"
#include "sipe-backend.h"

const gchar *sipe_backend_network_ip_address(void)
{
	return purple_network_get_my_ip(-1);
}

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

	if (ldata->connect_cb)
		ldata->connect_cb(fd, ldata->data);

	g_free(ldata);
}

static void
backend_listen_cb(int listenfd, struct sipe_backend_listendata *ldata)
{
	struct sockaddr_in addr;
	socklen_t socklen = sizeof (addr);

	ldata->listenfd = -1;
	ldata->listener = NULL;
	ldata->listenfd = listenfd;

	getsockname(listenfd, (struct sockaddr*)&addr, &socklen);
	if (ldata->listen_cb)
		ldata->listen_cb(ntohs(addr.sin_port), ldata->data);

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
						      SOCK_STREAM,
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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
