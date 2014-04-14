/**
 * @file purple-network.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
#include "network.h"
#include "eventloop.h"

#ifdef _WIN32
/* wrappers for write() & friends for socket handling */
#include "win32/win32dep.h"
#include <nspapi.h>
#else
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h> /* SIOCGIFCONF for Solaris */
#endif
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "purple-private.h"

#if 0
/**
 * @TODO: get_suitable_local_ip()
 *
 * The code is most likely broken for Mac OS X as it seems that that platform
 * returns variable-sized "struct ifreq". The new, alignment compliant code
 * assumes a fix-sized "struct ifreq", i.e. it uses array access.
 *
 * If somebody is bothered by this, please provide a *VERIFIED* alternative
 * implementation for platforms that define _SIZEOF_ADDR_IFREQ().
 *
 **/

/*
 * Calling sizeof(struct ifreq) isn't always correct on
 * Mac OS X (and maybe others).
 */
#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif
#endif

#define IFREQ_MAX 32

/**
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
static const gchar *get_suitable_local_ip(void)
{
	int source = socket(PF_INET,SOCK_STREAM, 0);

	if (source >= 0) {
		struct ifreq *buffer = g_new0(struct ifreq, IFREQ_MAX);
		struct ifconf ifc;
		guint32 lhost = htonl(127 * 256 * 256 * 256 + 1);
		guint32 llocal = htonl((169 << 24) + (254 << 16));
		guint i;
		static char ip[16];

		/* @TODO: assumes constant sizeof(struct ifreq) [see above] */
		ifc.ifc_len = sizeof(struct ifreq) * IFREQ_MAX;
		ifc.ifc_req = buffer;
		ioctl(source, SIOCGIFCONF, &ifc);

		close(source);

		for (i = 0; i < IFREQ_MAX; i++)
		{
			/* @TODO: assumes constant sizeof(struct ifreq) [see above] */
			struct ifreq *ifr = &buffer[i];

			if (ifr->ifr_addr.sa_family == AF_INET)
			{
				struct sockaddr_in sin;
				memcpy(&sin, &ifr->ifr_addr, sizeof(struct sockaddr_in));
				if (sin.sin_addr.s_addr != lhost
				    && (sin.sin_addr.s_addr & htonl(0xFFFF0000)) != llocal)
				{
					long unsigned int add = ntohl(sin.sin_addr.s_addr);
					g_snprintf(ip, 16, "%lu.%lu.%lu.%lu",
						   ((add >> 24) & 255),
						   ((add >> 16) & 255),
						   ((add >> 8) & 255),
						   add & 255);

					g_free(buffer);
					return ip;
				}
			}
		}
		g_free(buffer);
	}

	return "0.0.0.0";
}

const gchar *sipe_backend_network_ip_address(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	const gchar *ip = purple_network_get_my_ip(-1);
	if (g_str_has_prefix(ip, "169.254."))
		ip = get_suitable_local_ip();
	return ip;
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

	if (ldata->connect_cb) {
		struct sipe_backend_fd *sipe_fd = g_new(struct sipe_backend_fd, 1);
		sipe_fd->fd = fd;
		ldata->connect_cb(sipe_fd, ldata->data);
	}

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

	/* ignore error code */
	(void) getsockname(listenfd, (struct sockaddr*)&addr, &socklen);
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
