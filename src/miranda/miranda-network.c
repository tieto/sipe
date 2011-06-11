/**
 * @file miranda-network.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

#include <windows.h>
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"
#include "m_netlib.h"

#include "sipe-backend.h"
#include "miranda-private.h"

extern HANDLE sipe_miranda_incoming_netlibuser;

const gchar *sipe_backend_network_ip_address(void)
{
	static gchar ip[60] = "\0";

	if (!strlen(ip)) {
		gchar *tmp;
		tmp = sipe_miranda_getGlobalString("public_ip");
		SIPE_DEBUG_INFO("Retrieving public ip option for caching: <%s>", tmp);
		strncpy(ip, tmp, 60);
		mir_free(tmp);
	}

	return ip;
}

struct sipe_backend_listendata {
	sipe_listen_start_cb listen_cb;
	sipe_client_connected_cb connect_cb;
	gpointer data;
	unsigned short port_min;
	unsigned short port_max;

	HANDLE boundport;
};


static void client_connected_callback(HANDLE hNewConnection, DWORD dwRemoteIP, void *data)
{
	struct sipe_backend_listendata *ldata = (struct sipe_backend_listendata *)data;

	SIPE_DEBUG_INFO("Remote connection from <%08x>", dwRemoteIP);

	CallServiceAsync(MS_NETLIB_CLOSEHANDLE,(WPARAM)ldata->boundport,0);

	if (ldata->connect_cb)
                ldata->connect_cb((struct sipe_backend_fd *)hNewConnection, ldata->data);

        g_free(ldata);
}

static unsigned __stdcall listen_callback(void* data)
{
	NETLIBBIND nlb = {0};
	NETLIBUSERSETTINGS nls = {0};
	struct sipe_backend_listendata *ldata = (struct sipe_backend_listendata *)data;

	nls.cbSize = sizeof(NETLIBUSERSETTINGS);
	CallService(MS_NETLIB_GETUSERSETTINGS, (WPARAM)sipe_miranda_incoming_netlibuser, (LPARAM)&nls);
	nls.specifyIncomingPorts = 1;
	nls.szIncomingPorts = mir_alloc(20);
	mir_snprintf( nls.szIncomingPorts, 20, "%d-%d", ldata->port_min, ldata->port_max);
	CallService(MS_NETLIB_SETUSERSETTINGS, (WPARAM)sipe_miranda_incoming_netlibuser, (LPARAM)&nls);

	nlb.cbSize = sizeof(NETLIBBIND);
	nlb.pfnNewConnectionV2 = client_connected_callback;
	nlb.pExtra = ldata;
	SetLastError(ERROR_INVALID_PARAMETER); // this must be here - NetLib does not set any error :((

	ldata->boundport = (HANDLE)CallService(MS_NETLIB_BINDPORT, (WPARAM)sipe_miranda_incoming_netlibuser, (LPARAM)&nlb);

	if (ldata->listen_cb)
		ldata->listen_cb(nlb.wPort, ldata->data);

	return 0;
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
	ldata->port_min = port_min;
	ldata->port_max = port_max;

	CloseHandle((HANDLE) mir_forkthreadex( listen_callback, ldata, 65536, NULL ));

	return ldata;
}

void sipe_backend_network_listen_cancel(struct sipe_backend_listendata *ldata)
{
	_NIF();
}

gboolean
sipe_backend_fd_is_valid(struct sipe_backend_fd *fd)
{
	return (fd != NULL);
}

void sipe_backend_fd_free(struct sipe_backend_fd *fd)
{
	/* N/A; sipe_backend_fd is the actual HANDLE */
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
