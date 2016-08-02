/**
 * @file purple-appshare.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include <account.h>

#include "sipe-backend.h"
#include "sipe-core.h"
#include "purple-private.h"

SipeRDPClient
sipe_backend_appshare_get_rdp_client(struct sipe_core_public *sipe_public)
{
	PurpleAccount *account;
	const char *client;

	account = sipe_public->backend_private->account;

	client = purple_account_get_string(account, "rdp-client", "remmina");
	if (sipe_strequal(client, "remmina")) {
		return SIPE_RDP_CLIENT_REMMINA;
	} else {
		return SIPE_RDP_CLIENT_XFREERDP;
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
