/**
 * @file purple-dbus.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2017 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "account.h"
#include "connection.h"

#include "sipe-core.h"

#include "purple-dbus.h"
#include "purple-private.h"

#if PURPLE_VERSION_CHECK(3,0,0)
#else
#define purple_account_is_disconnecting(a) a->disconnecting
#endif

/**
 * A call to our D-Bus interface is independent from the actual libpurple
 * state. Therefore we can't trust any of the incoming data.
 *
 * @param account (in) libpurple account (may be @c NULL)
 *
 * @return @c TRUE if it is safe to use PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC
 */
static gboolean account_is_valid(PurpleAccount *account)
{
	gboolean valid = FALSE;

	if (account &&
	    !purple_account_is_disconnecting(account) &&
	    (sipe_strequal(purple_account_get_protocol_id(account), SIPE_PURPLE_PLUGIN_ID))) {
		PurpleConnection *gc = purple_account_get_connection(account);

		if (gc && PURPLE_CONNECTION_IS_CONNECTED(gc))
			valid = TRUE;
	}

	return(valid);
}

void sipe_join_conference_with_organizer_and_id(PurpleAccount *account,
						const gchar *organizer,
						const gchar *meeting_id)
{
	/* Make sure organizer & ID are valid before calling to core */
	if (account_is_valid(account) && organizer && meeting_id)
		sipe_core_conf_create(PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC,
				      NULL,
				      organizer,
				      meeting_id);
}

void sipe_join_conference_with_uri(PurpleAccount *account,
				   const gchar *uri)
{
	/* Make sure URI is valid before calling to core */
	if (account_is_valid(account) && uri)
		sipe_core_conf_create(PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC,
				      uri,
				      NULL,
				      NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
