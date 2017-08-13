/**
 * @file purple-dbus.h
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

/*
 * Work around some versions of dbus-server.h that redefine DBUS_EXPORT
 * without checking that it is already defined. Include dbus/dbus.h first
 * to suppress the implicit inclusion through dbus-server.h. Then undefine
 * the macro to avoid the potential build failure.
 */
#include <dbus/dbus.h>
#ifdef DBUS_EXPORT
#undef DBUS_EXPORT
#endif
#include "dbus-server.h"
#include "account.h"

extern PurpleDBusBinding sipe_purple_dbus_bindings[];

/**
 * SipeJoinConferenceWithOrganizerAndId - join conference using
 * organizer account name and meeting ID
 *
 * @param account   (in) libpurple account
 * @param organizer (in) organizer account name
 * @param id        (in) meeting ID string
 */
DBUS_EXPORT void sipe_join_conference_with_organizer_and_id(PurpleAccount *account,
							    const gchar *organizer,
							    const gchar *meeting_id);

/**
 * SipeJoinConferenceWithUri - join conference using URI
 *
 * @param account (in) libpurple account
 * @param uri     (in) URI string
 */
DBUS_EXPORT void sipe_join_conference_with_uri(PurpleAccount *account,
					       const gchar *uri);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
