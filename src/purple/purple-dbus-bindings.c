/**
 * @file purple-dbus-bindings.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "purple-dbus.h"

/*
 * The contents of this file need to be updated when any line which starts
 * with DBUS_EXPORT in purple-dbus.h gets added/removed/changed.
 *
 * You'll need access to the Pidgin source code to update this file:
 *
 *    $ python <path to pidgin>/libpurple/dbus-analyze-functions.py \
 *             --export-only                                        \
 *             src/purple/purple-dbus.h                             \
 *             >> src/purple/purple-dbus-bindings.c
 *
 * You'll have to edit the contents manually after running the above command.
 */

/*
 * The generated xxx_DBUS() functions need to be copied here
 */
#ifdef HAVE_VV
static DBusMessage*
sipe_call_phone_number_DBUS(DBusMessage *message_DBUS, DBusError *error_DBUS) {
	DBusMessage *reply_DBUS;
	dbus_int32_t account_ID;
	PurpleAccount *account;
	const char *phone_number;
	dbus_message_get_args(message_DBUS, error_DBUS, DBUS_TYPE_INT32, &account_ID, DBUS_TYPE_STRING, &phone_number, DBUS_TYPE_INVALID);
	CHECK_ERROR(error_DBUS);
	PURPLE_DBUS_ID_TO_POINTER(account, account_ID, PurpleAccount, error_DBUS);
	phone_number = (phone_number && phone_number[0]) ? phone_number : NULL;
	sipe_call_phone_number(account, phone_number);
	reply_DBUS = dbus_message_new_method_return (message_DBUS);
	dbus_message_append_args(reply_DBUS, DBUS_TYPE_INVALID);
	return reply_DBUS;
}
#endif

static DBusMessage*
sipe_join_conference_with_organizer_and_id_DBUS(DBusMessage *message_DBUS, DBusError *error_DBUS) {
	DBusMessage *reply_DBUS;
	dbus_int32_t account_ID;
	PurpleAccount *account;
	const char *organizer;
	const char *meeting_id;
	dbus_message_get_args(message_DBUS, error_DBUS, DBUS_TYPE_INT32, &account_ID, DBUS_TYPE_STRING, &organizer, DBUS_TYPE_STRING, &meeting_id, DBUS_TYPE_INVALID);
	CHECK_ERROR(error_DBUS);
	PURPLE_DBUS_ID_TO_POINTER(account, account_ID, PurpleAccount, error_DBUS);
	organizer = (organizer && organizer[0]) ? organizer : NULL;
	meeting_id = (meeting_id && meeting_id[0]) ? meeting_id : NULL;
	sipe_join_conference_with_organizer_and_id(account, organizer, meeting_id);
	reply_DBUS = dbus_message_new_method_return (message_DBUS);
	dbus_message_append_args(reply_DBUS, DBUS_TYPE_INVALID);
	return reply_DBUS;
}

static DBusMessage*
sipe_join_conference_with_uri_DBUS(DBusMessage *message_DBUS, DBusError *error_DBUS) {
	DBusMessage *reply_DBUS;
	dbus_int32_t account_ID;
	PurpleAccount *account;
	const char *uri;
	dbus_message_get_args(message_DBUS, error_DBUS, DBUS_TYPE_INT32, &account_ID, DBUS_TYPE_STRING, &uri, DBUS_TYPE_INVALID);
	CHECK_ERROR(error_DBUS);
	PURPLE_DBUS_ID_TO_POINTER(account, account_ID, PurpleAccount, error_DBUS);
	uri = (uri && uri[0]) ? uri : NULL;
	sipe_join_conference_with_uri(account, uri);
	reply_DBUS = dbus_message_new_method_return (message_DBUS);
	dbus_message_append_args(reply_DBUS, DBUS_TYPE_INVALID);
	return reply_DBUS;
}

static DBusMessage*
sipe_republish_calendar_DBUS(DBusMessage *message_DBUS, DBusError *error_DBUS) {
	DBusMessage *reply_DBUS;
	dbus_int32_t account_ID;
	PurpleAccount *account;
	dbus_message_get_args(message_DBUS, error_DBUS, DBUS_TYPE_INT32, &account_ID, DBUS_TYPE_INVALID);
	CHECK_ERROR(error_DBUS);
	PURPLE_DBUS_ID_TO_POINTER(account, account_ID, PurpleAccount, error_DBUS);
	sipe_republish_calendar(account);
	reply_DBUS = dbus_message_new_method_return (message_DBUS);
	dbus_message_append_args(reply_DBUS, DBUS_TYPE_INVALID);
	return reply_DBUS;
}

/*
 * The contents of bindings_DBUS[] need to be copied here
 */
PurpleDBusBinding sipe_purple_dbus_bindings[] = {
#ifdef HAVE_VV
	{"SipeCallPhoneNumber", "in\0i\0account\0in\0s\0phone_number\0", sipe_call_phone_number_DBUS},
#endif
	{"SipeJoinConferenceWithOrganizerAndId", "in\0i\0account\0in\0s\0organizer\0in\0s\0meeting_id\0", sipe_join_conference_with_organizer_and_id_DBUS},
	{"SipeJoinConferenceWithUri", "in\0i\0account\0in\0s\0uri\0", sipe_join_conference_with_uri_DBUS},
	{"SipeRepublishCalendar", "in\0i\0account\0", sipe_republish_calendar_DBUS},
	{NULL, NULL, NULL}
};

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
