/**
 * @file sipe-domino.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
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
 */

/**
For communication with Lotus Domino groupware server.

Server requirements: Domino 5.0.2 and above with Web Access.

0) May be try to read user's notes.ini for mail database name.

1) Authenticates to server (HTTPS POST, plaintext login/password over SSL)
https://[domino_server]/[databasename].nsf/?Login
Content-Type=application/x-www-form-urlencoded
Username=[email]&Password=[password] (email is url-encoded) 
Saves auth cookie.
Set-Cookie=DomAuthSessId=17D0428F7B9D57D4D0B064AE42FD21F9; path=/

2) Queries Calendar data (HTTPS GET, result is XML)
https://[domino_server]/[databasename].nsf/[viewname]?ReadViewEntries
https://[domino_server]/[databasename].nsf/($Calendar)?ReadViewEntries&KeyType=time&StartKey=20090805T000000Z&UntilKey=20090806T000000Z&Count=-1&TZType=UTC
Uses auth cookie.
Cookie=DomAuthSessId=17D0428F7B9D57D4D0B064AE42FD21F9

It will be able to retrieve our Calendar information (Meetings schedule,
subject and location) from Lotus Domino for subsequent publishing.

Ref. for more implementation details:
https://sourceforge.net/tracker/?func=detail&aid=2945346&group_id=194563&atid=949934

Similar functionality for iCalendar/CalDAV/Google would be great to implement too.
*/

#include <glib.h>

#include "sipe-core.h"
#include "sipe.h"
#include "sipe-backend.h"
#include "sipe-cal.h"
#include "sipe-domino.h"

static void
sipe_domino_do_login_request(struct sipe_calendar *ews)
{

}

void
sipe_domino_update_calendar(struct sipe_account_data *sip)
{

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: started.");

		sipe_domino_do_login_request(sip->cal);

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: finished.");
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
