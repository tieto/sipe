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
Username=[email]&Password=[password] (params are url-encoded)
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

/* @TODO replace purple_url_encode() with non-purple equiv. */
#include "util.h"

#include "sipe-core.h"
#include "sipe.h"
#include "sipe-backend.h"
#include "sipe-cal.h"
#include "sipe-domino.h"
#include "http-conn.h"

/**
 * GetUserAvailabilityRequest SOAP request to Exchange Web Services
 * to obtain our Availability (FreeBusy, WorkingHours, Meetings) information.
 * @param email      (%s) Ex.: alice@cosmo.local
 * @param start_time (%s) Ex.: 2009-12-06T00:00:00
 * @param end_time   (%s) Ex.: 2009-12-09T23:59:59
 */
#define SIPE_DOMINO_LOGIN_REQUEST \
"Username=%s&Password=%s"

static void
sipe_domino_process_login_response(int return_code,
				   const char *body,
				   HttpConn *conn,
				   void *data)
{
	struct sipe_calendar *cal = data;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_process_login_response: cb started.");

	http_conn_set_close(conn);
	cal->http_conn = NULL;

	if (return_code == 200 && body) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_process_login_response: SUCCESS");
	} else if (return_code < 0) {
		SIPE_DEBUG_INFO("sipe_domino_process_login_response: FAILURE, ret=%d", return_code);
		cal->http_conn = NULL;
	}
}

static void
sipe_domino_do_login_request(struct sipe_calendar *cal)
{
	if (cal->as_url) {
		char *body;
		const char *content_type = "application/x-www-form-urlencoded";
		char *login_url = g_strconcat(cal->as_url, "/?Login", NULL);
		char *user;
		char *password;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_do_login_request: going Login req.");
		
		if (!cal->auth) return;
		
		/* @TODO replace purple_url_encode() with non-purple equiv. */
		user     = g_strdup(purple_url_encode(cal->auth->user));
		password = g_strdup(purple_url_encode(cal->auth->password));

		body = g_strdup_printf(SIPE_DOMINO_LOGIN_REQUEST, user, password);
		g_free(user);
		g_free(password);
		
		if (!cal->http_conn) {
			cal->http_conn = http_conn_create(cal->account,
							  HTTP_CONN_SSL,
							  login_url,
							  body,
							  content_type,
							  cal->auth,
							  sipe_domino_process_login_response,
							  cal);
		} else {
			http_conn_post(cal->http_conn,
				       login_url,
				       body,
				       content_type,
				       sipe_domino_process_login_response,
				       cal);
		}
		g_free(login_url);
		g_free(body);
	}
}

void
sipe_domino_update_calendar(struct sipe_account_data *sip)
{

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: started.");

	sipe_cal_calendar_init(sip, NULL);
	
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
