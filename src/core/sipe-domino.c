/**
 * @file sipe-domino.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

1) Tries to read user's notes.ini for mail database name.
Windows registry keys for notes.ini location:
HKEY_CURRENT_USER\Software\Lotus\Notes\6.0\NotesIniPath

2) Authenticates to server (HTTPS POST, plaintext login/password over SSL)
https://[domino_server]/[databasename].nsf/?Login
Content-Type=application/x-www-form-urlencoded
Username=[email]&Password=[password] (params are url-encoded)
Saves auth cookie.
Set-Cookie=DomAuthSessId=17D0428F7B9D57D4D0B064AE42FD21F9; path=/

3) Queries Calendar data (HTTPS GET, result is XML)
https://[domino_server]/[databasename].nsf/[viewname]?ReadViewEntries
https://[domino_server]/[databasename].nsf/($Calendar)?ReadViewEntries&KeyType=time&StartKey=20090805T000000Z&UntilKey=20090806T000000Z&Count=-1&TZType=UTC
Uses auth cookie.
Cookie=DomAuthSessId=17D0428F7B9D57D4D0B064AE42FD21F9

It is able to retrieve our Calendar information (Meetings schedule,
subject and location) from Lotus Domino for subsequent publishing.

Ref. for more implementation details:
https://sourceforge.net/tracker/?func=detail&aid=2945346&group_id=194563&atid=949934

Similar functionality for iCalendar/CalDAV/Google would be great to implement too.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <glib.h>

/* for registry read */
#ifdef _WIN32
#include "sipe-win32dep.h"
#endif

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-domino.h"
#include "sipe-http.h"
#include "sipe-nls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/**
 * POST request for Login to Domino server
 * @param email      (%s) Should be URL-encoded. Ex.: alice@cosmo.local
 * @param password   (%s) Should be URL-encoded.
 */
#define SIPE_DOMINO_LOGIN_REQUEST \
"Username=%s&Password=%s"

/**
 * GET request to Domino server
 * to obtain our Calendar information.
 * @param start_time (%s) Ex.: 20090805T000000Z
 * @param end_time   (%s) Ex.: 20090806T000000Z
 */
#define SIPE_DOMINO_CALENDAR_REQUEST \
"/($Calendar)?ReadViewEntries&KeyType=time&StartKey=%s&UntilKey=%s&Count=-1&TZType=UTC"

/*
<?xml version="1.0" encoding="UTF-8"?>
<viewentries timestamp="20100416T112140,02Z" toplevelentries="77" rangeentries="
1000">
	<viewentry position="77" unid="C3A77CC76EAA7D08802576FD0043D7D0" noteid="27B42" siblings="77">
		<entrydata columnnumber="0" name="$134">
			<datetime>20100423T103000,00Z</datetime>
		</entrydata>
		<entrydata columnnumber="1" name="$149">
			<number>158</number>
		</entrydata>
		<entrydata columnnumber="2" name="$144">
			<datetime>20100423T103000,00Z</datetime>
		</entrydata>
		<entrydata columnnumber="3" name="$145">
			<text>-</text>
		</entrydata>
		<entrydata columnnumber="4" name="$146">
			<datetime>20100423T120000,00Z</datetime>
		</entrydata>
		<entrydata columnnumber="5" name="$147">
			<textlist>
				<text>G. S. ..I. L. T. Hall</text>
				<text>Location: Auditorium - W. House</text>
				<text>Chair: S. S.</text>
			</textlist>
		</entrydata>
	</viewentry>
	<viewentry .........
</viewentries>
*/

#define VIEWENTITY_START0_TIME	"$134"
#define VIEWENTITY_START_TIME	"$144"
#define VIEWENTITY_END_TIME	"$146"
#define VIEWENTITY_TEXT_LIST	"$147"


static int
sipe_domino_get_slot_no(time_t fb_start, time_t in)
{
	return (in - fb_start) / SIPE_FREE_BUSY_GRANULARITY_SEC;
}

static char *
sipe_domino_get_free_busy(time_t fb_start,
			  GSList *cal_events)
{
	GSList *entry = cal_events;
	char *res;

	if (!cal_events) return NULL;

	res = g_strnfill(SIPE_FREE_BUSY_PERIOD_SEC / SIPE_FREE_BUSY_GRANULARITY_SEC,
			 SIPE_CAL_FREE + '0');

	while (entry) {
		struct sipe_cal_event *cal_event = entry->data;
		int start = sipe_domino_get_slot_no(fb_start, cal_event->start_time);
		int end = sipe_domino_get_slot_no(fb_start, (cal_event->end_time - 1));
		int i;

		for (i = start; i <= end; i++) {
			res[i] = SIPE_CAL_BUSY + '0';
		}
		entry = entry->next;
	}
	SIPE_DEBUG_INFO("sipe_domino_get_free_busy: res=\n%s", res);
	return res;
}

static void sipe_domino_process_calendar_response(struct sipe_core_private *sipe_private,
						  guint status,
						  GSList *headers,
						  const gchar *body,
						  gpointer data)
{
	struct sipe_calendar *cal = data;
	const gchar *content_type = sipe_utils_nameval_find(headers, "Content-Type");

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_process_calendar_response: cb started.");

	cal->request = NULL;

	if (content_type && !g_str_has_prefix(content_type, "text/xml")) {
		cal->is_domino_disabled = TRUE;
		SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_process_calendar_response: not XML, disabling.");
		return;
	}

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		const sipe_xml *node, *node2, *node3;
		sipe_xml *xml;

		SIPE_DEBUG_INFO("sipe_domino_process_calendar_response: SUCCESS, ret=%d", status);
		xml = sipe_xml_parse(body, strlen(body));

		sipe_cal_events_free(cal->cal_events);
		cal->cal_events = NULL;
		/* viewentry */
		for (node = sipe_xml_child(xml, "viewentry");
		     node;
		     node = sipe_xml_twin(node))
		{
			struct sipe_cal_event *cal_event = g_new0(struct sipe_cal_event, 1);
			cal->cal_events = g_slist_append(cal->cal_events, cal_event);
			cal_event->cal_status = SIPE_CAL_BUSY;
			cal_event->is_meeting = TRUE;

			/* SIPE_DEBUG_INFO("viewentry unid=%s", sipe_xml_attribute(node, "unid")); */

			/* entrydata */
			for (node2 = sipe_xml_child(node, "entrydata");
			     node2;
			     node2 = sipe_xml_twin(node2))
			{
				const char *name = sipe_xml_attribute(node2, "name");

				SIPE_DEBUG_INFO("\tentrydata name=%s", name);

				if (sipe_strequal(name, VIEWENTITY_START0_TIME) ||
				    sipe_strequal(name, VIEWENTITY_START_TIME) ||
				    sipe_strequal(name, VIEWENTITY_END_TIME))
				{
					char *tmp = sipe_xml_data(sipe_xml_child(node2, "datetime"));
					time_t time_val = sipe_utils_str_to_time(tmp);

					if (sipe_strequal(name, VIEWENTITY_START_TIME)) {
						cal_event->start_time = time_val;
					} else if (sipe_strequal(name, VIEWENTITY_END_TIME)) {
						cal_event->end_time = time_val;
					}

					SIPE_DEBUG_INFO("\t\tdatetime=%s", asctime(gmtime(&time_val)));
					g_free(tmp);
				} else if (sipe_strequal(name, VIEWENTITY_TEXT_LIST)) {
					int i = 0;

					/* test */
					for (node3 = sipe_xml_child(node2, "textlist/text");
					     node3;
					     node3 = sipe_xml_twin(node3))
					{
						char *tmp = sipe_xml_data(node3);

						if (!tmp) continue;

						SIPE_DEBUG_INFO("\t\ttext=%s", tmp);
						if (i == 0) {
							cal_event->subject = g_strdup(tmp);
							SIPE_DEBUG_INFO("\t\t*Subj.=%s", tmp);
						} else {
							/* plain English, don't localize! */
							if (!g_ascii_strncasecmp(tmp, "Location:", 9)) {
								if (strlen(tmp) > 9) {
									cal_event->location = g_strdup(g_strstrip(tmp+9));
									SIPE_DEBUG_INFO("\t\t*Loc.=%s", cal_event->location);
								}
							/* Translators: (!) should be as in localized Lotus Notes to be able to extract meeting location */
							} else if (g_str_has_prefix(tmp, _("Location:"))) {
								guint len = strlen(_("Location:"));
								if (strlen(tmp) > len) {
									cal_event->location = g_strdup(g_strstrip(tmp+len));
									SIPE_DEBUG_INFO("\t\t*Loc.=%s", cal_event->location);
								}
							}
						}
						i++;
						g_free(tmp);
					}
				}
			}
		}
		sipe_xml_free(xml);

		/* creates FreeBusy from cal->cal_events */
		g_free(cal->free_busy);
		cal->free_busy = sipe_domino_get_free_busy(cal->fb_start, cal->cal_events);

		/* update SIP server */
		cal->is_updated = TRUE;
		sipe_cal_presence_publish(sipe_private, TRUE);

	} else if (!headers) {
		SIPE_DEBUG_INFO("sipe_domino_process_calendar_response: rather FAILURE, ret=%d", status);
	}

	sipe_http_session_close(cal->session);
	cal->session = NULL;
}

/* Domino doesn't like '-' and ':' in ISO timestamps */
static gchar *
sipe_domino_time_to_str(time_t timestamp)
{
	char *res, *tmp;

	res = sipe_utils_time_to_str(timestamp);
	res = sipe_utils_str_replace((tmp = res), "-", "");
	g_free(tmp);
	res = sipe_utils_str_replace((tmp = res), ":", "");
	g_free(tmp);

	return res;
}

static void sipe_domino_send_http_request(struct sipe_calendar *cal)
{
	if (cal->request) {
		sipe_core_email_authentication(cal->sipe_private,
					       cal->request);
		sipe_http_request_session(cal->request, cal->session);
		sipe_http_request_ready(cal->request);
	}
}

static void sipe_domino_do_calendar_request(struct sipe_calendar *cal)
{
	if (cal->domino_url) {
		char *url_req;
		char *url;
		time_t end;
		time_t now = time(NULL);
		char *start_str;
		char *end_str;
		struct tm *now_tm;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_do_calendar_request: going Calendar req.");

		now_tm = gmtime(&now);
		/* start -1 day, 00:00:00 */
		now_tm->tm_sec = 0;
		now_tm->tm_min = 0;
		now_tm->tm_hour = 0;
		cal->fb_start = sipe_mktime_tz(now_tm, "UTC");
		cal->fb_start -= 24*60*60;
		/* end = start + 4 days - 1 sec */
		end = cal->fb_start + SIPE_FREE_BUSY_PERIOD_SEC - 1;

		start_str = sipe_domino_time_to_str(cal->fb_start);
		end_str = sipe_domino_time_to_str(end);

		url_req = g_strdup_printf(SIPE_DOMINO_CALENDAR_REQUEST, start_str, end_str);
		g_free(start_str);
		g_free(end_str);

		url = g_strconcat(cal->domino_url, url_req, NULL);
		g_free(url_req);
		cal->request = sipe_http_request_get(cal->sipe_private,
						     url,
						     NULL,
						     sipe_domino_process_calendar_response,
						     cal);
		g_free(url);

		sipe_domino_send_http_request(cal);
	}
}

static void sipe_domino_process_login_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
					       guint status,
					       GSList *headers,
					       /* temporary? */
					       SIPE_UNUSED_PARAMETER const gchar *body,
					       gpointer data)
{
	struct sipe_calendar *cal = data;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_process_login_response: cb started.");

	cal->request = NULL;

	if ((status >= SIPE_HTTP_STATUS_OK) &&
	    (status <  SIPE_HTTP_STATUS_CLIENT_ERROR)) {
		SIPE_DEBUG_INFO("sipe_domino_process_login_response: rather SUCCESS, ret=%d", status);

		/* next query */
		sipe_domino_do_calendar_request(cal);

	} else if (!headers ||
		   (status >= SIPE_HTTP_STATUS_CLIENT_ERROR)) {
		SIPE_DEBUG_INFO("sipe_domino_process_login_response: rather FAILURE, ret=%d", status);

		/* stop here */
		/* cal->is_domino_disabled = TRUE; */
	}
}

static gchar *sipe_domino_uri_escape(const gchar *string)
{
	gchar *escaped;

	if (!string) return(NULL);
	if (!g_utf8_validate(string, -1, NULL)) return(NULL);

#if GLIB_CHECK_VERSION(2,16,0)
	escaped = g_uri_escape_string(string, NULL, FALSE);
#else
	/* loosely based on libpurple/util.c:purple_url_encode() */
	{
		GString *buf = g_string_new(NULL);

		while (*string) {
			gunichar c = g_utf8_get_char(string);

			/* If the character is an ASCII character and is alphanumeric
			 * no need to escape */
			if (c < 128 &&
			    (isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~')) {
				g_string_append_c(buf, c);
			} else {
				gchar *p, utf_char[6];
				guint bytes = g_unichar_to_utf8(c, utf_char);

				p = utf_char;
				while (bytes-- > 0) {
					g_string_append_printf(buf,
							       "%%%02X",
							       *p++ & 0xff);
				}
			}

			string = g_utf8_next_char(string);
		}

		escaped = g_string_free(buf, FALSE);
	}
#endif

	return(escaped);
}

static void
sipe_domino_do_login_request(struct sipe_calendar *cal)
{
	if (cal->domino_url) {
		struct sipe_core_private *sipe_private = cal->sipe_private;
		char *body;
		const char *content_type = "application/x-www-form-urlencoded";
		char *login_url = g_strconcat(cal->domino_url, "/?Login", NULL);
		char *user;
		gchar *password = sipe_private->email_password ? sipe_private->email_password : sipe_private->password;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_do_login_request: going Login req.");

		if (!password) return;

		/* @TODO replace purple_url_encode() with non-purple equiv. */
		user     = sipe_domino_uri_escape(cal->email);
		password = sipe_domino_uri_escape(password);

		body = g_strdup_printf(SIPE_DOMINO_LOGIN_REQUEST, user, password);
		g_free(user);
		g_free(password);

		cal->request = sipe_http_request_post(sipe_private,
						      login_url,
						      NULL,
						      body,
						      content_type,
						      sipe_domino_process_login_response,
						      cal);
		g_free(login_url);
		g_free(body);

		sipe_domino_send_http_request(cal);
	}
}

/* in notes.ni
MailFile=mail5\mhe111bm.nsf
MailServer=CN=MSGM2222/OU=srv/O=xxcom

Output values should be freed if requested.
*/
static void
sipe_domino_read_notes_ini(const char *filename_with_path, char **mail_server, char **mail_file)
{
	char rbuf[256];
	FILE *fp = fopen(filename_with_path, "r+");

	if (fp) {
		while (fgets(rbuf, sizeof (rbuf), fp)) {
			char *prop = "MailFile=";
			guint prop_len = strlen(prop);

			/* SIPE_DEBUG_INFO("\t%s (%"G_GSIZE_FORMAT")", rbuf, strlen(rbuf)); */
			if (mail_file && !g_ascii_strncasecmp(rbuf, prop, prop_len) && (strlen(rbuf) > prop_len)) {
				*mail_file = g_strdup(g_strstrip((rbuf+prop_len)));
			}

			prop = "MailServer=";
			prop_len = strlen(prop);

			if (mail_server && !g_ascii_strncasecmp(rbuf, prop, prop_len) && (strlen(rbuf) > prop_len)) {
				*mail_server = g_strdup(g_strstrip((rbuf+prop_len)));
			}
		}
		fclose(fp);
	} else {
		SIPE_DEBUG_ERROR("sipe_domino_read_notes_ini(): could not open `%s': %s", filename_with_path, g_strerror (errno));
	}
}

/**
@param protocol		Ex.: https
@param mail_server	Ex.: CN=MSGM2222/OU=srv/O=xxcom
@param mail_file	Ex.: mail5\mhe111bm.nsf

@return			Ex.: https://msgm2222/mail5/mhe111bm.nsf
*/
static char *
sipe_domino_compose_url(const char *protocol, const char *mail_server, const char *mail_file)
{
	const char *ptr;
	char *tmp, *tmp2, *tmp3;

	g_return_val_if_fail(protocol, NULL);
	g_return_val_if_fail(mail_server, NULL);
	g_return_val_if_fail(mail_file, NULL);

	/* mail_server: exptacting just common name */
	if ((ptr = strstr(mail_server, "/"))) {
		tmp = g_strndup(mail_server, (ptr-mail_server));
	} else {
		tmp = g_strdup(mail_server);
	}
	if ((!g_ascii_strncasecmp(tmp, "CN=", 3))) {
		tmp2 = g_strdup(tmp+3);
	} else {
		tmp2 = g_strdup(tmp);
	}
	g_free(tmp);
	tmp = g_ascii_strdown(tmp2, -1);
	g_free(tmp2);

	/* mail_file */
	tmp3 = sipe_utils_str_replace(mail_file, "\\", "/");

	tmp2 = g_strconcat(protocol, "://", tmp, "/", tmp3, NULL);
	g_free(tmp);
	g_free(tmp3);

	return tmp2;
}

void
sipe_domino_update_calendar(struct sipe_core_private *sipe_private)
{
	struct sipe_calendar* cal;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: started.");

	sipe_cal_calendar_init(sipe_private);

	/* check if URL is valid if provided */
	cal = sipe_private->calendar;
	if (cal && !is_empty(cal->domino_url)) {
		char *tmp = g_ascii_strdown(cal->domino_url, -1);
		if (!g_str_has_suffix(tmp, ".nsf")) {
			/* not valid Domino mail services URL */
			cal->is_domino_disabled = TRUE;
			SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: invalid Domino URI supplied, disabling.");
		}
		g_free(tmp);
	}

	/* Autodiscovery.
	 * Searches location of notes.ini in Registry, reads it, extracts mail server and mail file,
	 * composes HTTPS URL to Domino web, basing on that
	 */
	if (cal && is_empty(cal->domino_url)) {
		char *path = NULL;
#ifdef _WIN32
		/* fine for Notes 8.5 too */
		path = wpurple_read_reg_expand_string(HKEY_CURRENT_USER, "Software\\Lotus\\Notes\\8.0", "NotesIniPath");
		if (is_empty(path)) {
			g_free(path);
			path = wpurple_read_reg_expand_string(HKEY_CURRENT_USER, "Software\\Lotus\\Notes\\7.0", "NotesIniPath");
			if (is_empty(path)) {
				g_free(path);
				path = wpurple_read_reg_expand_string(HKEY_CURRENT_USER, "Software\\Lotus\\Notes\\6.0", "NotesIniPath");
				if (is_empty(path)) {
					g_free(path);
					path = wpurple_read_reg_expand_string(HKEY_CURRENT_USER, "Software\\Lotus\\Notes\\5.0", "NotesIniPath");
				}
			}
		}
		SIPE_DEBUG_INFO("sipe_domino_update_calendar: notes.ini path:\n%s", path ? path : "");
#else
		/* How to know location of notes.ini on *NIX ? */
#endif

		/* get server url */
		if (path) {
			char *mail_server = NULL;
			char *mail_file = NULL;

			sipe_domino_read_notes_ini(path, &mail_server, &mail_file);
			g_free(path);
			SIPE_DEBUG_INFO("sipe_domino_update_calendar: mail_server=%s", mail_server ? mail_server : "");
			SIPE_DEBUG_INFO("sipe_domino_update_calendar: mail_file=%s", mail_file ? mail_file : "");

			g_free(cal->domino_url);
			cal->domino_url = sipe_domino_compose_url("https", mail_server, mail_file);
			g_free(mail_server);
			g_free(mail_file);
			SIPE_DEBUG_INFO("sipe_domino_update_calendar: cal->domino_url=%s", cal->domino_url ? cal->domino_url : "");
		} else {
			/* No domino_url, no path discovered, disabling */
			cal->is_domino_disabled = TRUE;
			SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: Domino URI hasn't been discovered, neither provided, disabling.");
		}
	}

	if (cal) {

		if (cal->is_domino_disabled) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_domino_update_calendar: disabled, exiting.");
			return;
		}

		/* re-create session */
		sipe_http_session_close(cal->session);
		cal->session = sipe_http_session_start();

		sipe_domino_do_login_request(cal);
	}

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
