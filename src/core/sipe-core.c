/**
 * @file sipe-core.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "http-conn.h" /* sipe-cal.h requires this */
#include "sip-csta.h"
#include "sip-sec.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-certificate.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-crypt.h"
#include "sipe-group.h"
#include "sipe-groupchat.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-status.h"
#include "sipe-subscriptions.h"
#include "sipe-svc.h"
#include "sipe-utils.h"
#include "sipe.h"

/* locale_dir is unused if ENABLE_NLS is not defined */
void sipe_core_init(SIPE_UNUSED_PARAMETER const char *locale_dir)
{
	srand(time(NULL));
	sip_sec_init();

#ifdef ENABLE_NLS
	SIPE_DEBUG_INFO("bindtextdomain = %s",
			bindtextdomain(PACKAGE_NAME, locale_dir));
	SIPE_DEBUG_INFO("bind_textdomain_codeset = %s",
			bind_textdomain_codeset(PACKAGE_NAME, "UTF-8"));
	textdomain(PACKAGE_NAME);
#endif
	/* Initialization for crypto backend (production mode) */
	sipe_crypto_init(TRUE);
	sipe_mime_init();
}

void sipe_core_destroy(void)
{
	sipe_chat_destroy();
	sipe_mime_shutdown();
	sipe_crypto_shutdown();
	sip_sec_destroy();
}

gchar *sipe_core_about(void)
{
	return g_strdup_printf(
		/*
		 * Non-translatable parts, like markup, are hard-coded
		 * into the format string. This requires more translatable
		 * texts but it makes the translations less error prone.
		 */
		"<b><font size=\"+1\">SIPE " PACKAGE_VERSION " </font></b><br/>"
		"<br/>"
		/* 1 */   "%s:<br/>"
		"<li> - MS Office Communications Server 2007 R2</li><br/>"
		"<li> - MS Office Communications Server 2007</li><br/>"
		"<li> - MS Live Communications Server 2005</li><br/>"
		"<li> - MS Live Communications Server 2003</li><br/>"
		"<li> - Reuters Messaging</li><br/>"
		"<br/>"
		/* 2 */   "%s: <a href=\"" PACKAGE_URL "\">" PACKAGE_URL "</a><br/>"
		/* 3,4 */ "%s: <a href=\"http://sourceforge.net/projects/sipe/forums/forum/688534\">%s</a><br/>"
		/* 5,6 */   "%s: <a href=\"" PACKAGE_BUGREPORT "\">%s</a><br/>"
		/* 7 */   "%s: <a href=\"" SIPE_TRANSLATIONS_URL "\">Transifex.net</a><br/>"
		/* 8 */   "%s: GPLv2+<br/>"
		"<br/>"
		/* 9 */  "%s:<br/>"
		" - CERN<br/>"
		" - Reuters Messaging network<br/>"
		" - Deutsche Bank<br/>"
		" - Merrill Lynch<br/>"
		" - Wachovia<br/>"
		" - Intel<br/>"
		" - Nokia<br/>"
		" - HP<br/>"
		" - Symantec<br/>"
		" - Accenture<br/>"
		" - Capgemini<br/>"
		" - Siemens<br/>"
		" - Alcatel-Lucent<br/>"
		" - BT<br/>"
		"<br/>"
		/* 10,11 */ "%s<a href=\"" SIPE_TRANSLATIONS_URL "\">Transifex.net</a>%s.<br/>"
		"<br/>"
		/* 12 */  "<b>%s:</b><br/>"
		" - Anibal Avelar<br/>"
		" - Gabriel Burt<br/>"
		" - Stefan Becker<br/>"
		" - pier11<br/>"
		" - Jakub Adam<br/>"
		" - Tomáš Hrabčík<br/>"
		"<br/>"
		/* 13 */  "%s<br/>"
		,
		/* The next 13 texts make up the SIPE about note text */
		/* About note, part 1/13: introduction */
		_("A third-party plugin implementing extended version of SIP/SIMPLE used by various products"),
		/* About note, part 2/13: home page URL (label) */
		_("Home"),
		/* About note, part 3/13: support forum URL (label) */
		_("Support"),
		/* About note, part 4/13: support forum name (hyperlink text) */
		_("Help Forum"),
		/* About note, part 5/13: bug tracker URL (label) */
		_("Report Problems"),
		/* About note, part 6/13: bug tracker URL (hyperlink text) */
		_("Bug Tracker"),
		/* About note, part 7/13: translation service URL (label) */
		_("Translations"),
		/* About note, part 8/13: license type (label) */
		_("License"),
		/* About note, part 9/13: known users */
		_("We support users in such organizations as"),
		/* About note, part 10/13: translation request, text before Transifex.net URL */
		/* append a space if text is not empty */
		_("Please help us to translate SIPE to your native language here at "),
		/* About note, part 11/13: translation request, text after Transifex.net URL */
		/* start with a space if text is not empty */
		_(" using convenient web interface"),
		/* About note, part 12/13: author list (header) */
		_("Authors"),
		/* About note, part 13/13: Localization credit */
		/* PLEASE NOTE: do *NOT* simply translate the english original */
		/* but write something similar to the following sentence: */
		/* "Localization for <language name> (<language code>): <name>" */
		_("Original texts in English (en): SIPE developers")
		);
}

static guint sipe_ht_hash_nick(const char *nick)
{
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean sipe_ht_equals_nick(const char *nick1, const char *nick2)
{
	char *nick1_norm = NULL;
	char *nick2_norm = NULL;
	gboolean equal;

	if (nick1 == NULL && nick2 == NULL) return TRUE;
	if (nick1 == NULL || nick2 == NULL    ||
	    !g_utf8_validate(nick1, -1, NULL) ||
	    !g_utf8_validate(nick2, -1, NULL)) return FALSE;

	nick1_norm = g_utf8_casefold(nick1, -1);
	nick2_norm = g_utf8_casefold(nick2, -1);
	equal = g_utf8_collate(nick1_norm, nick2_norm) == 0;
	g_free(nick2_norm);
	g_free(nick1_norm);

	return equal;
}

struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    const gchar *login_domain,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg)
{
	struct sipe_core_private *sipe_private;
	struct sipe_account_data *sip;
	gchar **user_domain;

	SIPE_DEBUG_INFO("sipe_core_allocate: signin_name '%s'", signin_name);

	/* ensure that sign-in name doesn't contain invalid characters */
	if (strpbrk(signin_name, "\t\v\r\n") != NULL) {
		*errmsg = _("SIP Exchange user name contains invalid characters");
		return NULL;
	}

	/* ensure that sign-in name format is name@domain */
	if (!strchr(signin_name, '@') ||
	    g_str_has_prefix(signin_name, "@") ||
	    g_str_has_suffix(signin_name, "@")) {
		*errmsg = _("User name should be a valid SIP URI\nExample: user@company.com");
		return NULL;
	}

	/* ensure that email format is name@domain (if provided) */
	if (!is_empty(email) &&
	    (!strchr(email, '@') ||
	     g_str_has_prefix(email, "@") ||
	     g_str_has_suffix(email, "@")))
	{
		*errmsg = _("Email address should be valid if provided\nExample: user@company.com");
		return NULL;
	}

	/* ensure that user name doesn't contain spaces */
	user_domain = g_strsplit(signin_name, "@", 2);
	SIPE_DEBUG_INFO("sipe_core_allocate: user '%s' domain '%s'", user_domain[0], user_domain[1]);
	if (strchr(user_domain[0], ' ') != NULL) {
		g_strfreev(user_domain);
		*errmsg = _("SIP Exchange user name contains whitespace");
		return NULL;
	}

	/* ensure that email_url is in proper format if enabled (if provided).
	 * Example (Exchange): https://server.company.com/EWS/Exchange.asmx
	 * Example (Domino)  : https://[domino_server]/[mail_database_name].nsf
	 */
	if (!is_empty(email_url)) {
		char *tmp = g_ascii_strdown(email_url, -1);
		if (!g_str_has_prefix(tmp, "https://"))
		{
			g_free(tmp);
			g_strfreev(user_domain);
			*errmsg = _("Email services URL should be valid if provided\n"
				    "Example: https://exchange.corp.com/EWS/Exchange.asmx\n"
				    "Example: https://domino.corp.com/maildatabase.nsf");
			return NULL;
		}
		g_free(tmp);
	}

	sipe_private = g_new0(struct sipe_core_private, 1);
	sipe_private->temporary = sip = g_new0(struct sipe_account_data, 1);
	SIPE_CORE_PRIVATE_FLAG_UNSET(SUBSCRIBED_BUDDIES);
	SIPE_CORE_PRIVATE_FLAG_UNSET(INITIAL_PUBLISH);
	sipe_private->username   = g_strdup(signin_name);
	sipe_private->email      = is_empty(email)         ? g_strdup(signin_name) : g_strdup(email);
	sip->authdomain = is_empty(login_domain)  ? NULL                  : g_strdup(login_domain);
	sip->authuser   = is_empty(login_account) ? NULL                  : g_strdup(login_account);
	sip->password   = g_strdup(password);
	sipe_private->public.sip_name   = g_strdup(user_domain[0]);
	sipe_private->public.sip_domain = g_strdup(user_domain[1]);
	g_strfreev(user_domain);

	sipe_private->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);
	sipe_private->our_publications = g_hash_table_new_full(g_str_hash, g_str_equal,
							       g_free, (GDestroyNotify)g_hash_table_destroy);
	sipe_subscriptions_init(sipe_private);
	sipe_status_set_activity(sipe_private, SIPE_ACTIVITY_UNSET);

	return((struct sipe_core_public *)sipe_private);
}

void sipe_core_connection_cleanup(struct sipe_core_private *sipe_private)
{
	g_free(sipe_private->epid);
	sipe_private->epid = NULL;

	sip_transport_disconnect(sipe_private);

	sipe_schedule_cancel_all(sipe_private);

	if (sipe_private->allowed_events) {
		GSList *entry = sipe_private->allowed_events;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sipe_private->allowed_events);

	sipe_ocs2007_free(sipe_private);

	sipe_blist_menu_free_containers(sipe_private);

	if (sipe_private->contact)
		g_free(sipe_private->contact);
	sipe_private->contact = NULL;
	if (sipe_private->register_callid)
		g_free(sipe_private->register_callid);
	sipe_private->register_callid = NULL;

	if (sipe_private->focus_factory_uri)
		g_free(sipe_private->focus_factory_uri);
	sipe_private->focus_factory_uri = NULL;

	if (sipe_private->calendar) {
		sipe_cal_calendar_free(sipe_private->calendar);
	}
	sipe_private->calendar = NULL;

	sipe_groupchat_free(sipe_private);
}

void sipe_core_deallocate(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

#ifdef HAVE_VV
	if (sipe_private->media_call) {
		sipe_media_handle_going_offline(sipe_private->media_call);
	}
#endif

	/* leave all conversations */
	if (sipe_private->sessions) {
		GSList *entry;
		while ((entry = sipe_private->sessions) != NULL) {
			sipe_session_close(sipe_private, entry->data);
		}
	}

	sipe_conf_cancel_unaccepted(sipe_private, NULL);

	if (sipe_private->csta) {
		sip_csta_close(sipe_private);
	}

	sipe_certificate_free(sipe_private);
	sipe_svc_free(sipe_private);

	if (sipe_backend_connection_is_valid(SIPE_CORE_PUBLIC)) {
		sipe_subscriptions_unsubscribe(sipe_private);
		sip_transport_deregister(sipe_private);
	}

	sipe_core_connection_cleanup(sipe_private);
	g_free(sipe_private->public.sip_name);
	g_free(sipe_private->public.sip_domain);
	g_free(sipe_private->username);
	g_free(sipe_private->email);
	g_free(sip->password);
	g_free(sip->authdomain);
	g_free(sip->authuser);
	g_free(sipe_private->status);
	g_free(sipe_private->note);
	g_free(sipe_private->ocs2005_user_states);

	sipe_buddy_free_all(sipe_private);
	g_hash_table_destroy(sipe_private->buddies);
	g_hash_table_destroy(sipe_private->our_publications);
	g_hash_table_destroy(sipe_private->user_state_publications);
	sipe_subscriptions_destroy(sipe_private);

	if (sipe_private->groups) {
		GSList *entry = sipe_private->groups;
		while (entry) {
			struct sipe_group *group = entry->data;
			g_free(group->name);
			g_free(group);
			entry = entry->next;
		}
	}
	g_slist_free(sipe_private->groups);

	if (sipe_private->our_publication_keys) {
		GSList *entry = sipe_private->our_publication_keys;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sipe_private->our_publication_keys);

#ifdef HAVE_VV
	g_free(sipe_private->mras_uri);
	g_free(sipe_private->media_relay_username);
	g_free(sipe_private->media_relay_password);
	sipe_media_relay_list_free(sipe_private->media_relays);
#endif

	g_free(sip);
	g_free(sipe_private);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
