/**
 * @file sipe-core.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2018 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * Some notes on the history of this project/code/copyrights:
 *
 *  - the project is called SIPE, but originally the code was only written
 *    for the libpurple framework, i.e. Pidgin. Hence the package name is
 *    "pidgin-sipe".
 *
 *  - in the beginning almost all of the code was located in a module
 *    called "sipe.c". During the effort to remove the libpurple
 *    dependencies from the SIPE core, thousands of lines of code got
 *    shifted out of sipe.c, mostly to newly created modules and sipe.c
 *    ceased to exist.
 *
 *  - it would have been tedious to track down the original author or
 *    copyright and preserve them for each line of code that was moved.
 *    Therefore the new modules started with a fresh copyright notice
 *    (like the one above).
 *
 *  - the original copyright notices from sipe.c have been moved to this
 *    file (see below) and *MUST* be preserved!
 *
 *  - if necessary the author of a line of code in question can still be
 *    reconstructed from the git repository information.
 *    See also "man git-blame"
 *
 *  - if you think your copyright should be restored for a piece of code,
 *    then please contact the SIPE project to fix the source files ASAP.
 *
 *------------------- Copyright notices from "sipe.c" ---------------
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009-10 pier11 <pier11@operamail.com>
 * Copyright (C) 2008    Novell, Inc.
 * Copyright (C) 2007-09 Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2005    Thomas Butter <butter@uni-mannheim.de>
 *
 * ***
 * Thanks to Google's Summer of Code Program and the helpful mentors
 * ***
 *------------------- Copyright notices from "sipe.c" ---------------
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
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
#include "sipe-ews-autodiscover.h"
#include "sipe-group.h"
#include "sipe-groupchat.h"
#include "sipe-http.h"
#include "sipe-lync-autodiscover.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-status.h"
#include "sipe-subscriptions.h"
#include "sipe-svc.h"
#include "sipe-ucs.h"
#include "sipe-utils.h"
#include "sipe-webticket.h"

#if !GLIB_CHECK_VERSION(2,18,0)
#error glib-2.0 >= 2.18.0 is required to build SIPE
#endif

#ifdef PACKAGE_GIT_COMMIT
#define SIPE_CORE_VERSION PACKAGE_VERSION " (git commit " PACKAGE_GIT_COMMIT " / "
#else
#define SIPE_CORE_VERSION PACKAGE_VERSION " ("
#endif

/* translate config.h options to strings */
static const gchar * const sipe_core_build_options[] = {

	/* Authentication */
#ifdef HAVE_SSPI
	"SSPI",
#elif defined(HAVE_GSSAPI_ONLY)
	"GSSAPI",
#ifndef HAVE_GSSAPI_PASSWORD_SUPPORT
	"SSO only",
#endif
#else
#ifdef HAVE_GSSAPI_GSSAPI_H
	"Kerberos 5 & NTLM",
#else
	"NTLM",
#endif
#endif

	/* D-Bus */
#ifdef HAVE_DBUS
	"D-Bus",
#endif

	/* Media */
#ifdef HAVE_VV
	"Voice & Video",
#ifdef HAVE_SRTP
	"SRTP",
#endif
#ifdef HAVE_XDATA
	"Lync FT",
#endif
#ifdef HAVE_APPSHARE
#ifdef HAVE_APPSHARE_SERVER
	"Application Sharing - full",
#else
	"Application Sharing - client only",
#endif
#endif
#endif

	/* Development */
#ifdef HAVE_VALGRIND
	"Valgrind",
#endif

	NULL
};


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
	sipe_status_init();
}

void sipe_core_destroy(void)
{
	sipe_chat_destroy();
	sipe_status_shutdown();
	sipe_mime_shutdown();
	sipe_crypto_shutdown();
	sip_sec_destroy();
}

gchar *sipe_core_about(void)
{
	gchar *options = g_strjoinv(" / ", (gchar **) sipe_core_build_options);
	gchar *about   = g_strdup_printf(
		/*
		 * Non-translatable parts, like markup, are hard-coded
		 * into the format string. This requires more translatable
		 * texts but it makes the translations less error prone.
		 */
		"<b><font size=\"+1\">SIPE " SIPE_CORE_VERSION "%s) </font></b><br/>"
		"<br/>"
		/* 1 */   "%s:<br/>"
		" - Skype for Business<br/>"
		" - Microsoft Office 365<br/>"
		" - Microsoft Business Productivity Online Suite (BPOS)<br/>"
		" - Microsoft Lync Server<br/>"
		" - Microsoft Office Communications Server 2007 R2<br/>"
		" - Microsoft Office Communications Server 2007<br/>"
		" - Microsoft Live Communications Server 2005<br/>"
		" - Microsoft Live Communications Server 2003<br/>"
		"<br/>"
		/* 2 */   "%s: <a href=\"" PACKAGE_URL "\">" PACKAGE_URL "</a><br/>"
		/* 3,4 */ "%s: <a href=\"http://sourceforge.net/p/sipe/discussion/688534/\">%s</a><br/>"
		/* 5,6 */   "%s: <a href=\"" PACKAGE_BUGREPORT "\">%s</a><br/>"
		/* 7 */   "%s: <a href=\"" SIPE_TRANSLATIONS_URL "\">Transifex.com</a><br/>"
		/* 8 */   "%s: GPLv2+<br/>"
		"<br/>"
		/* 9 (REMOVED) */
		/* 10,11 */ "%s<a href=\"" SIPE_TRANSLATIONS_URL "\">Transifex.com</a>%s.<br/>"
		"<br/>"
		/* 12 */  "<b>%s:</b><br/>"
		" - Stefan Becker<br/>"
		" - Jakub Adam<br/>"
		" - Jochen De Smet (retired, Miranda port)<br/>"
		" - Michael Lamb (retired, Adium port)<br/>"
		" - Anibal Avelar (retired)<br/>"
		" - Gabriel Burt (retired)<br/>"
		" - pier11 (retired)<br/>"
		" - Tomáš Hrabčík (retired)<br/>"
		"<br/>"
		/* 13 */  "%s<br/>"
		, options,
		/* The next 13 texts make up the SIPE about note text */
		/* About note, part 1/13: introduction */
		_("A third-party plugin implementing extended version of SIP/SIMPLE used by various products"),
		/* About note, part 2/13: home page URL (label) */
		_("Home Page"),
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
		/* About note, part 9/13: (REMOVED) */
		/* About note, part 10/13: translation request, text before Transifex.com URL */
		/* append a space if text is not empty */
		_("Please help us to translate SIPE to your native language here at "),
		/* About note, part 11/13: translation request, text after Transifex.com URL */
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
	g_free(options);
	return(about);
}

struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    gboolean sso,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg)
{
	struct sipe_core_private *sipe_private;
	gchar **user_domain;
	gchar *options = g_strjoinv(" / ", (gchar **) sipe_core_build_options);

	SIPE_LOG_INFO("sipe_core_allocate: SIPE version " SIPE_CORE_VERSION "%s)", options);
	g_free(options);
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


	/* ensure that Password is valid when SSO is not selected */
	if (!sso && is_empty(password)) {
		*errmsg = _("Password is required when Single Sign-On is not enabled");
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

	/* re-use sign-in name if login is empty */
	if (is_empty(login_account))
		login_account = signin_name;

	sipe_private = g_new0(struct sipe_core_private, 1);
	SIPE_CORE_PRIVATE_FLAG_UNSET(SUBSCRIBED_BUDDIES);
	SIPE_CORE_PRIVATE_FLAG_UNSET(INITIAL_PUBLISH);
	SIPE_CORE_PRIVATE_FLAG_UNSET(SSO);
	if (sso)
		SIPE_CORE_PRIVATE_FLAG_SET(SSO);
	sipe_private->username   = g_strdup(signin_name);
	sipe_private->email      = is_empty(email) ? g_strdup(signin_name) : g_strdup(email);
	sipe_private->authuser   = sso             ? NULL                  : g_strdup(login_account);
	sipe_private->password   = sso             ? NULL                  : g_strdup(password);
	sipe_private->public.sip_name   = g_strdup(user_domain[0]);
	sipe_private->public.sip_domain = g_strdup(user_domain[1]);
	g_strfreev(user_domain);

	sipe_group_init(sipe_private);
	sipe_buddy_init(sipe_private);
	sipe_private->our_publications = g_hash_table_new_full(g_str_hash, g_str_equal,
							       g_free, (GDestroyNotify)g_hash_table_destroy);
	sipe_subscriptions_init(sipe_private);
	sipe_lync_autodiscover_init(sipe_private);
	sipe_ews_autodiscover_init(sipe_private);
	sipe_status_set_activity(sipe_private, SIPE_ACTIVITY_UNSET);

	sipe_private->media_calls = g_hash_table_new_full(g_str_hash, g_str_equal,
							  g_free, NULL);
	sipe_private->access_numbers = g_hash_table_new_full(g_str_hash, g_str_equal,
							     g_free, g_free);

	return((struct sipe_core_public *)sipe_private);
}

void sipe_core_backend_initialized(struct sipe_core_private *sipe_private,
				   guint authentication)
{
	const gchar *value;

	sipe_private->authentication_type = authentication;

	/* user specified email login? */
	value = sipe_backend_setting(SIPE_CORE_PUBLIC, SIPE_SETTING_EMAIL_LOGIN);
	if (!is_empty(value)) {
		sipe_private->email_authuser = g_strdup(value);
		sipe_private->email_password = g_strdup(sipe_backend_setting(SIPE_CORE_PUBLIC,
									     SIPE_SETTING_EMAIL_PASSWORD));
	}
}

void sipe_core_connection_cleanup(struct sipe_core_private *sipe_private)
{
	sipe_http_free(sipe_private);
	sip_transport_disconnect(sipe_private);

	sipe_schedule_cancel_all(sipe_private);

	if (sipe_private->allowed_events)
		sipe_utils_slist_free_full(sipe_private->allowed_events, g_free);

	sipe_ocs2007_free(sipe_private);

	sipe_core_buddy_menu_free(SIPE_CORE_PUBLIC);

	if (sipe_private->contact)
		g_free(sipe_private->contact);
	sipe_private->contact = NULL;
	if (sipe_private->register_callid)
		g_free(sipe_private->register_callid);
	sipe_private->register_callid = NULL;

	if (sipe_private->focus_factory_uri)
		g_free(sipe_private->focus_factory_uri);
	sipe_private->focus_factory_uri = NULL;

	sipe_groupchat_free(sipe_private);

	while (sipe_private->lync_autodiscover_servers)
		sipe_private->lync_autodiscover_servers =
			sipe_lync_autodiscover_pop(sipe_private->lync_autodiscover_servers);
}

void sipe_core_deallocate(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

#ifdef HAVE_VV
	sipe_media_handle_going_offline(sipe_private);
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

	/* pending service requests must be cancelled first */
	sipe_svc_free(sipe_private);
	sipe_webticket_free(sipe_private);
	sipe_ucs_free(sipe_private);
	sipe_lync_autodiscover_free(sipe_private);

	if (sipe_backend_connection_is_valid(SIPE_CORE_PUBLIC)) {
		sipe_subscriptions_unsubscribe(sipe_private);
		sip_transport_deregister(sipe_private);
	}

	sipe_core_connection_cleanup(sipe_private);
	sipe_ews_autodiscover_free(sipe_private);
	sipe_cal_calendar_free(sipe_private->calendar);
	sipe_certificate_free(sipe_private);

	g_free(sipe_private->public.sip_name);
	g_free(sipe_private->public.sip_domain);
	g_free(sipe_private->username);
	g_free(sipe_private->user_agent);
	g_free(sipe_private->email_password);
	g_free(sipe_private->email_authuser);
	g_free(sipe_private->email);
	g_free(sipe_private->password);
	g_free(sipe_private->authuser);
	g_free(sipe_private->status);
	g_free(sipe_private->note);
	g_free(sipe_private->ocs2005_user_states);

	sipe_buddy_free(sipe_private);
	g_hash_table_destroy(sipe_private->our_publications);
	g_hash_table_destroy(sipe_private->user_state_publications);
	g_hash_table_destroy(sipe_private->media_calls);
	sipe_subscriptions_destroy(sipe_private);
	sipe_group_free(sipe_private);

	if (sipe_private->our_publication_keys)
		sipe_utils_slist_free_full(sipe_private->our_publication_keys, g_free);

#ifdef HAVE_VV
	g_free(sipe_private->test_call_bot_uri);
	g_free(sipe_private->uc_line_uri);
	g_free(sipe_private->mras_uri);
	g_free(sipe_private->media_relay_username);
	g_free(sipe_private->media_relay_password);
	sipe_media_relay_list_free(sipe_private->media_relays);
#endif

	g_free(sipe_private->persistentChatPool_uri);
	g_free(sipe_private->addressbook_uri);
	g_free(sipe_private->dlx_uri);
	sipe_utils_slist_free_full(sipe_private->conf_mcu_types, g_free);
	g_hash_table_destroy(sipe_private->access_numbers);
	g_free(sipe_private);
}

void sipe_core_email_authentication(struct sipe_core_private *sipe_private,
				    struct sipe_http_request *request)
{
	if (sipe_private->email_authuser) {
		sipe_http_request_authentication(request,
						 sipe_private->email_authuser,
						 sipe_private->email_password);
	}
}

const gchar *sipe_core_user_agent(struct sipe_core_private *sipe_private)
{
	if (!sipe_private->user_agent) {
		const gchar *useragent = sipe_backend_setting(SIPE_CORE_PUBLIC,
							      SIPE_SETTING_USER_AGENT);
		if (is_empty(useragent)) {
/*@TODO: better approach to define _user_ OS, it's version and host architecture */
/* ref: lzodefs.h */
#if defined(__linux__) || defined(__linux) || defined(__LINUX__)
  #define SIPE_TARGET_PLATFORM "linux"
#elif defined(__NetBSD__) ||defined( __OpenBSD__) || defined(__FreeBSD__)
  #define SIPE_TARGET_PLATFORM "bsd"
#elif defined(__APPLE__) || defined(__MACOS__)
  #define SIPE_TARGET_PLATFORM "macosx"
#elif defined(_AIX) || defined(__AIX__) || defined(__aix__)
  #define SIPE_TARGET_PLATFORM "aix"
#elif defined(__solaris__) || defined(__sun)
  #define SIPE_TARGET_PLATFORM "sun"
#elif defined(_WIN32)
  #define SIPE_TARGET_PLATFORM "win"
#elif defined(__CYGWIN__)
  #define SIPE_TARGET_PLATFORM "cygwin"
#elif defined(__hpux__)
  #define SIPE_TARGET_PLATFORM "hpux"
#elif defined(__sgi__)
  #define SIPE_TARGET_PLATFORM "irix"
#else
  #define SIPE_TARGET_PLATFORM "unknown"
#endif

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  #define SIPE_TARGET_ARCH "x86_64"
#elif defined(__386__) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_M_I386)
  #define SIPE_TARGET_ARCH "i386"
#elif defined(__ppc64__)
  #define SIPE_TARGET_ARCH "ppc64"
#elif defined(__powerpc__) || defined(__powerpc) || defined(__ppc__) || defined(__PPC__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PWR)
  #define SIPE_TARGET_ARCH "ppc"
#elif defined(__hppa__) || defined(__hppa)
  #define SIPE_TARGET_ARCH "hppa"
#elif defined(__mips__) || defined(__mips) || defined(_MIPS_ARCH) || defined(_M_MRX000)
  #define SIPE_TARGET_ARCH "mips"
#elif defined(__s390__) || defined(__s390) || defined(__s390x__) || defined(__s390x)
  #define SIPE_TARGET_ARCH "s390"
#elif defined(__sparc__) || defined(__sparc) || defined(__sparcv8)
  #define SIPE_TARGET_ARCH "sparc"
#elif defined(__arm__)
  #define SIPE_TARGET_ARCH "arm"
#else
  #define SIPE_TARGET_ARCH "other"
#endif
			gchar *backend = sipe_backend_version();
			sipe_private->user_agent = g_strdup_printf("%s Sipe/" PACKAGE_VERSION " (" SIPE_TARGET_PLATFORM "-" SIPE_TARGET_ARCH ")",
								   backend);
			g_free(backend);
		} else {
			sipe_private->user_agent = g_strdup(useragent);
		}
	}
	return(sipe_private->user_agent);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
