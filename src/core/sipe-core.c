/**
 * @file sipe-core.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>
#ifdef HAVE_NSS
#include "nss.h"
#endif
#ifdef HAVE_GMIME
#include <gmime/gmime.h>
#endif

#include "sipe-common.h"
#include "sip-csta.h"
#include "sip-sec.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-subscriptions.h"
#include "sipe-media.h"
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
#ifdef HAVE_NSS
	if (!NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
		SIPE_DEBUG_INFO_NOFORMAT("NSS initialised");
	}
#endif
#ifdef HAVE_GMIME
	g_mime_init(0);
#endif
}

void sipe_core_destroy(void)
{
	sipe_chat_destroy();
#ifdef HAVE_NSS
	/* do nothing.
	 * We don't want accedently switch off NSS possibly used by other plugin -
	 * ssl-nss in Pidgin for example.
	 */
#endif
#ifdef HAVE_GMIME
	g_mime_shutdown();
#endif
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
		/* 7 */   "%s: <a href=\"https://transifex.net/projects/p/pidgin-sipe/c/mob-branch/\">Transifex.net</a><br/>"
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
		/* 10,11 */ "%s<a href=\"https://transifex.net/projects/p/pidgin-sipe/c/mob-branch/\">Transifex.net</a>%s.<br/>"
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

	if (sip->csta) {
		sip_csta_close(sipe_private);
	}

	if (sipe_backend_connection_is_valid(SIPE_CORE_PUBLIC)) {
		sipe_subscriptions_unsubscribe(sipe_private);
		sip_transport_deregister(sipe_private);
	}

	sipe_connection_cleanup(sipe_private);
	g_free(sipe_private->public.sip_name);
	g_free(sipe_private->public.sip_domain);
	g_free(sipe_private->username);
	g_free(sip->email);
	g_free(sip->password);
	g_free(sip->authdomain);
	g_free(sip->authuser);
	g_free(sip->status);
	g_free(sip->note);
	g_free(sip->user_states);

	sipe_buddy_free_all(sipe_private);
	g_hash_table_destroy(sipe_private->buddies);
	g_hash_table_destroy(sip->our_publications);
	g_hash_table_destroy(sip->user_state_publications);
	sipe_subscriptions_destroy(sipe_private);

	if (sip->groups) {
		GSList *entry = sip->groups;
		while (entry) {
			struct sipe_group *group = entry->data;
			g_free(group->name);
			g_free(group);
			entry = entry->next;
		}
	}
	g_slist_free(sip->groups);

	if (sip->our_publication_keys) {
		GSList *entry = sip->our_publication_keys;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sip->our_publication_keys);

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
