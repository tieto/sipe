/**
 * @file purple-plugin.c
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

#include "sipe-common.h"

/* Flag needed for correct version of PURPLE_INIT_PLUGIN() */
#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include "accountopt.h"
#include "prpl.h"
#include "plugin.h"

#include "sipe-core-api.h"
#include "sipe-nls.h"

#include "core-depurple.h"

void sipe_plugin_destroy(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
	GList *entry;

	sipe_core_destroy();

	entry = prpl_info.protocol_options;
	while (entry) {
		purple_account_option_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	prpl_info.protocol_options = NULL;

	entry = prpl_info.user_splits;
	while (entry) {
		purple_account_user_split_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	prpl_info.user_splits = NULL;
}

static void init_plugin(PurplePlugin *plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;

	/* This needs to be called first */
	sipe_core_init();

	purple_plugin_register(plugin);

	split = purple_account_user_split_new(_("Login\n   user  or  DOMAIN\\user  or\n   user@company.com"), NULL, ',');
	purple_account_user_split_set_reverse(split, FALSE);
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = purple_account_option_string_new(_("Server[:Port]\n(leave empty for auto-discovery)"), "server", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_list_new(_("Connection type"), "transport", NULL);
	purple_account_option_add_list_item(option, _("Auto"), "auto");
	purple_account_option_add_list_item(option, _("SSL/TLS"), "tls");
	purple_account_option_add_list_item(option, _("TCP"), "tcp");
	purple_account_option_add_list_item(option, _("UDP"), "udp");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/*option = purple_account_option_bool_new(_("Publish status (note: everyone may watch you)"), "doservice", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);*/

	option = purple_account_option_string_new(_("User Agent"), "useragent", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#ifdef HAVE_KERBEROS
	option = purple_account_option_bool_new(_("Use Kerberos"), "krb5", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/* Suitable for sspi/NTLM, sspi/Kerberos and krb5 security mechanisms
	 * No login/password is taken into account if this option present,
	 * instead used default credentials stored in OS.
	 */
	option = purple_account_option_bool_new(_("Use Single Sign-On"), "sso", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

	option = purple_account_option_list_new(_("Calendar source"), "calendar", NULL);
	purple_account_option_add_list_item(option, _("Exchange 2007/2010"), "EXCH");
	purple_account_option_add_list_item(option, _("None"), "NONE");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/** Example: https://server.company.com/EWS/Exchange.asmx */
	option = purple_account_option_string_new(_("Email services URL\n(leave empty for auto-discovery)"), "email_url", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Email address\n(if different from Username)"), "email", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/** Example: DOMAIN\user  or  user@company.com */
	option = purple_account_option_string_new(_("Email login\n(if different from Login)"), "email_login", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Email password\n(if different from Password)"), "email_password", "");
	purple_account_option_set_masked(option, TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
}

PURPLE_INIT_PLUGIN(sipe, init_plugin, info);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
