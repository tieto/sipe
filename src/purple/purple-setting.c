/**
 * @file purple-setting.c
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

#include <glib.h>

#include "account.h"
#include "connection.h"

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

/**
 * Map sipe_setting values to purple account setting keys
 *
 * This needs to be kept in sync with
 *
 *     api/sipe-backend.h
 *     purple-plugin.c:init_plugin()
 */
static const gchar * const setting_name[SIPE_SETTING_LAST] = {
	"email_url",      /* SIPE_SETTING_EMAIL_URL      */
	"email_login",    /* SIPE_SETTING_EMAIL_LOGIN    */
	"email_password", /* SIPE_SETTING_EMAIL_PASSWORD */
	"groupchat_user", /* SIPE_SETTING_GROUPCHAT_USER */
	"useragent"       /* SIPE_SETTING_USER_AGENT     */
};

const gchar *sipe_backend_setting(struct sipe_core_public *sipe_public,
				  sipe_setting type)
{
	return(purple_account_get_string(purple_connection_get_account(sipe_public->backend_private->gc),
					 setting_name[type], NULL));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
