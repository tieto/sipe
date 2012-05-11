/**
 * @file miranda-setting.c
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

#include <windows.h>

#include <glib.h>

#include "sipe-core.h"
#include "sipe-backend.h"

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"
#include "m_database.h"

#include "miranda-private.h"

/**
 * Map sipe_setting values to miranda account setting keys
 *
 * This needs to be kept in sync with
 *
 *     api/sipe-backend.h
 */
static const gchar * const setting_name[SIPE_SETTING_LAST] = {
	"email_url",      /* SIPE_SETTING_EMAIL_URL      */
	"login",          /* SIPE_SETTING_EMAIL_LOGIN    */
	"password",       /* SIPE_SETTING_EMAIL_PASSWORD */
	"groupchat_user", /* SIPE_SETTING_GROUPCHAT_USER */
	"useragent"       /* SIPE_SETTING_USER_AGENT     */
};

const gchar *sipe_backend_setting(struct sipe_core_public *sipe_public,
				  sipe_setting type)
{
	SIPPROTO *pr = sipe_public->backend_private;
	gchar *ret;
	gchar *tmp;

	if (type == SIPE_SETTING_EMAIL_PASSWORD) {
		tmp = (char*)mir_calloc(1024);

		if (sipe_miranda_getStaticString(pr, NULL, "password", tmp, 1024 )) tmp[0] = '\0';
		CallService(MS_DB_CRYPT_DECODESTRING, sizeof(tmp),(LPARAM)tmp);

        } else {
		tmp = sipe_miranda_getString(pr, setting_name[type] );
	}

	ret = g_strdup(tmp);
	mir_free(tmp);
	return ret;

}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
