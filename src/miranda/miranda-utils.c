/**
 * @file miranda-utils.c
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

#define MIRANDA_VER 0x900

#include <windows.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_database.h"
#include "m_netlib.h"

#include "libsipe.h"
#include "sipe-backend.h"
#include "miranda-private.h"

static GHashTable *entities = NULL;

#define ADDENT(a,b) g_hash_table_insert(entities, a, b)


gchar* sipe_miranda_getContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name)
{
	return DBGetString( hContact, pr->proto.m_szModuleName, name );
}

gchar* sipe_miranda_getString(const SIPPROTO *pr, const gchar* name)
{
	return sipe_miranda_getContactString( pr, NULL, name );
}

DWORD sipe_miranda_getDword(const SIPPROTO *pr, HANDLE hContact, const gchar* name, DWORD* rv)
{
	DBVARIANT dbv;
	DBCONTACTGETSETTING cgs;

	cgs.szModule = pr->proto.m_szModuleName;
	cgs.szSetting = name;
	cgs.pValue=&dbv;
	if(CallService(MS_DB_CONTACT_GETSETTING,(WPARAM)hContact,(LPARAM)&cgs))
		return 0;

	if (rv) {
		*rv = dbv.dVal;
		return 1;
	} else {
		return dbv.dVal;
	}

}

int sipe_miranda_setWord(const SIPPROTO *pr, HANDLE hContact, const gchar* szSetting, WORD wValue)
{
	return DBWriteContactSettingWord(hContact, pr->proto.m_szModuleName, szSetting, wValue);
}

gbooleanbsipe_miranda_get_bool(const SIPPROTO *pr, const gchar *name, gboolean defval)
{
	DWORD ret;

	if (sipe_miranda_getDword( pr, NULL, name, &ret ))
		return ret?TRUE:FALSE;

	return defval;
}

int sipe_miranda_getStaticString(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, gchar* dest, unsigned dest_len)
{
	DBVARIANT dbv;
	DBCONTACTGETSETTING sVal;

	dbv.pszVal = dest;
	dbv.cchVal = (WORD)dest_len;
	dbv.type = DBVT_ASCIIZ;

	sVal.pValue = &dbv;
	sVal.szModule = pr->proto.m_szModuleName;
	sVal.szSetting = valueName;
	if (CallService(MS_DB_CONTACT_GETSETTINGSTATIC, (WPARAM)hContact, (LPARAM)&sVal) != 0)
		return 1;

	return (dbv.type != DBVT_ASCIIZ);
}

void sipe_miranda_setContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name, const gchar* value)
{
	DBWriteContactSettingString(hContact, pr->proto.m_szModuleName, name, value);
}

void sipe_miranda_setContactStringUtf(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, const gchar* parValue )
{
	DBWriteContactSettingStringUtf( hContact, pr->proto.m_szModuleName, valueName, parValue );
}

void sipe_miranda_setString(const SIPPROTO *pr, const gchar* name, const gchar* value)
{
	sipe_miranda_setContactString( pr, NULL, name, value );
}

void sipe_miranda_setStringUtf(const SIPPROTO *pr, const gchar* name, const gchar* value)
{
	sipe_miranda_setContactStringUtf( pr, NULL, name, value );
}

static void initEntities(void)
{
	entities = g_hash_table_new(g_str_hash, g_str_equal);

	ADDENT("nbsp"," ");
	ADDENT("quot","\"");
	ADDENT("lt","<");
	ADDENT("gt",">");
	ADDENT("apos","'");
}

gchar* sipe_miranda_eliminate_html(const gchar *string, int len)
{
	gchar *tmp = (char*)mir_alloc(len + 1);
	int i,j;
	BOOL tag = FALSE;
	gchar *res;

	if (!entities)
		initEntities();

	for (i=0,j=0;i<len;i++)
	{
		if (!tag && string[i] == '<')
		{
			if ((i + 4 <= len) && (!_strnicmp(string + i, "<br>", 4) || !_strnicmp(string + i, "<br/>", 5)))
			{ // insert newline
				tmp[j] = '\r';
				j++;
				tmp[j] = '\n';
				j++;
			}
			tag = TRUE;
		}
		else if (tag && string[i] == '>')
		{
			tag = FALSE;
		}
		else if (!tag)
		{
			char *tkend;

			if ((string[i] == '&') && (tkend = strstr((char*)&string[i], ";")))
			{
				gchar *rep;
				gchar c = *tkend;
				*tkend = '\0';

				rep = (char*)g_hash_table_lookup(entities, &string[i+1]);

				if (rep)
				{
					strcpy(&tmp[j], rep);
					j += strlen(rep);
					i += strlen(&string[i]);
					*tkend = c;
				}
				else
				{
					*tkend = c;
					tmp[j] = string[i];
					j++;
				}

			}
			else
			{
				tmp[j] = string[i];
				j++;
			}
		}
		tmp[j] = '\0';
	}
//	mir_free((void *)string);
//	res = DemangleXml(tmp, strlennull(tmp));
//	mir_free(tmp);
	res = tmp;

	return res;
}

unsigned short sipe_miranda_network_get_port_from_fd( HANDLE fd )
{
	SOCKET sock = CallService(MS_NETLIB_GETSOCKET, (WPARAM)fd, (LPARAM)0);

	struct sockaddr_in sockbuf;
	int namelen = sizeof(sockbuf);
	getsockname(sock, (struct sockaddr *)&sockbuf, &namelen);
	SIPE_DEBUG_INFO("<%x> <%x><%x><%s>", namelen, sockbuf.sin_family, sockbuf.sin_port, inet_ntoa(sockbuf.sin_addr) );

	return sockbuf.sin_port;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
