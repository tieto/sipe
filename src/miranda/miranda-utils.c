/**
 * @file miranda-utils.c
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

#define MIRANDA_VER 0x900

#include <windows.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_database.h"
#include "m_netlib.h"
#include "m_langpack.h"
#include "m_protomod.h"

#include "glib.h"
#include "sipe-backend.h"
#include "miranda-private.h"

static GHashTable *entities = NULL;

#define ADDENT(a,b) g_hash_table_insert(entities, a, b)


gchar* sipe_miranda_getGlobalString(const gchar* name)
{
	return DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, name );
}

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

gboolean sipe_miranda_get_bool(const SIPPROTO *pr, const gchar *name, gboolean defval)
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

void sipe_miranda_setGlobalString(const gchar* name, const gchar* value)
{
	DBWriteContactSettingString(NULL, SIPSIMPLE_PROTOCOL_NAME, name, value);
}

void sipe_miranda_setGlobalStringUtf(const gchar* valueName, const gchar* parValue )
{
	DBWriteContactSettingStringUtf( NULL, SIPSIMPLE_PROTOCOL_NAME, valueName, parValue );
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

/* Misc functions */
TCHAR _tcharbuf[32768];
TCHAR* CHAR2TCHAR( const char *chr ) {
#ifdef UNICODE
	if (!chr) return NULL;
	mbstowcs( _tcharbuf, chr, strlen(chr)+1 );
	return _tcharbuf;
#else
	return chr;
#endif
}

char _charbuf[32768];
char* TCHAR2CHAR( const TCHAR *tchr ) {
#ifdef UNICODE
	if (!tchr) return NULL;
	wcstombs( _charbuf, tchr, wcslen(tchr)+1 );
	return _charbuf;
#else
	return tchr;
#endif
}

HANDLE sipe_miranda_AddEvent(const SIPPROTO *pr, HANDLE hContact, WORD wType, DWORD dwTime, DWORD flags, DWORD cbBlob, PBYTE pBlob)
{
	DBEVENTINFO dbei = {0};

	dbei.cbSize = sizeof(dbei);
	dbei.szModule = pr->proto.m_szModuleName;
	dbei.timestamp = dwTime;
	dbei.flags = flags;
	dbei.eventType = wType;
	dbei.cbBlob = cbBlob;
	dbei.pBlob = pBlob;

	return (HANDLE)CallService(MS_DB_EVENT_ADD, (WPARAM)hContact, (LPARAM)&dbei);
}

struct msgboxinfo {
	TCHAR *msg;
	TCHAR *caption;
};

static unsigned __stdcall msgboxThread(void* arg)
{
	struct msgboxinfo *err = (struct msgboxinfo*)arg;
	if (!err)
		return 0;

	MessageBox(NULL, err->msg, err->caption, MB_OK);
	mir_free(err->msg);
	mir_free(err->caption);
	g_free(err);
	return 0;
}

void sipe_miranda_msgbox(const char *msg, const char *caption)
{
	struct msgboxinfo *info = g_new(struct msgboxinfo,1);

	info->msg = mir_a2t(msg);
	info->caption = mir_a2t(caption);

	CloseHandle((HANDLE) mir_forkthreadex( msgboxThread, info, 8192, NULL ));
}

static unsigned __stdcall sendbroadcastThread(void* arg)
{
	ACKDATA *ack = (ACKDATA*)arg;
	SIPE_DEBUG_INFO("delayed broadcasting result <%08x> par1 <%08x> par2 <%08x>", ack->type, ack->hProcess, ack->lParam);
	CallServiceSync(MS_PROTO_BROADCASTACK,0,(LPARAM)ack);
	g_free(ack);
	return 0;
}

int sipe_miranda_SendBroadcast(SIPPROTO *pr, HANDLE hContact,int type,int result,HANDLE hProcess,LPARAM lParam)
{
	ACKDATA *ack = g_new0(ACKDATA, 1);

	ack->cbSize = sizeof(ACKDATA);
	ack->szModule = pr->proto.m_szModuleName;
	ack->hContact = hContact;
	ack->type = type;
	ack->result = result;
	ack->hProcess = hProcess;
	ack->lParam = lParam;

	if (pr->main_thread_id == GetCurrentThreadId())
	{
		int ret;
		SIPE_DEBUG_INFO("broadcasting result <%08x> par1 <%08x> par2 <%08x>", type, hProcess, lParam);
		ret = CallServiceSync(MS_PROTO_BROADCASTACK,0,(LPARAM)ack);
		g_free(ack);
		return ret;
	}
	else
	{
		CloseHandle((HANDLE) mir_forkthreadex( sendbroadcastThread, ack, 8192, NULL ));
		return 0;
	}
}

struct sipe_miranda_connection_info {
	SIPPROTO *pr;
	const gchar *server_name;
	int server_port;
	int timeout;
	gboolean tls;
	void (*callback)(HANDLE fd, void *data, const gchar *reason);
	void *data;

	/* Private. For locking only */
	HANDLE hDoneEvent;
	HANDLE fd;
	const gchar *reason;
};

static void __stdcall
connection_cb_async(void *data)
{
	struct sipe_miranda_connection_info *entry = (struct sipe_miranda_connection_info*)data;
	SIPE_DEBUG_INFO("[C:%08x] Calling real connected function", entry);
	entry->callback(entry->fd, entry->data, entry->reason);
	SetEvent(entry->hDoneEvent);
}

static unsigned __stdcall
sipe_miranda_connected_callback(void* data)
{
	struct sipe_miranda_connection_info *info = (struct sipe_miranda_connection_info*)data;
	SIPPROTO *pr = info->pr;
	NETLIBOPENCONNECTION ncon = {0};

	ncon.cbSize = sizeof(ncon);
	ncon.flags = NLOCF_V2;
	ncon.szHost = info->server_name;
	ncon.wPort = info->server_port;
	ncon.timeout = info->timeout;

	info->fd = (HANDLE)CallService(MS_NETLIB_OPENCONNECTION, (WPARAM)pr->m_hServerNetlibUser, (LPARAM)&ncon);
	if (info->fd == NULL)  {
		SIPE_DEBUG_INFO("[C:%08x] Connection to <%s:%d> failed", info, info->server_name, info->server_port);
		info->reason = "Connection failed";

	} else {
		SIPE_DEBUG_INFO("[C:%08x] connected <%d>", info, (int)info->fd);

		if (info->tls)
		{
			if (!CallService(MS_NETLIB_STARTSSL, (WPARAM)info->fd, 0))
			{
				Netlib_CloseHandle(info->fd);
				info->fd = NULL;
				info->reason = "Failed to enabled SSL";
			} else {
				SIPE_DEBUG_INFO("[C:%08x] SSL enabled", info);
			}
		} else {
			info->reason = NULL;
		}
	}

	info->hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CallFunctionAsync(connection_cb_async, info);
	WaitForSingleObject(info->hDoneEvent, INFINITE);
	CloseHandle(info->hDoneEvent);

	g_free(info);
	return 0;
}

struct sipe_miranda_connection_info *
sipe_miranda_connect(SIPPROTO *pr,
		     const gchar *host,
		     int port,
		     gboolean tls,
		     int timeout,
		     void (*callback)(HANDLE fd, void *data, const gchar *reason),
		     void *data)
{
	struct sipe_miranda_connection_info *info = g_new0(struct sipe_miranda_connection_info, 1);
	SIPE_DEBUG_INFO("[C:%08x] Connecting to <%s:%d> tls <%d> timeout <%d>", info, host, port, tls, timeout);

	info->pr = pr;
	info->server_name = host;
	info->server_port = port;
	info->timeout = timeout;
	info->tls = tls;
	info->callback = callback;
	info->data = data;

	CloseHandle((HANDLE) mir_forkthreadex( sipe_miranda_connected_callback, info, 65536, NULL ));

	return info;
}

struct sipe_miranda_servicedata
{
	const char *service;
	WPARAM wParam;
	LPARAM lParam;
};

static unsigned __stdcall
sipe_miranda_service_async_callback(void* data)
{
	struct sipe_miranda_servicedata *svc = (struct sipe_miranda_servicedata *)data;
	CallService(svc->service, svc->wParam, svc->lParam);
	g_free(svc);
	return 0;
}

void
CallServiceAsync(const char *service, WPARAM wParam, LPARAM lParam)
{
	struct sipe_miranda_servicedata *svc = g_new(struct sipe_miranda_servicedata, 1);
	svc->service = service;
	svc->wParam = wParam;
	svc->lParam = lParam;
	CloseHandle((HANDLE) mir_forkthreadex( sipe_miranda_service_async_callback, svc, 65536, NULL ));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
