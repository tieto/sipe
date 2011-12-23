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

#include <windows.h>

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_database.h"
#include "m_netlib.h"
#include "m_langpack.h"
#include "m_protomod.h"

#include "glib.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

/*
 * Table to hold HTML entities we want to convert
 */
static GHashTable *entities = NULL;


/**
 * Various shortcut functions to get database values
 */
gchar*
sipe_miranda_getGlobalString(const gchar* name)
{
	return DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, name );
}

gchar*
sipe_miranda_getContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name)
{
	return DBGetString( hContact, pr->proto.m_szModuleName, name );
}

gchar*
sipe_miranda_getString(const SIPPROTO *pr, const gchar* name)
{
	return sipe_miranda_getContactString( pr, NULL, name );
}

DWORD
sipe_miranda_getDword(const SIPPROTO *pr, HANDLE hContact, const gchar* name, DWORD* rv)
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

WORD
sipe_miranda_getGlobalWord(const gchar* name, WORD* rv)
{
	DBVARIANT dbv;
	DBCONTACTGETSETTING cgs;

	cgs.szModule = SIPSIMPLE_PROTOCOL_NAME;
	cgs.szSetting = name;
	cgs.pValue=&dbv;
	if(CallService(MS_DB_CONTACT_GETSETTING, (WPARAM)NULL,(LPARAM)&cgs))
		return 0;

	if (rv) {
		*rv = dbv.wVal;
		return 1;
	} else {
		return dbv.wVal;
	}

}

WORD
sipe_miranda_getWord(const SIPPROTO *pr, HANDLE hContact, const gchar* name, WORD* rv)
{
	DBVARIANT dbv;
	DBCONTACTGETSETTING cgs;

	cgs.szModule = pr->proto.m_szModuleName;
	cgs.szSetting = name;
	cgs.pValue=&dbv;
	if(CallService(MS_DB_CONTACT_GETSETTING,(WPARAM)hContact,(LPARAM)&cgs))
		return 0;

	if (rv) {
		*rv = dbv.wVal;
		return 1;
	} else {
		return dbv.wVal;
	}

}

gboolean
sipe_miranda_getBool(const SIPPROTO *pr, const gchar *name, gboolean defval)
{
	WORD ret;

	if (sipe_miranda_getWord( pr, NULL, name, &ret ))
		return ret?TRUE:FALSE;

	return defval;
}

int
sipe_miranda_getStaticString(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, gchar* dest, unsigned dest_len)
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

/**
 * Various shortcut functions to set database values
 */
void
sipe_miranda_setGlobalString(const gchar* name, const gchar* value)
{
	DBWriteContactSettingString(NULL, SIPSIMPLE_PROTOCOL_NAME, name, value);
}

void
sipe_miranda_setGlobalStringUtf(const gchar* valueName, const gchar* parValue )
{
	DBWriteContactSettingStringUtf( NULL, SIPSIMPLE_PROTOCOL_NAME, valueName, parValue );
}

void
sipe_miranda_setContactString(const SIPPROTO *pr, HANDLE hContact, const gchar* name, const gchar* value)
{
	DBWriteContactSettingString(hContact, pr->proto.m_szModuleName, name, value);
}

void
sipe_miranda_setContactStringUtf(const SIPPROTO *pr, HANDLE hContact, const gchar* valueName, const gchar* parValue )
{
	DBWriteContactSettingStringUtf( hContact, pr->proto.m_szModuleName, valueName, parValue );
}

void
sipe_miranda_setString(const SIPPROTO *pr, const gchar* name, const gchar* value)
{
	sipe_miranda_setContactString( pr, NULL, name, value );
}

void
sipe_miranda_setStringUtf(const SIPPROTO *pr, const gchar* name, const gchar* value)
{
	sipe_miranda_setContactStringUtf( pr, NULL, name, value );
}

int
sipe_miranda_setGlobalWord(const gchar* szSetting, WORD wValue)
{
	return DBWriteContactSettingWord(NULL, SIPSIMPLE_PROTOCOL_NAME, szSetting, wValue);
}

int
sipe_miranda_setWord(const SIPPROTO *pr, HANDLE hContact, const gchar* szSetting, WORD wValue)
{
	return DBWriteContactSettingWord(hContact, pr->proto.m_szModuleName, szSetting, wValue);
}

int
sipe_miranda_setBool(const SIPPROTO *pr, const gchar *name, gboolean value)
{
	return DBWriteContactSettingWord(NULL, pr->proto.m_szModuleName, name, value?1:0);
}

/*
 * Initialize our table of HTML entities
 */
#define ADDENT(a,b) g_hash_table_insert(entities, a, b)
static void
initEntities(void)
{
	entities = g_hash_table_new(g_str_hash, g_str_equal);

	ADDENT("nbsp"," ");
	ADDENT("quot","\"");
	ADDENT("lt","<");
	ADDENT("gt",">");
	ADDENT("apos","'");
}

/*
 * WARNING: Returns miranda-allocated string, not glib one
 */
gchar*
sipe_miranda_eliminate_html(const gchar *string, int len)
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
	res = tmp;

	return res;
}

unsigned short
sipe_miranda_network_get_port_from_fd( HANDLE fd )
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

HANDLE
sipe_miranda_AddEvent(const SIPPROTO *pr, HANDLE hContact, WORD wType, DWORD dwTime, DWORD flags, DWORD cbBlob, PBYTE pBlob)
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

static unsigned __stdcall
msgboxThread(void* arg)
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

void
sipe_miranda_msgbox(const char *msg, const char *caption)
{
	struct msgboxinfo *info = g_new(struct msgboxinfo,1);

	info->msg = mir_a2t(msg);
	info->caption = mir_a2t(caption);

	CloseHandle((HANDLE) mir_forkthreadex( msgboxThread, info, 8192, NULL ));
}

char* sipe_miranda_acktype_strings[] = {
	"ACKTYPE_MESSAGE",	"ACKTYPE_URL",		"ACKTYPE_FILE",
	"ACKTYPE_CHAT",		"ACKTYPE_AWAYMSG",	"ACKTYPE_AUTHREQ",
	"ACKTYPE_ADDED",	"ACKTYPE_GETINFO",	"ACKTYPE_SETINFO",
	"ACKTYPE_LOGIN",	"ACKTYPE_SEARCH",	"ACKTYPE_NEWUSER",
	"ACKTYPE_STATUS",	"ACKTYPE_CONTACTS",	"ACKTYPE_AVATAR",
	"ACKTYPE_EMAIL" };

char* sipe_miranda_ackresult_strings[] = {
	"ACKRESULT_SUCCESS",	"ACKRESULT_FAILED",	"ACKRESULT_CONNECTING",
	"ACKRESULT_CONNECTED",	"ACKRESULT_INITIALISING",	"ACKRESULT_SENTREQUEST",
	"ACKRESULT_DATA",	"ACKRESULT_NEXTFILE",	"ACKRESULT_FILERESUME",
	"ACKRESULT_DENIED",	"ACKRESULT_STATUS",	"ACKRESULT_LISTENING",
	"ACKRESULT_CONNECTPROXY",	"ACKRESULT_SEARCHRESULT" };

int
sipe_miranda_SendBroadcast(SIPPROTO *pr, HANDLE hContact,int type,int result,HANDLE hProcess,LPARAM lParam)
{
	ACKDATA ack = {0};

	ack.cbSize = sizeof(ACKDATA);
	ack.szModule = pr->proto.m_szModuleName;
	ack.hContact = hContact;
	ack.type = type;
	ack.result = result;
	ack.hProcess = hProcess;
	ack.lParam = lParam;

	SIPE_DEBUG_INFO("broadcasting contact <%08x> type <%d:%s> result <%d:%s> par1 <%08x> par2 <%08x>",
		hContact,
		type, sipe_miranda_acktype_strings[type],
		result, sipe_miranda_ackresult_strings[result>99 ? result-98 : result],
		hProcess, lParam);

	return CallServiceSync(MS_PROTO_BROADCASTACK,0,(LPARAM)&ack);
}

struct sipe_miranda_connection_info {
	SIPPROTO *pr;
	gchar *server_name;
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

	g_free(info->server_name);
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
	info->server_name = g_strdup(host);
	info->server_port = port;
	info->timeout = timeout;
	info->tls = tls;
	info->callback = callback;
	info->data = data;

	CloseHandle((HANDLE) mir_forkthreadex( sipe_miranda_connected_callback, info, 65536, NULL ));

	return info;
}

struct sipe_miranda_ack_args
{
        HANDLE hContact;
        int    nAckType;
        int    nAckResult;
        HANDLE hSequence;
        gchar *pszMessage;
	const gchar *modname;
};

static unsigned __stdcall
ProtocolAckThread(struct sipe_miranda_ack_args* args)
{
	ProtoBroadcastAck(args->modname, args->hContact, args->nAckType, args->nAckResult, args->hSequence, (LPARAM)args->pszMessage);

	if (args->nAckResult == ACKRESULT_SUCCESS)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent ACK");
	else if (args->nAckResult == ACKRESULT_FAILED)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent NACK");

	g_free(args->pszMessage);
	g_free(args);
	return 0;
}

void
sipe_miranda_SendProtoAck( SIPPROTO *pr, HANDLE hContact, DWORD dwCookie, int nAckResult, int nAckType, const char* pszMessage)
{
	struct sipe_miranda_ack_args* pArgs = g_new0(struct sipe_miranda_ack_args, 1);

	pArgs->hContact = hContact;
	pArgs->hSequence = (HANDLE)dwCookie;
	pArgs->nAckResult = nAckResult;
	pArgs->nAckType = nAckType;
	pArgs->pszMessage = g_strdup(pszMessage);
	pArgs->modname = pr->proto.m_szModuleName;

	CloseHandle((HANDLE) mir_forkthreadex(ProtocolAckThread, pArgs, 65536, NULL));
}

gboolean
sipe_miranda_cmd(gchar *cmd, gchar *buf, DWORD *maxlen)
{
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = {0};
	SECURITY_ATTRIBUTES sa = {0};
	HANDLE rd,wr;

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&rd, &wr, &sa, 0))
	{
		SIPE_DEBUG_INFO_NOFORMAT("Could not create pipe");
		return FALSE;
	}

	SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = wr;
	si.hStdError = wr;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		SIPE_DEBUG_INFO("Could not run child program <%s> (%d)", cmd, GetLastError());
		return FALSE;
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if (!ReadFile(rd, buf, *maxlen, maxlen, NULL))
	{
		SIPE_DEBUG_INFO("Could not read from child program <%s>", cmd);
		return FALSE;
	}

	return TRUE;
}

gchar*
sipe_miranda_html2rtf(const gchar *text)
{
	const gchar *intro = "{\\rtf1\\ansi";
	const gchar *link1 = "{\\field{\\*\\fldinst{HYPERLINK \"";
	const gchar *link2 = "}}{\\fldrslt {\\ul\\cf2 ";
	gchar *tmp = g_malloc(strlen(text)+1);
	int maxlen = strlen(text);
	const gchar *i = text;
	int j = 0;
	gboolean skiptag = FALSE;
	gboolean escape = FALSE;
	gboolean copystring = FALSE;
	gboolean link_stage2 = FALSE;

	strncpy(tmp+j, intro, maxlen-j);
	j += strlen(intro);

	while (*i)
	{
		if (j+100>=maxlen) /* 100 is max substitution size */
		{
			maxlen += 128;
			tmp = g_realloc(tmp, maxlen);
		}
		if (skiptag && !escape && *i != '>') {
			i++;
		} else if (skiptag && !escape) {
			i++;
			skiptag = FALSE;
		} else if (copystring) {
			if (!escape && *i == '"') copystring = FALSE;
			if (escape) escape = FALSE;
			else if (*i == '\\') escape = TRUE;
			*(tmp+j) = *i;
			j++;
			i++;
		} else if (link_stage2) {
			strcpy(tmp+j, link2);
			j += strlen(link2);
			link_stage2 = FALSE;
			skiptag = TRUE;
		} else if (g_str_has_prefix(i,"<br/>"))	{
			strcpy(tmp+j, "\\par\n");
			j += 5;
			i += 5;
		} else if (g_str_has_prefix(i,"<b>")) {
			strcpy(tmp+j, "\\b");
			j += 2;
			i += 3;
		} else if (g_str_has_prefix(i,"</b>")) {
			strcpy(tmp+j, "\\b0");
			j += 3;
			i += 4;
		} else if (g_str_has_prefix(i,"<font size=\"")) {
			strcpy(tmp+j, "\\fs36");
			j += 5;
			i += 12;
			skiptag = TRUE;
		} else if (g_str_has_prefix(i,"</font>")) {
			strcpy(tmp+j, "\\fs20");
			j += 5;
			i += 7;
		} else if (g_str_has_prefix(i,"<a href=\"")) {
			strcpy(tmp+j, link1);
			j += strlen(link1);
			link_stage2 = TRUE;
			copystring = TRUE;
			i += 9;
		} else if (g_str_has_prefix(i,"</a>")) {
			strcpy(tmp+j, "}}}\\cf0 ");
			j += 7;
			i += 4;
		} else if (*i == '<') {
			skiptag = TRUE;
		} else {
			if (escape) {
				escape = FALSE;
			} else if (*i == '\\') {
				escape = TRUE;
			}
			if (!skiptag)
			{
				*(tmp+j) = *i;
				j++;
			}
			i++;
		}
	}
	*(tmp+j++) = '}';
	*(tmp+j++) = '\0';
	tmp = g_realloc(tmp, j);
	return tmp;
}

int SipeStatusToMiranda(guint activity) {

	switch (activity)
	{
	case SIPE_ACTIVITY_OFFLINE:
		return ID_STATUS_OFFLINE;
	case SIPE_ACTIVITY_AVAILABLE:
		return ID_STATUS_ONLINE;
	case SIPE_ACTIVITY_ON_PHONE:
		return ID_STATUS_ONTHEPHONE;
	case SIPE_ACTIVITY_DND:
	case SIPE_ACTIVITY_URGENT_ONLY:
		return ID_STATUS_DND;
	case SIPE_ACTIVITY_AWAY:
	case SIPE_ACTIVITY_OOF:
		return ID_STATUS_NA;
	case SIPE_ACTIVITY_LUNCH:
		return ID_STATUS_OUTTOLUNCH;
	case SIPE_ACTIVITY_BUSY:
	case SIPE_ACTIVITY_IN_MEETING:
	case SIPE_ACTIVITY_IN_CONF:
		return ID_STATUS_OCCUPIED;
	case SIPE_ACTIVITY_INVISIBLE:
		return ID_STATUS_INVISIBLE;
	case SIPE_ACTIVITY_BRB:
		return ID_STATUS_AWAY;
	case SIPE_ACTIVITY_UNSET:
		return ID_STATUS_OFFLINE;
	case SIPE_ACTIVITY_INACTIVE:
	case SIPE_ACTIVITY_ONLINE:
	case SIPE_ACTIVITY_BUSYIDLE:
		return ID_STATUS_ONLINE;
	default:
		/* None of those? We'll have to guess. Online seems ok. */
		return ID_STATUS_ONLINE;
	}

	/* Don't have SIPE equivalent of these:
		- ID_STATUS_FREECHAT
	*/

}

guint MirandaStatusToSipe(int status) {

	switch (status)
	{
	case ID_STATUS_OFFLINE:
		return SIPE_ACTIVITY_OFFLINE;

	case ID_STATUS_ONLINE:
	case ID_STATUS_FREECHAT:
		return SIPE_ACTIVITY_AVAILABLE;

	case ID_STATUS_ONTHEPHONE:
		return SIPE_ACTIVITY_ON_PHONE;

	case ID_STATUS_DND:
		return SIPE_ACTIVITY_DND;

	case ID_STATUS_NA:
		return SIPE_ACTIVITY_AWAY;

	case ID_STATUS_AWAY:
		return SIPE_ACTIVITY_BRB;

	case ID_STATUS_OUTTOLUNCH:
		return SIPE_ACTIVITY_LUNCH;

	case ID_STATUS_OCCUPIED:
		return SIPE_ACTIVITY_BUSY;

	case ID_STATUS_INVISIBLE:
		return SIPE_ACTIVITY_INVISIBLE;

	default:
		return SIPE_ACTIVITY_UNSET;
	}

}

gchar *sipe_miranda_uri_self(SIPPROTO *pr) {
	gchar *username = sipe_miranda_getString(pr, "username");
	gchar *uri = g_strdup_printf("sip:%s", username);
	mir_free(username);
	return uri;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
