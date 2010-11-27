#define MIRANDA_VER 0x900

#include <windows.h>
#include <win2k.h>
#include <Richedit.h>
#include <process.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"
#include "m_database.h"
#include "m_langpack.h"
#include "m_options.h"
#include "m_clist.h"
#include "m_chat.h"
#include "m_netlib.h"
#include "m_protomod.h"

#include "libsipe.h"
#include "sipe-core.h"
#include "sipe.h"
#include "sipe-core-private.h"
#include "sipe-backend.h"
#include "sipe-utils.h"
#include "sipe-conf.h"
#include "sipe-chat.h"
#include "sipe-session.h"
#include "miranda-private.h"
#include "miranda-resource.h"

#define _NI(string) _debuglog( __FILE__, __FUNCTION__, "(%d) ##NOT IMPLEMENTED## %s\n", __LINE__, #string )

/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     "unset"                  /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     "offline"                /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   "available"              /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_BUSYIDLE    "busyidle"                                                 /* BusyIdle */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_IN_MEETING  "in-a-meeting"                                             /* In a meeting */
#define SIPE_STATUS_ID_IN_CONF     "in-a-conference"                                          /* In a conference */
#define SIPE_STATUS_ID_ON_PHONE    "on-the-phone"                                             /* On the phone */
#define SIPE_STATUS_ID_INVISIBLE   "invisible"              /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        "away"                   /* Away (primitive) */
/** Reuters status (user settable) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */

/* Plugin information structure */
PLUGININFOEX pluginInfo = {
	sizeof(PLUGININFOEX),
	"SIP/Simple Protocol",
	PLUGIN_MAKE_VERSION(9,12,19,12),
	"Support for SIP/Simple as used by Communicator 2007.",
	"Miranda support by Jochen De Smet, for core sipe support see homepage",
	"jochen.libsipe@leahnim.org",
	"(C)2009-2010",
	"https://sourceforge.net/projects/sipe",
	UNICODE_AWARE,
	0,   //doesn't replace anything built-in
    #if defined( _UNICODE )
	{ 0x842395ed, 0x4e56, 0x40e5, { 0x94, 0x25, 0x28, 0x29, 0xd8, 0xab, 0xae, 0xa5 } } // {842395ED-4E56-40e5-9425-2829D8ABAEA5}
    #else
	{ 0x1ef8af37, 0xdec1, 0x4757, { 0x89, 0x78, 0xe8, 0xad, 0xd0, 0xd8, 0x6e, 0x7f } } // {1EF8AF37-DEC1-4757-8978-E8ADD0D86E7F}
    #endif
};

/* Miranda interface globals */
#define ENTRY_SIG 0x88442211

HINSTANCE hInst;
PLUGINLINK* pluginLink;
struct MM_INTERFACE mmi;
static NETLIBSELECTEX m_select = {0};
static GHashTable *m_readhash = NULL;
static GHashTable *m_writehash = NULL;
static GList *m_entries = NULL;
static HANDLE wake_up_semaphore = NULL;

static BOOL (WINAPI *pfnEnableThemeDialogTexture)(HANDLE, DWORD) = 0;

/* Misc functions */
TCHAR _tcharbuf[32768];
TCHAR* CHAR2TCHAR( const char *chr ) {
#ifdef UNICODE
	mbstowcs( _tcharbuf, chr, strlen(chr)+1 );
	return _tcharbuf;
#else
	return chr;
#endif
}

char _charbuf[32768];
char* TCHAR2CHAR( const TCHAR *tchr ) {
#ifdef UNICODE
	wcstombs( _charbuf, tchr, wcslen(tchr)+1 );
	return _charbuf;
#else
	return tchr;
#endif
}

void CreateProtoService(const SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc)
{
	char str[ MAXMODULELABELLENGTH ];

	mir_snprintf(str, sizeof(str), "%s%s", pr->proto.m_szModuleName, szService);
	CreateServiceFunctionObj(str, (MIRANDASERVICEOBJ)*(void**)&serviceProc, pr);
}

HANDLE HookProtoEvent(const SIPPROTO *pr, const char* szEvent, SipSimpleEventFunc pFunc)
{
	return HookEventObj(szEvent, (MIRANDAHOOKOBJ)*(void**)&pFunc, pr);
}

void ProtocolAckThread(struct miranda_sipe_ack_args* pArguments)
{
	ProtoBroadcastAck(pArguments->pr->proto.m_szModuleName, pArguments->hContact, pArguments->nAckType, pArguments->nAckResult, pArguments->hSequence, pArguments->pszMessage);

	if (pArguments->nAckResult == ACKRESULT_SUCCESS)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent ACK");
	else if (pArguments->nAckResult == ACKRESULT_FAILED)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent NACK");

	g_free((gpointer)pArguments->pszMessage);
	g_free(pArguments);
}

void ForkThread( SIPPROTO *pr, SipSimpleThreadFunc pFunc, void* arg )
{
/*
	CloseHandle(( HANDLE )mir_forkthreadowner(( pThreadFuncOwner )*( void** )&pFunc, pr, arg, NULL ));
*/
}

void SendProtoAck( SIPPROTO *pr, HANDLE hContact, DWORD dwCookie, int nAckResult, int nAckType, char* pszMessage)
{
	struct miranda_sipe_ack_args* pArgs = (struct miranda_sipe_ack_args*)g_malloc(sizeof(struct miranda_sipe_ack_args)); // This will be freed in the new thread
	pArgs->hContact = hContact;
	pArgs->hSequence = (HANDLE)dwCookie;
	pArgs->nAckResult = nAckResult;
	pArgs->nAckType = nAckType;
	pArgs->pszMessage = (LPARAM)g_strdup(pszMessage);
	pArgs->pr = pr;

	ForkThread( pr, ( SipSimpleThreadFunc )&ProtocolAckThread, pArgs );
}

void set_buddies_offline(const SIPPROTO* pr)
{
	HANDLE hContact;

	hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDFIRST, 0, 0);
	while (hContact) {
		char* szProto = (char*)CallService(MS_PROTO_GETCONTACTBASEPROTO, (WPARAM)hContact, 0);
		if (szProto != NULL && !lstrcmpA(szProto, pr->proto.m_szModuleName)) {
			if (DBGetContactSettingByte(hContact, pr->proto.m_szModuleName, "ChatRoom", 0) == 0)
				DBWriteContactSettingWord(hContact, pr->proto.m_szModuleName, "Status", ID_STATUS_OFFLINE);
		}
		hContact = (HANDLE)CallService(MS_DB_CONTACT_FINDNEXT, (WPARAM)hContact, 0);
	}
}


const char *MirandaStatusToSipe(int status) {

	switch (status)
	{
	case ID_STATUS_OFFLINE:
		return SIPE_STATUS_ID_OFFLINE;

	case ID_STATUS_ONLINE:
	case ID_STATUS_FREECHAT:
		return SIPE_STATUS_ID_AVAILABLE;

	case ID_STATUS_ONTHEPHONE:
		return SIPE_STATUS_ID_ON_PHONE;

	case ID_STATUS_DND:
		return SIPE_STATUS_ID_DND;

	case ID_STATUS_NA:
		return SIPE_STATUS_ID_AWAY;

	case ID_STATUS_AWAY:
		return SIPE_STATUS_ID_BRB;

	case ID_STATUS_OUTTOLUNCH:
		return SIPE_STATUS_ID_LUNCH;

	case ID_STATUS_OCCUPIED:
		return SIPE_STATUS_ID_BUSY;

	case ID_STATUS_INVISIBLE:
		return SIPE_STATUS_ID_INVISIBLE;

	default:
		return SIPE_STATUS_ID_UNKNOWN;
	}

}

int SendBroadcast(SIPPROTO *pr, HANDLE hContact,int type,int result,HANDLE hProcess,LPARAM lParam)
{
	ACKDATA ack={0};

	ack.cbSize = sizeof(ACKDATA);
	ack.szModule = pr->proto.m_szModuleName;
	ack.hContact = hContact;
	ack.type = type;
	ack.result = result;
	ack.hProcess = hProcess;
	ack.lParam = lParam;
	return CallService(MS_PROTO_BROADCASTACK,0,(LPARAM)&ack);
}


/* Protocol interface support functions */
void
_debuglog(const char *filename, const char *funcname, const char *fmt,...)
{
	va_list va;
	char szText[32768];
	const char *tmp;
	FILE *fh;

	for ( tmp=filename ; *tmp ; tmp++ )
	{
		if ((*tmp == '/') || (*tmp == '\\')) filename=tmp+1;
	}

	va_start(va,fmt);
	vsnprintf(szText,sizeof(szText),fmt,va);
	va_end(va);

	if (!fopen_s(&fh,"c:/sipsimple.log","a")) {
		fprintf(fh, "[%d] %22s %s: %s", _getpid(), filename, funcname, szText);
		fclose(fh);
	}
}

typedef struct _time_entry
{
	guint interval;
	GSourceFunc function;
	gpointer data;
	HANDLE sem;
} time_entry;

static INT_PTR StartChat(SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;
	struct sipe_core_public *sipe_public = pr->sip;
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	DBVARIANT dbv;
	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		{
			sipe_conf_add(sipe_private, dbv.pszVal);
		}
		else /* 2005- multiparty chat */
		{
			gchar *self = sip_uri_self(sipe_private);
			struct sip_session *session;

			session = sipe_session_add_chat(sipe_private,
							NULL,
							TRUE,
							self);
			session->chat_session->backend = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
										  session->chat_session,
										  session->chat_session->title,
										  self);
			g_free(self);

			sipe_invite(sipe_private, session, dbv.pszVal, NULL, NULL, NULL, FALSE);
	}
		DBFreeVariant( &dbv );
		return TRUE;
	}

	return FALSE;
}

static void OnModulesLoaded(SIPPROTO *pr)
{
	TCHAR descr[MAX_PATH];
	NETLIBUSER nlu = {0};
	char service_name[200];
	GCREGISTER gcr;
	CLISTMENUITEM mi = {0};

	SIPE_DEBUG_INFO_NOFORMAT("OnEvent::OnModulesLoaded");

	nlu.cbSize = sizeof(nlu);
	nlu.flags = NUF_OUTGOING | NUF_TCHAR;
	nlu.szSettingsModule = pr->proto.m_szModuleName;
	_sntprintf(descr, SIZEOF(descr), TranslateT("%s server connection"), pr->proto.m_tszUserName );
	nlu.ptszDescriptiveName = descr;

	pr->m_hServerNetlibUser = (HANDLE)CallService(MS_NETLIB_REGISTERUSER, 0, (LPARAM)&nlu);

	mi.cbSize = sizeof( mi );
	mi.pszContactOwner = pr->proto.m_szModuleName;
	mi.pszService = service_name;

	mir_snprintf(service_name, sizeof(service_name), "%s%s", pr->proto.m_szModuleName, "/StartChat");
	CreateProtoService(pr, "/StartChat",&StartChat);
	mi.position=-2000005060;
	mi.icolibItem = NULL; //GetIconHandle("block");
	mi.pszName = LPGEN("&Start Chat");
	mi.flags=0; //CMIF_ICONFROMICOLIB|CMIF_HIDDEN;
	CallService(MS_CLIST_ADDCONTACTMENUITEM,0,(LPARAM)&mi);

	gcr.cbSize = sizeof(gcr);
	gcr.dwFlags = 0;
	gcr.pszModule = pr->proto.m_szModuleName;
	gcr.pszModuleDispName = "Sip/Simple";
	gcr.iMaxText = 0;
	gcr.nColors = 0;

	if (CallService(MS_GC_REGISTER, 0, (LPARAM)&gcr))
	{
		SIPE_DEBUG_INFO_NOFORMAT("OnEvent::OnModulesLoaded Failed to register chat");
	}

}

static unsigned __stdcall
inputloop(void* data)
{
	int cnt;
	struct sipe_miranda_sel_entry *entry;
	INT_PTR lstRes;

	m_select.cbSize = sizeof(m_select);
	m_select.dwTimeout = 6000;

	while( m_select.hReadConns[0] || m_select.hWriteConns[0])
	{

		SIPE_DEBUG_INFO_NOFORMAT("About to run select");
		lstRes = CallService(MS_NETLIB_SELECTEX, 0, (LPARAM)&m_select);
		SIPE_DEBUG_INFO_NOFORMAT("Back from select");
		if (lstRes < 0)
		{
			SIPE_DEBUG_INFO_NOFORMAT("Connection failed while waiting.");
			break;
		}
		else if (lstRes == 0)
		{
			SIPE_DEBUG_INFO_NOFORMAT("Receive Timeout.");
			lstRes = SOCKET_ERROR;
		}
		else
		{

			for ( cnt=0 ; m_select.hReadConns[cnt] ; cnt++ )
			{
				if (!m_select.hReadStatus[cnt]) continue;
				SIPE_DEBUG_INFO("FD at position <%d> ready to read.", cnt);
				entry = (struct sipe_miranda_sel_entry*)g_hash_table_lookup(m_readhash, (gconstpointer)m_select.hReadConns[cnt]);
				if (!entry)
				{
					SIPE_DEBUG_INFO_NOFORMAT("ERROR: no read handler found.");
					continue;
				}
				SIPE_DEBUG_INFO_NOFORMAT("About to call read function.");
				entry->func( entry->user_data, (gint)m_select.hReadConns[cnt], SIPE_MIRANDA_INPUT_READ);
				SIPE_DEBUG_INFO_NOFORMAT("read function returned.");
			}

			for ( cnt=0 ; m_select.hWriteConns[cnt] ; cnt++ )
			{
				if (!m_select.hWriteStatus[cnt]) continue;
				SIPE_DEBUG_INFO("FD at position <%d> ready to write.", cnt);
				entry = (struct sipe_miranda_sel_entry*)g_hash_table_lookup(m_writehash, (gconstpointer)m_select.hWriteConns[cnt]);
				if (!entry)
				{
					SIPE_DEBUG_INFO_NOFORMAT("ERROR: no write handler found.");
					continue;
				}
				SIPE_DEBUG_INFO_NOFORMAT("About to call write function.");
				entry->func( entry->user_data, (gint)m_select.hWriteConns[cnt], SIPE_MIRANDA_INPUT_WRITE);
				SIPE_DEBUG_INFO_NOFORMAT("write function returned.");
			}
		}

		/* Free all removed entries */
		while (m_entries) g_list_delete_link(m_entries, g_list_last(m_entries));
	}

	return 0;
}

/* libsipe interface functions */
static char*
miranda_sipe_get_current_status(struct sipe_core_private *sip, const char* name)
{
	SIPPROTO *pr = sip->public.backend_private;
	char *module = pr->proto.m_szModuleName;
	HANDLE hContact;

	if (!name)
		return g_strdup(MirandaStatusToSipe(pr->proto.m_iStatus));

	hContact = sipe_backend_find_buddy(sip, name, NULL);
	return g_strdup(MirandaStatusToSipe(DBGetContactSettingWord( hContact, module, "Status", ID_STATUS_OFFLINE )));
}

struct sipe_miranda_sel_entry*
sipe_miranda_input_add(HANDLE fd, sipe_miranda_input_condition cond, sipe_miranda_input_function func, gpointer user_data)
{
	int rcnt = 0;
	int wcnt = 0;
	struct sipe_miranda_sel_entry *entry;

	if (!m_readhash)
		m_readhash = g_hash_table_new(NULL, NULL);

	if (!m_writehash)
		m_writehash = g_hash_table_new(NULL, NULL);

	if ((cond != SIPE_MIRANDA_INPUT_READ) && (cond != SIPE_MIRANDA_INPUT_WRITE))
	{
		SIPE_DEBUG_INFO("Invalid input condition <%d> cond.", cond);
		return 0;
	}

	entry = g_new0(struct sipe_miranda_sel_entry,1);
	entry->sig = ENTRY_SIG;
	entry->func = func;
	entry->user_data = user_data;
	entry->fd = fd;

	if (cond == SIPE_MIRANDA_INPUT_READ)
	{
		for ( rcnt=0 ; m_select.hReadConns[rcnt] && m_select.hReadConns[rcnt]!=(HANDLE)fd ; rcnt++ );
		m_select.hReadConns[rcnt] = (HANDLE)fd;
		g_hash_table_replace( m_readhash, (gpointer)fd, entry );
	}
	else if (cond == SIPE_MIRANDA_INPUT_WRITE)
	{
		for ( wcnt=0 ; m_select.hWriteConns[wcnt] && m_select.hWriteConns[wcnt]!=(HANDLE)fd ; wcnt++ );
		m_select.hWriteConns[rcnt] = (HANDLE)fd;
		g_hash_table_replace( m_writehash, (gpointer)fd, entry );
	}

	if (!(rcnt+wcnt))
		CloseHandle((HANDLE) mir_forkthreadex( inputloop, NULL, 8192, NULL ));

	SIPE_DEBUG_INFO_NOFORMAT("Added input handler.");
	return entry;
}

gboolean
sipe_miranda_input_remove(struct sipe_miranda_sel_entry *entry)
{
	int cnt;

	if (!entry)
	{
		SIPE_DEBUG_INFO_NOFORMAT("Not a valid entry. NULL.");
		return FALSE;
	}

	if (entry->sig != ENTRY_SIG)
	{
		SIPE_DEBUG_INFO("Not a valid entry. Sig is <%08x>.", entry->sig);
		return FALSE;
	}

	if (g_hash_table_lookup(m_readhash, (gconstpointer)entry->fd) == entry)
	{
		for ( cnt=0 ; m_select.hReadConns[cnt] && m_select.hReadConns[cnt]!=(HANDLE)entry->fd ; cnt++ );
		for ( ; m_select.hReadConns[cnt] ; cnt++ ) m_select.hReadConns[cnt] = m_select.hReadConns[cnt+1];
		g_hash_table_remove(m_readhash, (gconstpointer)entry->fd);
	}

	if (g_hash_table_lookup(m_writehash, (gconstpointer)entry->fd) == entry)
	{
		for ( cnt=0 ; m_select.hWriteConns[cnt] && m_select.hWriteConns[cnt]!=(HANDLE)entry->fd ; cnt++ );
		for ( ; m_select.hWriteConns[cnt] ; cnt++ ) m_select.hWriteConns[cnt] = m_select.hWriteConns[cnt+1];
		g_hash_table_remove(m_writehash, (gconstpointer)entry->fd);
	}

	/* Add it to the list of entries that can be freed after the next select
	 * loop in the thread that's handling the actual select
	 */
	g_list_append( m_entries, entry );

	return TRUE;
}

static void*
miranda_sipe_request_authorization(struct sipe_core_private *sip, const char *who, const char *alias,
		sipe_request_authorization_cb auth_cb, sipe_request_authorization_cb deny_cb, void *data)
{
	SIPPROTO *pr = sip->public.backend_private;
	CCSDATA ccs;
	PROTORECVEVENT pre = {0};
	HANDLE hContact;
	char* szBlob;
	char* pCurBlob;

	hContact = sipe_backend_find_buddy( sip, who, NULL );
	if (!hContact)
	{
		hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
		CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
		DBWriteContactSettingByte( hContact, "CList", "NotOnList", 1 );
		sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, who ); // name
		sipe_miranda_setContactStringUtf( pr, hContact, "Nick", alias );               // server_alias
	}

	ccs.szProtoService = PSR_AUTH;
	ccs.wParam = 0;
	ccs.lParam = (LPARAM)&pre;
	ccs.hContact=hContact = hContact;

	pre.timestamp = time(NULL);
	pre.lParam=sizeof(DWORD)+sizeof(HANDLE)+strlen(who)+1+strlen(alias)+1+1+5;

	/*blob is: uin(DWORD), hcontact(HANDLE), nick(ASCIIZ), first(ASCIIZ), last(ASCIIZ), email(ASCIIZ), reason(ASCIIZ)*/
	pCurBlob=szBlob=(char *)_alloca(pre.lParam);
	memset(pCurBlob, 0, sizeof(DWORD)); pCurBlob+=sizeof(DWORD);
	memcpy(pCurBlob,&hContact,sizeof(HANDLE)); pCurBlob+=sizeof(HANDLE);
	strcpy((char *)pCurBlob,who); pCurBlob+=strlen((char *)pCurBlob)+1;
	*pCurBlob = '\0'; pCurBlob++;
	strcpy((char *)pCurBlob,alias); pCurBlob+=strlen((char *)pCurBlob)+1;
	*pCurBlob = '\0'; pCurBlob++;
	*pCurBlob = '\0'; pCurBlob++;
	pre.szMessage=(char *)szBlob;

	CallService(MS_PROTO_CHAINRECV,0,(LPARAM)&ccs);

	/* TODO: Store callbacks somewhere since miranda has no way to pass them on */
	return NULL;
}

static void
miranda_sipe_connection_cleanup(struct sipe_core_private *sip)
{
	SIPPROTO *pr = sip->public.backend_private;
	_NIF();
}

static void
miranda_sipe_notify_user(SIP_HANDLE sip, const char *name, sipe_message_flags flags, const gchar *message)
{
	_NIF();
}

static void
__debuglog(sipe_debug_level level, const char *fmt,...)
{
	va_list va;
	char szText[32768];
	FILE *fh;
	char *str = DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog");

	va_start(va,fmt);
	vsnprintf(szText,sizeof(szText),fmt,va);
	va_end(va);

	if (!str)
		str = mir_strdup("c:/sipsimple.log");

	if (!fopen_s(&fh, str, "a")) {
		fprintf(fh, "<[%d]> %s", _getpid(), szText);
		fclose(fh);
	}
	mir_free(str);
}


/****************************************************************************
 * Struct that defines our interface with libsipe
 ****************************************************************************/
/* Protocol interface functions */
HANDLE AddToListByEvent( SIPPROTO *pr, int flags, int iContact, HANDLE hDbEvent )
{
	_NIF();
	SIPE_DEBUG_INFO("AddToListByEvent: flags <%x> iContact <%x>", flags, iContact);
	return NULL;
}

int Authorize( SIPPROTO *pr, HANDLE hContact )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("Authorize");
	return 0;
}

int AuthDeny( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szReason )
{
	_NIF();
	SIPE_DEBUG_INFO("AuthDeny: reason <%s>", szReason);
	return 0;
}

int AuthRecv( SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* evt )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("AuthRecv");
	return 0;
}

int AuthRequest( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szMessage )
{
	_NIF();
	SIPE_DEBUG_INFO("AuthRequest: message <%s>", szMessage);
	return 0;
}

HANDLE ChangeInfo( SIPPROTO *pr, int iInfoType, void* pInfoData )
{
	_NIF();
	SIPE_DEBUG_INFO("ChangeInfo: infotype <%x>", iInfoType);
	return NULL;
}

HANDLE FileAllow( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szPath )
{
	_NIF();
	SIPE_DEBUG_INFO("FileAllow: path <%s>", szPath);
	return NULL;
}

int FileCancel( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("FileCancel");
	return 0;
}

int FileDeny( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szReason )
{
	_NIF();
	SIPE_DEBUG_INFO("FileDeny: reason <%s>", szReason);
	return 0;
}

int FileResume( SIPPROTO *pr, HANDLE hTransfer, int* action, const PROTOCHAR** szFilename )
{
	_NIF();
	SIPE_DEBUG_INFO("FileResume: action <%x>", action);
	return 0;
}

static void set_if_defined(SIPPROTO *pr, GHashTable *store, HANDLE hContact, sipe_info_fields field, char *label)
{
	char *value = (char *)g_hash_table_lookup(store, (gpointer)field);
	if (value)
		sipe_miranda_setContactStringUtf(pr, hContact, label, value);
}

static gboolean
miranda_sipe_get_info_cb(struct sipe_core_public *sipe_public, const char* uri, GHashTable *results, void* data )
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact = (HANDLE) data;

	GHashTableIter iter;
	const char *id, *value;

	g_hash_table_iter_init( &iter, results);
	while (g_hash_table_iter_next (&iter, (gpointer *)&id, (gpointer *)&value)) {
		SIPE_DEBUG_INFO("miranda_sipe_get_info_cb: user info field <%d> = <%s>", id, value ? value : "(none)");
	}
	set_if_defined(pr, results, hContact, SIPE_INFO_EMAIL, "e-mail");
	set_if_defined(pr, results, hContact, SIPE_INFO_CITY, "City");
	set_if_defined(pr, results, hContact, SIPE_INFO_STATE, "State");
	set_if_defined(pr, results, hContact, SIPE_INFO_COUNTRY, "Country");
	set_if_defined(pr, results, hContact, SIPE_INFO_COMPANY, "Company");
	set_if_defined(pr, results, hContact, SIPE_INFO_JOB_TITLE, "CompanyPosition");
	set_if_defined(pr, results, hContact, SIPE_INFO_WORK_PHONE, "CompanyPhone");
	set_if_defined(pr, results, hContact, SIPE_INFO_STREET, "CompanyStreet");
	set_if_defined(pr, results, hContact, SIPE_INFO_ZIPCODE, "CompanyZIP");
	set_if_defined(pr, results, hContact, SIPE_INFO_DEPARTMENT, "CompanyDepartment");

	SendBroadcast(pr, hContact, ACKTYPE_GETINFO, ACKRESULT_SUCCESS, (HANDLE) 1, (LPARAM) 0);
	return TRUE;
}

int GetInfo( SIPPROTO *pr, HANDLE hContact, int infoType )
{
	DBVARIANT dbv;

	SIPE_DEBUG_INFO("GetInfo: infotype <%x>", infoType);

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		sipe_get_info(pr->sip, dbv.pszVal, miranda_sipe_get_info_cb, hContact);
		DBFreeVariant( &dbv );
	}

	return 0;
}

void sipsimple_search_contact_cb( GList *columns, GList *results, GHashTable *opts, void *data )
{
	SIPPROTO *pr = (SIPPROTO *)data;
	GList *row, *col;
	HANDLE hProcess = g_hash_table_lookup(opts, "searchid");
	PROTOSEARCHRESULT psr = { 0 };

	psr.cbSize = sizeof(psr);

	row = results;
	while (row)
	{
		col = (GList*)row->data;
		psr.nick = (PROTOCHAR*)col->data;

		col = g_list_next(col);
		psr.lastName = (PROTOCHAR*)col->data;

		col = g_list_next(col);
		/* company */

		col = g_list_next(col);
		/* country */

		col = g_list_next(col);
		psr.email = (PROTOCHAR*)col->data;

		row = g_list_next(row);
		SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_DATA, hProcess, (LPARAM) & psr);
	}

	SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_SUCCESS, hProcess, 0);

}

HANDLE SearchBasic( SIPPROTO *pr, const PROTOCHAR* id )
{
	return NULL;
}

HWND SearchAdvanced( SIPPROTO *pr, HWND owner )
{
	_NIF();
	return NULL;
}

HWND CreateExtendedSearchUI( SIPPROTO *pr, HWND owner )
{
	_NIF();
	return NULL;
}

HANDLE SearchByEmail( SIPPROTO *pr, const PROTOCHAR* email )
{
	GHashTable *query = g_hash_table_new(NULL,NULL);

	SIPE_DEBUG_INFO("SearchByEmail: email <%s>", email);

	g_hash_table_insert(query, "email", (gpointer)email);

	return (HANDLE)sipe_search_contact_with_cb( pr->sip, query, sipsimple_search_contact_cb, pr);

}

HANDLE SearchByName( SIPPROTO *pr, const PROTOCHAR* nick, const PROTOCHAR* firstName, const PROTOCHAR* lastName)
{
	GHashTable *query = g_hash_table_new(NULL,NULL);

	SIPE_DEBUG_INFO("SearchByName: nick <%s> firstname <%s> lastname <%s>", nick, firstName, lastName);

	g_hash_table_insert(query, "givenName", (gpointer)mir_t2a(firstName));
	g_hash_table_insert(query, "sn", (gpointer)mir_t2a(lastName));

	return (HANDLE)sipe_search_contact_with_cb( pr->sip, query, sipsimple_search_contact_cb, pr);
}

HANDLE AddToList( SIPPROTO *pr, int flags, PROTOSEARCHRESULT* psr )
{
	HANDLE hContact;
	gchar *nick = g_strdup(mir_t2a(psr->nick));

	/* Prepend sip: if needed */
	if (strncmp("sip:", nick, 4)) {
		gchar *tmp = nick;
		nick = sip_uri_from_name(tmp);
		g_free(tmp);
	}

	hContact = sipe_backend_find_buddy(pr->sip, nick, NULL);
	if (hContact) {
		g_free(nick);
		return hContact;
	}

	hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
	CallService( MS_PROTO_ADDTOCONTACT, (WPARAM)hContact, (LPARAM)pr->proto.m_szModuleName );
	sipe_miranda_setString( hContact, SIP_UNIQUEID, nick ); // name
	if (psr->lastName) sipe_miranda_setStringUtf( hContact, "Nick", mir_t2a(psr->lastName) );               // server_alias

	g_free(nick);
	return hContact;
}

int RecvMsg(SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* pre)
{
//	// stop contact from typing - some clients do not sent stop notify
//	if (CheckContactCapabilities(hContact, CAPF_TYPING))
//		CallService(MS_PROTO_CONTACTISTYPING, (WPARAM)hContact, PROTOTYPE_CONTACTTYPING_OFF);
//	char *msg = EliminateHtml( pre->szMessage, strlen(pre->szMessage));
//	mir_free(pre->szMessage);
//	pre->szMessage = msg;

	CCSDATA ccs = { hContact, PSR_MESSAGE, 0, ( LPARAM )pre };
	return CallService( MS_PROTO_RECVMSG, 0, ( LPARAM )&ccs );
}

int SendMsg( SIPPROTO *pr, HANDLE hContact, int flags, const char* msg )
{
	DBVARIANT dbv;

	SIPE_DEBUG_INFO("SendMsg: flags <%x> msg <%s>", flags, msg);

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
//		SendProtoAck( pr, hContact, 1, ACKRESULT_SENTREQUEST, ACKTYPE_MESSAGE, NULL );
		sipe_im_send(pr->sip, dbv.pszVal, msg, SIPE_MESSAGE_SEND);
		SendProtoAck( pr, hContact, 1, ACKRESULT_SUCCESS, ACKTYPE_MESSAGE, NULL );
		DBFreeVariant(&dbv);
	} else {
		SendProtoAck( pr, hContact, 1, ACKRESULT_FAILED, ACKTYPE_MESSAGE, NULL );
	}
	return 1;
}

int UserIsTyping( SIPPROTO *pr, HANDLE hContact, int type )
{
	SIPE_DEBUG_INFO("UserIsTyping: type <%x>", type);
	if (hContact)
	{
		DBVARIANT dbv;
		char *name;

		if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
			name = g_strdup(dbv.pszVal);
			DBFreeVariant(&dbv);
		} else {
			return 1;
		}

		switch (type) {
			case PROTOTYPE_SELFTYPING_ON:
				sipe_core_user_feedback_typing(pr->sip, name);
				g_free(name);
				return 0;

			case PROTOTYPE_SELFTYPING_OFF:
				/* Not supported anymore? */
				g_free(name);
				return 0;
		}

		g_free(name);
	}

	return 1;
}

static void sipe_miranda_login(SIPPROTO *pr) {
	gchar *username = sipe_miranda_getString(pr, "username");
	gchar *login = sipe_miranda_getString(pr, "login");
	gchar *email = sipe_miranda_getString(pr, "email");
	gchar *email_url = sipe_miranda_getString(pr, "email_url");
	gchar **domain_user = g_strsplit_set(login, "/\\", 2);
	const gchar *errmsg;
	gchar *password;
	char *tmp = (char*)mir_calloc(1024);

	if (sipe_miranda_getStaticString(pr, NULL, "password", tmp, 1024 )) tmp[0] = '\0';
	CallService(MS_DB_CRYPT_DECODESTRING, sizeof(tmp),(LPARAM)tmp);
	password = g_strdup(tmp);
	mir_free(tmp);

	pr->sip = sipe_core_allocate(username,
					    domain_user[0], domain_user[1],
					    password,
					    email,
					    email_url,
					    &errmsg);

	pr->sip->backend_private = pr;

	mir_free(username);
	mir_free(login);
	mir_free(email);
	mir_free(email_url);
	g_strfreev(domain_user);
	g_free(password);

	if (!pr->sip) {
		/* FIXME: Flag connection error */
		return;
	}

	//sipe_miranda_chat_setup_rejoin(pr);

#ifdef HAVE_LIBKRB5
//	if (purple_account_get_bool(account, "krb5", FALSE))
//		SIPE_CORE_FLAG_SET(KRB5);
#endif
//	/* @TODO: is this correct?
//	   "sso" is only available when Kerberos support is compiled in */
//	if (purple_account_get_bool(account, "sso", TRUE))
//		SIPE_CORE_FLAG_SET(SSO);

	/* Set display name */
	sipe_miranda_setStringUtf(pr, "Nick", pr->sip->sip_name);

	/* Update connection progress */
	pr->proto.m_iStatus = ID_STATUS_CONNECTING;
	SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)pr->proto.m_iStatus, ID_STATUS_CONNECTING);

/*
	username_split = g_strsplit(purple_account_get_string(account, "server", ""), ":", 2);
	if (sipe_strequal(transport, "auto")) {
		type = (username_split[0] == NULL) ?
			SIPE_TRANSPORT_AUTO : SIPE_TRANSPORT_TLS;
	} else if (sipe_strequal(transport, "tls")) {
		type = SIPE_TRANSPORT_TLS;
	} else {
		type = SIPE_TRANSPORT_TCP;
	}

	sipe_core_transport_sip_connect(pr->sip,
					type,
					username_split[0],
					username_split[0] ? username_split[1] : NULL);
	g_strfreev(username_split);
*/
	sipe_core_transport_sip_connect(pr->sip,
					SIPE_TRANSPORT_AUTO,
					NULL,
					NULL);
}

static void sipe_miranda_close( SIPPROTO *pr)
{
	struct sipe_core_public *sipe_public = pr->sip;

	if (sipe_public) {
		sipe_core_deallocate(sipe_public);

//		sipe_purple_chat_destroy_rejoin(purple_private);
//		g_free(purple_private);
	}
}

static int SetStatus( SIPPROTO *pr, int iNewStatus )
{
	int oldStatus;
	if (!pr->m_hServerNetlibUser) return 0;
	if (pr->proto.m_iDesiredStatus == iNewStatus) return 0;

	oldStatus = pr->proto.m_iStatus;
	pr->proto.m_iDesiredStatus = iNewStatus;

	SIPE_DEBUG_INFO("SetStatus: newstatus <%x>", iNewStatus);

	if (iNewStatus == ID_STATUS_OFFLINE) {
		sipe_miranda_close(pr);
		set_buddies_offline(pr);
		pr->proto.m_iStatus = iNewStatus;
		SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, iNewStatus);
	} else {
		if (pr->proto.m_iStatus == ID_STATUS_OFFLINE) {
			sipe_miranda_login(pr);
			pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
			sipe_set_status(pr->sip, MirandaStatusToSipe(iNewStatus));
			SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
		} else {
			pr->proto.m_iStatus = iNewStatus;
			sipe_set_status(pr->sip, MirandaStatusToSipe(iNewStatus));
			SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)pr->proto.m_iStatus, iNewStatus);
		}
	}


/*
//Will send an ack with:
//type=ACKTYPE_STATUS, result=ACKRESULT_SUCCESS, hProcess=(HANDLE)previousMode, lParam=newMode
//when the change completes. This ack is sent for all changes, not just ones
//caused by calling this function.
//Note that newMode can be ID_STATUS_CONNECTING<=newMode<ID_STATUS_CONNECTING+
//MAX_CONNECT_RETRIES to signify that it's connecting and it's the nth retry.
//Protocols are initially always in offline mode.
//Non-network-level protocol modules do not have the concept of a status and
//should leave this service unimplemented
//If a protocol doesn't support the specific status mode, it should pick the
*/

	return 0;
}

static DWORD_PTR GetCaps( SIPPROTO *pr, int type, HANDLE hContact )
{
	switch (type) {
		case PFLAGNUM_1:
			return PF1_IM | PF1_CHAT | PF1_USERIDISEMAIL | PF1_SEARCHBYNAME
				| PF1_AUTHREQ | PF1_SERVERCLIST | PF1_ADDSEARCHRES;

		case PFLAGNUM_2:
			return PF2_ONLINE | PF2_INVISIBLE | PF2_SHORTAWAY | PF2_LONGAWAY | PF2_LIGHTDND | PF2_HEAVYDND
				| PF2_OUTTOLUNCH | PF2_ONTHEPHONE;

		case PFLAGNUM_3:
			return 0;

		case PFLAGNUM_4:
			return PF4_NOCUSTOMAUTH | PF4_IMSENDUTF | PF4_SUPPORTTYPING;

		case PFLAGNUM_5:
			return 0;

		case PFLAG_UNIQUEIDSETTING:
			return (DWORD_PTR) SIP_UNIQUEID;
			break;
		default:
			SIPE_DEBUG_INFO("GetCaps: unknown type <%x>", type);

	}

	return 0;
}

static HICON GetIcon( SIPPROTO *pr, int iconIndex )
{
	SIPE_DEBUG_INFO("GetIcon: unknown index <%x>", iconIndex);
	return NULL;
}

int RecvContacts( SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* evt )
{
	_NIF();
	return 0;
}

int RecvFile( SIPPROTO *pr, HANDLE hContact, PROTOFILEEVENT* evt )
{
	_NIF();
	return 0;
}

int RecvUrl( SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* evt )
{
	_NIF();
	return 0;
}

int SendContacts( SIPPROTO *pr, HANDLE hContact, int flags, int nContacts, HANDLE* hContactsList )
{
	_NIF();
	SIPE_DEBUG_INFO("SendContacts: flags <%x> ncontacts <%x>", flags, nContacts);
	return 0;
}

HANDLE SendFile( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szDescription, PROTOCHAR** ppszFiles )
{
	_NIF();
	SIPE_DEBUG_INFO("SendFile: desc <%s>", szDescription);
	return 0;
}

int SendUrl( SIPPROTO *pr, HANDLE hContact, int flags, const char* url )
{
	_NIF();
	SIPE_DEBUG_INFO("SendUrl: iflags <%x> url <%s>", flags, url);
	return 0;
}

int SetApparentMode( SIPPROTO *pr, HANDLE hContact, int mode )
{
	_NIF();
	SIPE_DEBUG_INFO("SetApparentMode: mode <%x>", mode);
	return 0;
}

HANDLE GetAwayMsg( SIPPROTO *pr, HANDLE hContact )
{
	_NIF();
	SIPE_DEBUG_INFO_NOFORMAT("GetAwayMsg");
	return NULL;
}

int RecvAwayMsg( SIPPROTO *pr, HANDLE hContact, int mode, PROTORECVEVENT* evt )
{
	_NIF();
	SIPE_DEBUG_INFO("RecvAwayMsg: mode <%x>", mode);
	return 0;
}

int SendAwayMsg( SIPPROTO *pr, HANDLE hContact, HANDLE hProcess, const char* msg )
{
	_NIF();
	SIPE_DEBUG_INFO("SendAwayMsg: msg <%s>", msg);
	return 0;
}

int SetAwayMsg( SIPPROTO *pr, int m_iStatus, const PROTOCHAR* msg )
{
	_NIF();
	SIPE_DEBUG_INFO("SetAwayMsg: status <%x> msg <%s>", m_iStatus, msg);
	return 0;
}

INT_PTR CALLBACK DlgProcSipSimpleOpts(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static int lock=0;

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			const SIPPROTO *pr = (const SIPPROTO *)lParam;
			char *str;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			lock++;

			str = DBGetString( NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog");
			SetDlgItemTextA(hwndDlg, IDC_DEBUGLOG, str);
			SendDlgItemMessage(hwndDlg, IDC_DEBUGLOG, EM_SETLIMITTEXT, 100, 0);
			mir_free(str);

			str = sipe_miranda_getString(pr, "username");
			SetDlgItemTextA(hwndDlg, IDC_HANDLE, str);
			SendDlgItemMessage(hwndDlg, IDC_HANDLE, EM_SETLIMITTEXT, 50, 0);
			mir_free(str);

			str = sipe_miranda_getString(pr, "login");
			SetDlgItemTextA(hwndDlg, IDC_LOGIN, str);
			SendDlgItemMessage(hwndDlg, IDC_LOGIN, EM_SETLIMITTEXT, 50, 0);
			mir_free(str);

			str = sipe_miranda_getString(pr, "password");
			if (str) CallService(MS_DB_CRYPT_DECODESTRING, strlen(str),(LPARAM)str);
			SetDlgItemTextA(hwndDlg, IDC_PASSWORD, str);
			SendDlgItemMessage(hwndDlg, IDC_PASSWORD, EM_SETLIMITTEXT, 16, 0);
			mir_free(str);

			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("Auto"));
			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("SSL/TLS"));
			SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_ADDSTRING, 0, (LPARAM)_T("TCP"));

			str = sipe_miranda_getString(pr, "transport");
			if (!str || !strcmp(str, "auto"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("Auto"));
			else if (!strcmp(str, "tls"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("SSL/TLS"));
			else if (!strcmp(str, "tcp"))
				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, CB_SELECTSTRING, -1, (LPARAM)_T("TCP"));

			lock--;
			return TRUE;
		}

		case WM_COMMAND:
		{
			int code = wParam >> 16;
			int id = wParam & 0xffff;

			if (!lock && (code == EN_CHANGE || code == CBN_SELCHANGE)) {
				SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
			}
			return TRUE;
		}

		case WM_NOTIFY:
		{
			if (((LPNMHDR)lParam)->code == (UINT)PSN_APPLY)
			{
				char buf[100];
				TCHAR tbuf[100];

				const SIPPROTO *pr = (const SIPPROTO *)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);

				GetDlgItemTextA(hwndDlg, IDC_DEBUGLOG, buf, sizeof(buf));
				DBWriteContactSettingString(NULL, SIPSIMPLE_PROTOCOL_NAME, "debuglog", buf);

				GetDlgItemTextA(hwndDlg, IDC_HANDLE, buf, sizeof(buf));
				sipe_miranda_setString(pr, "username", buf);

				GetDlgItemTextA(hwndDlg, IDC_LOGIN, buf, sizeof(buf));
				sipe_miranda_setString(pr, "login", buf);

				GetDlgItemTextA(hwndDlg, IDC_PASSWORD, buf, sizeof(buf));
				CallService(MS_DB_CRYPT_ENCODESTRING, sizeof(buf),(LPARAM)buf);
				sipe_miranda_setString(pr, "password", buf);

				SendDlgItemMessage(hwndDlg, IDC_CONNTYPE, WM_GETTEXT, 100, (LPARAM)tbuf );

				if (!_tcscmp(tbuf, _T("Auto")))
					sipe_miranda_setString(pr, "transport", "auto");
				else if (!_tcscmp(tbuf, _T("SSL/TLS")))
					sipe_miranda_setString(pr, "transport", "tls");
				else if (!_tcscmp(tbuf, _T("TCP")))
					sipe_miranda_setString(pr, "transport", "tcp");

				return TRUE;
			}
			return TRUE;
		}

	}

	return FALSE;
}

static const char *about_txt =
"{\\rtf1\\ansi\\ansicpg1252\\deff0\\deflang1033{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}{\\f1\\fnil\fcharset2 Symbol;}}"
"{\\*\\generator Msftedit 5.41.15.1507;}\\viewkind4\\uc1\\pard\\b\\f0\\fs24 Sipe" SIPE_VERSION "\\fs20\\par"
"\\b0\\par "
"A third-party plugin implementing extended version of SIP/SIMPLE used by various products:\\par"
"\\pard{\\pntext\\f1\\'B7\\tab}{\\*\\pn\\pnlvlblt\\pnf1\\pnindent0{\\pntxtb\'B7}}\\fi-720"
"\\li720 MS Office Communications Server 2007 (R2)\\par"
"{\\pntext\\f1\\'B7\\tab}MS Live Communications Server 2005/2003\\par"
"{\\pntext\\f1\\'B7\\tab}Reuters Messaging\\par"
"\\pard\\par "
"Home: http://sipe.sourceforge.net\\par "
"Support: http://sourceforge.net/projects/sipe/forums/forum/68853\\par "
"License: GPLv2\\par "
"\\par"
"\\b Authors:\\b0\\par"
" - Anibal Avelar\\par"
" - Gabriel Burt\\par"
" - Stefan Becker\\par"
" - pier11\\par"
"}";

INT_PTR CALLBACK DlgProcSipSimpleOptsAbout(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			const SIPPROTO *pr = (const SIPPROTO *)lParam;
			SETTEXTEX tex;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);

			tex.flags = ST_DEFAULT;
			tex.codepage = 437;

			SendDlgItemMessage(hwndDlg, IDC_ABOUTSIPE, EM_SETTEXTEX, (WPARAM)&tex, (LPARAM)about_txt );

		}
	}

	return FALSE;
}

int OnOptionsInit(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	OPTIONSDIALOGPAGE odp = {0};
	HMODULE hUxTheme = 0;

	if (IsWinVerXPPlus())
	{
		hUxTheme = GetModuleHandleA("uxtheme.dll");
		if (hUxTheme)
			pfnEnableThemeDialogTexture = (BOOL (WINAPI *)(HANDLE, DWORD))GetProcAddress(hUxTheme, "EnableThemeDialogTexture");
	}

	odp.cbSize = sizeof(odp);
	odp.position = -800000000;
	odp.hInstance = hInst;
	odp.ptszGroup = LPGENT("Network");
	odp.dwInitParam = (LPARAM)pr;
	odp.ptszTitle = pr->proto.m_tszUserName;
	odp.flags = ODPF_BOLDGROUPS | ODPF_TCHAR;

	odp.ptszTab = LPGENT("Account");
	odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_SIPSIMPLE);
	odp.pfnDlgProc = DlgProcSipSimpleOpts;
	CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

	odp.ptszTab = LPGENT("About");
	odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_SIPSIMPLE_ABOUT);
	odp.pfnDlgProc = DlgProcSipSimpleOptsAbout;
	CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

#if 0

        odp.ptszTab = LPGENT("Features");
        odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_ICQFEATURES);
        odp.pfnDlgProc = DlgProcIcqFeaturesOpts;
        CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

        odp.ptszTab = LPGENT("Privacy");
        odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_ICQPRIVACY);
        odp.pfnDlgProc = DlgProcIcqPrivacyOpts;
        CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );

        if (bPopUpService)
        {
                odp.position = 100000000;
                odp.pszTemplate = MAKEINTRESOURCEA(IDD_OPT_POPUPS);
                odp.groupPosition = 900000000;
                odp.pfnDlgProc = DlgProcIcqPopupOpts;
                odp.ptszGroup = LPGENT("Popups");
                odp.ptszTab = NULL;
                CallService( MS_OPT_ADDPAGE, wParam, ( LPARAM )&odp );
        }
#endif
        return 0;
}

static int OnEvent( SIPPROTO *pr, PROTOEVENTTYPE eventType, WPARAM wParam, LPARAM lParam )
{
	SIPE_DEBUG_INFO("OnEvent: type <%x>", eventType);

	switch (eventType)
	{
		case EV_PROTO_ONLOAD:
			OnModulesLoaded(pr);
			break;

		case EV_PROTO_ONREADYTOEXIT:
			break;

		case EV_PROTO_ONEXIT:
			break;

		case EV_PROTO_ONRENAME:
			break;

		case EV_PROTO_ONOPTIONS:
			return OnOptionsInit( pr, wParam, lParam );
			break;

		case EV_PROTO_ONERASE:
			break;

	}

	return 0;
}


/* Dialogs */
INT_PTR CALLBACK DlgProcAccMgrUI(HWND hwndDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch(msg)
	{
		case WM_INITDIALOG:
		{
			const SIPPROTO *pr = (const SIPPROTO *)lParam;
			char *str;

			TranslateDialogDefault(hwndDlg);

			SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);


			str = sipe_miranda_getString(pr, "username");
			SetDlgItemTextA(hwndDlg, IDC_HANDLE, str);
			mir_free(str);

			str = sipe_miranda_getString(pr, "login");
			SetDlgItemTextA(hwndDlg, IDC_LOGIN, str);
			mir_free(str);

			str = sipe_miranda_getString(pr, "password");
			if (str) CallService(MS_DB_CRYPT_DECODESTRING, strlen(str),(LPARAM)str);
			SetDlgItemTextA(hwndDlg, IDC_PASSWORD, str);
			mir_free(str);

			SendDlgItemMessage(hwndDlg, IDC_HANDLE, EM_SETLIMITTEXT, 50, 0);
			SendDlgItemMessage(hwndDlg, IDC_LOGIN, EM_SETLIMITTEXT, 50, 0);
			SendDlgItemMessage(hwndDlg, IDC_PASSWORD, EM_SETLIMITTEXT, 16, 0);

			return TRUE;
		}

		case WM_COMMAND:
			if (HIWORD(wParam) == EN_CHANGE && (HWND)lParam == GetFocus())
			{
				switch(LOWORD(wParam))
				{
					case IDC_HANDLE:
					case IDC_LOGIN:
					case IDC_PASSWORD:
						SendMessage(GetParent(hwndDlg), PSM_CHANGED, 0, 0);
				}
			}
			break;

		case WM_NOTIFY:
			if (((LPNMHDR)lParam)->code == (UINT)PSN_APPLY)
			{
				char buf[100];

				const SIPPROTO *pr = (const SIPPROTO *)lParam;

				GetDlgItemTextA(hwndDlg, IDC_HANDLE, buf, sizeof(buf));
				sipe_miranda_setString(pr, "username", buf);

				GetDlgItemTextA(hwndDlg, IDC_LOGIN, buf, sizeof(buf));
				sipe_miranda_setString(pr, "login", buf);

				GetDlgItemTextA(hwndDlg, IDC_PASSWORD, buf, sizeof(buf));
				CallService(MS_DB_CRYPT_ENCODESTRING, sizeof(buf),(LPARAM)buf);
				sipe_miranda_setString(pr, "password", buf);

				return TRUE;
			}
			break;
	}

	return FALSE;
}

/* Event handlers */
int OnPreBuildContactMenu(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	HANDLE hContact = (HANDLE)wParam;

	return 0;
}

int OnChatEvent(const SIPPROTO *pr, WPARAM w, LPARAM l )
{
	GCHOOK *hook = (GCHOOK*)l;
	GCDEST *dst = hook->pDest;

	if (dst->iType == GC_USER_MESSAGE) {
		GCDEST gcd = {0};
		GCEVENT gce = {0};
		struct sipe_chat_session *session;

		gcd.pszModule = pr->proto.m_szModuleName;
		gcd.pszID = dst->pszID;
		gcd.iType = GC_EVENT_GETITEMDATA;

		gce.cbSize = sizeof(gce);
		gce.pDest = &gcd;


		if ((session = CallService( MS_GC_EVENT, 0, (LPARAM)&gce )) == NULL)
		{
			SIPE_DEBUG_WARNING_NOFORMAT("Failed to get chat session");
			return 0;
		}

		sipe_core_chat_send(pr->sip, session, hook->pszText);
		return TRUE;
	} else if (dst->iType == GC_USER_PRIVMESS) {
	}

	return FALSE;
}

int OnGroupChange( const SIPPROTO *pr, WPARAM w, LPARAM l )
{
	CLISTGROUPCHANGE *gi = (CLISTGROUPCHANGE*)l;
	HANDLE hContact = (HANDLE)w;
	DBVARIANT dbv;
	char *who;

	/* No contact => it's a group add/rename/remove */
	if (!hContact)
	{
		/* No old name => add */
		if (!gi->pszOldName)
		{
			return 0;
		}
		/* No new name => delete */
		else if (!gi->pszNewName)
		{
			SIPE_DEBUG_INFO("Removing group <l%s>", gi->pszOldName);
			sipe_remove_group(pr->sip, TCHAR2CHAR(gi->pszOldName));
			return 0;
		}

		SIPE_DEBUG_INFO("Renaming group <%ls> to <%ls>", gi->pszOldName, gi->pszNewName);
		sipe_rename_group(pr->sip, TCHAR2CHAR(gi->pszOldName), TCHAR2CHAR(gi->pszNewName));
		return 0;
	}

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		who = g_strdup(dbv.pszVal);
		DBFreeVariant( &dbv );

		if ( !DBGetContactSettingString( hContact, "Clist", "Group", &dbv )) {
			SIPE_DEBUG_INFO("Moving buddy <%s> from group <%ls> to group <%ls>", who, dbv.pszVal, gi->pszNewName);
			sipe_group_buddy(pr->sip, who, dbv.pszVal, TCHAR2CHAR(gi->pszNewName));
			DBFreeVariant( &dbv );
		} else {
			SIPE_DEBUG_INFO("Really adding buddy <%s> to list in group <%ls>", who, gi->pszNewName);
			sipe_add_buddy(pr->sip, who, TCHAR2CHAR(gi->pszNewName));
		}

		g_free(who);
	}

	return TRUE;
}

INT_PTR  SvcCreateAccMgrUI(const SIPPROTO *pr, WPARAM wParam, LPARAM lParam)
{
	return (INT_PTR)CreateDialogParam(hInst, MAKEINTRESOURCE(IDD_ACCMGRUI), (HWND)lParam, DlgProcAccMgrUI, (LPARAM)pr);
}

/* Main Miranda interface */
__declspec(dllexport) PLUGININFOEX *MirandaPluginInfoEx(DWORD mirandaVersion)
{
	// Only load for 0.8.0.29 or greater
	// We need the core stubs for PS_GETNAME and PS_GETSTATUS
	if (mirandaVersion < PLUGIN_MAKE_VERSION(0, 9, 0, 0))
	{
		MessageBoxA(
			NULL,
			"SIP/Simple plugin cannot be loaded. It requires Miranda IM 0.9.0.0 or later.",
			"SIP/Simple Plugin",
			MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST
		);
		return NULL;
	}

	return &pluginInfo;
}

static const MUUID interfaces[] = {MIID_PROTOCOL, MIID_LAST};
__declspec(dllexport) const MUUID* MirandaPluginInterfaces(void)
{
	return interfaces;
}

static PROTO_INTERFACE* sipsimpleProtoInit( const char* pszProtoName, const TCHAR* tszUserName )
{
	SIPPROTO *pr = (SIPPROTO *)mir_calloc(sizeof(SIPPROTO));
	pr->proto.vtbl = (PROTO_INTERFACE_VTBL*)mir_calloc(sizeof(PROTO_INTERFACE_VTBL));

	SIPE_DEBUG_INFO("protoname <%s> username <%ls>", pszProtoName, tszUserName);

	pr->proto.m_iVersion = 2;
	pr->proto.m_szModuleName = mir_strdup(pszProtoName);
	pr->proto.m_tszUserName = mir_tstrdup(tszUserName);
	pr->proto.m_szProtoName = mir_strdup(pszProtoName);

	set_buddies_offline(pr);

	/* Fill the function table */
	pr->proto.vtbl->GetCaps                = GetCaps;
	pr->proto.vtbl->GetIcon                = GetIcon;
	pr->proto.vtbl->OnEvent                = OnEvent;
	pr->proto.vtbl->SetStatus              = SetStatus;
	pr->proto.vtbl->UserIsTyping           = UserIsTyping;
	pr->proto.vtbl->SendMsg                = SendMsg;
	pr->proto.vtbl->RecvMsg                = RecvMsg;
	pr->proto.vtbl->AddToListByEvent       = AddToListByEvent;
	pr->proto.vtbl->Authorize              = Authorize;
	pr->proto.vtbl->AuthDeny               = AuthDeny;
	pr->proto.vtbl->AuthRecv               = AuthRecv;
	pr->proto.vtbl->AuthRequest            = AuthRequest;
	pr->proto.vtbl->ChangeInfo             = ChangeInfo;
	pr->proto.vtbl->FileAllow              = FileAllow;
	pr->proto.vtbl->FileCancel             = FileCancel;
	pr->proto.vtbl->FileDeny               = FileDeny;
	pr->proto.vtbl->FileResume             = FileResume;
	pr->proto.vtbl->GetInfo                = GetInfo;
	pr->proto.vtbl->SearchBasic            = SearchBasic;
	pr->proto.vtbl->SearchAdvanced         = SearchAdvanced;
	pr->proto.vtbl->CreateExtendedSearchUI = CreateExtendedSearchUI;
	pr->proto.vtbl->SearchByEmail          = SearchByEmail;
	pr->proto.vtbl->SearchByName           = SearchByName;
	pr->proto.vtbl->AddToList              = AddToList;

	/* Setup services */
	CreateProtoService(pr, PS_CREATEACCMGRUI, &SvcCreateAccMgrUI );

	HookProtoEvent(pr, ME_OPT_INITIALISE, &OnOptionsInit);
	HookProtoEvent(pr, ME_CLIST_GROUPCHANGE, &OnGroupChange );
	HookProtoEvent(pr, ME_GC_EVENT, &OnChatEvent );
	HookProtoEvent(pr, ME_CLIST_PREBUILDCONTACTMENU, &OnPreBuildContactMenu );

	return (PROTO_INTERFACE*)pr;
}

static int sipsimpleProtoUninit( PROTO_INTERFACE* _pr )
{
	SIPPROTO *pr = (SIPPROTO *)_pr;

	mir_free(pr->proto.m_szModuleName);
	mir_free(pr->proto.m_tszUserName);
	mir_free(pr->proto.vtbl);
	mir_free(pr);

	return 0;
}

__declspec(dllexport) int Load(PLUGINLINK *link)
{
	PROTOCOLDESCRIPTOR pd = {0};

	pluginLink = link;

	sipe_core_init("");

	mir_getMMI( &mmi );

	// Register the module
	pd.cbSize   = sizeof(pd);
	pd.szName   = SIPSIMPLE_PROTOCOL_NAME;
	pd.type     = PROTOTYPE_PROTOCOL;
	pd.fnInit   = sipsimpleProtoInit;
	pd.fnUninit = sipsimpleProtoUninit;
	CallService(MS_PROTO_REGISTERMODULE, 0, (LPARAM)&pd);

	return 0;
}

__declspec(dllexport) int Unload(void)
{
	sipe_core_destroy();
	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	hInst = hinstDLL;
	return TRUE;
}


