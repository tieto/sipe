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

/* Miranda interface globals */

static HANDLE wake_up_semaphore = NULL;

void CreateProtoService(SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc)
{
	char str[ MAXMODULELABELLENGTH ];

	mir_snprintf(str, sizeof(str), "%s%s", pr->proto.m_szModuleName, szService);
	CreateServiceFunctionObj(str, (MIRANDASERVICEOBJ)*(void**)&serviceProc, pr);
}

HANDLE HookProtoEvent(SIPPROTO *pr, const char* szEvent, SipSimpleEventFunc pFunc)
{
	return HookEventObj(szEvent, (MIRANDAHOOKOBJ)*(void**)&pFunc, pr);
}

void ProtocolAckThread(SIPPROTO *pr, struct miranda_sipe_ack_args* pArguments)
{
	ProtoBroadcastAck(pr->proto.m_szModuleName, pArguments->hContact, pArguments->nAckType, pArguments->nAckResult, pArguments->hSequence, pArguments->pszMessage);

	if (pArguments->nAckResult == ACKRESULT_SUCCESS)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent ACK");
	else if (pArguments->nAckResult == ACKRESULT_FAILED)
		SIPE_DEBUG_INFO_NOFORMAT("ProtocolAckThread: Sent NACK");

	g_free((gpointer)pArguments->pszMessage);
	g_free(pArguments);
}

void ForkThread( SIPPROTO *pr, SipSimpleThreadFunc pFunc, void* arg )
{
	CloseHandle(( HANDLE )mir_forkthreadowner(( pThreadFuncOwner )*( void** )&pFunc, pr, arg, NULL ));
}

void SendProtoAck( SIPPROTO *pr, HANDLE hContact, DWORD dwCookie, int nAckResult, int nAckType, char* pszMessage)
{
	struct miranda_sipe_ack_args* pArgs = (struct miranda_sipe_ack_args*)g_malloc(sizeof(struct miranda_sipe_ack_args)); // This will be freed in the new thread
	pArgs->hContact = hContact;
	pArgs->hSequence = (HANDLE)dwCookie;
	pArgs->nAckResult = nAckResult;
	pArgs->nAckType = nAckType;
	pArgs->pszMessage = (LPARAM)g_strdup(pszMessage);

	ForkThread( pr, ( SipSimpleThreadFunc )&ProtocolAckThread, pArgs );
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


/* Protocol interface support functions */
typedef struct _time_entry
{
	guint interval;
	GSourceFunc function;
	gpointer data;
	HANDLE sem;
} time_entry;

/* libsipe interface functions */
static char*
miranda_sipe_get_current_status(struct sipe_core_private *sipe_private, const char* name)
{
	SIPPROTO *pr = sipe_private->public.backend_private;
	char *module = pr->proto.m_szModuleName;
	HANDLE hContact;

	if (!name)
		return g_strdup(MirandaStatusToSipe(pr->proto.m_iStatus));

	hContact = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, name, NULL);
	return g_strdup(MirandaStatusToSipe(DBGetContactSettingWord( hContact, module, "Status", ID_STATUS_OFFLINE )));
}

static void*
miranda_sipe_request_authorization(struct sipe_core_private *sipe_private, const char *who, const char *alias,
		sipe_backend_buddy_request_authorization_cb auth_cb,
		sipe_backend_buddy_request_authorization_cb deny_cb, void *data)
{
	SIPPROTO *pr = sipe_private->public.backend_private;
	CCSDATA ccs;
	PROTORECVEVENT pre = {0};
	HANDLE hContact;
	char* szBlob;
	char* pCurBlob;

	hContact = sipe_backend_buddy_find( SIPE_CORE_PUBLIC, who, NULL );
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


/****************************************************************************
 * Struct that defines our interface with libsipe
 ****************************************************************************/
/* Protocol interface functions */
int RecvContacts( SIPPROTO *pr, HANDLE hContact, PROTORECVEVENT* evt )
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


/* Dialogs */
/* Event handlers */
