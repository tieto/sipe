#include <windows.h>
#include <win2k.h>
#include <Richedit.h>
#include <process.h>

#include <glib.h>

#include "miranda-version.h"
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
#include "sipe-core-private.h"
#include "sipe-backend.h"
#include "sipe-utils.h"
#include "sipe-conf.h"
#include "sipe-chat.h"
#include "sipe-session.h"
#include "miranda-private.h"
#include "miranda-resource.h"

/* Miranda interface globals */

void CreateProtoService(SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc)
{
	char str[ MAXMODULELABELLENGTH ];

	mir_snprintf(str, sizeof(str), "%s%s", pr->proto.m_szModuleName, szService);
	CreateServiceFunctionObj(str, (MIRANDASERVICEOBJ)*(void**)&serviceProc, pr);
}


/* libsipe interface functions */
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
