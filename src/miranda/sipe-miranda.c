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
#include "sipe-backend.h"
#include "miranda-private.h"
#include "miranda-resource.h"

/* Miranda interface globals */

void CreateProtoService(SIPPROTO *pr, const char* szService, SipSimpleServiceFunc serviceProc)
{
	char str[ MAXMODULELABELLENGTH ];

	mir_snprintf(str, sizeof(str), "%s%s", pr->proto.m_szModuleName, szService);
	CreateServiceFunctionObj(str, (MIRANDASERVICEOBJ)*(void**)&serviceProc, pr);
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
