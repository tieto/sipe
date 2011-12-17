/**
 * @file miranda-im.c
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
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"
#include "m_database.h"
#include "m_protomod.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

void sipe_backend_im_message(struct sipe_core_public *sipe_public,
			     const gchar *from,
			     const gchar *html)
{
	SIPPROTO *pr = sipe_public->backend_private;

	CCSDATA ccs;
	PROTORECVEVENT pre = {0};
	HANDLE hContact;
	gchar *msg;

	hContact = sipe_backend_buddy_find( sipe_public, from, NULL );
	if (!hContact)
	{
		SIPE_DEBUG_INFO("Adding miranda contact for incoming talker <%s>", from);
		hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
		CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
		DBWriteContactSettingByte( hContact, "CList", "NotOnList", 1 );
		sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, from ); // name
	}

	msg = sipe_miranda_eliminate_html(html, strlen(html));

	pre.szMessage = msg;
//	pre.flags = PREF_UTF + (isRtl ? PREF_RTL : 0);
	pre.timestamp = (DWORD)time(NULL);
	pre.lParam = 0;

	ccs.szProtoService = PSR_MESSAGE;
	ccs.hContact = hContact;
	ccs.wParam = 0;
	ccs.lParam = (LPARAM)&pre;
	CallService(MS_PROTO_CHAINRECV, 0, (LPARAM)&ccs);

	mir_free(msg);

}

int sipe_miranda_SendMsg(SIPPROTO *pr,
			 HANDLE hContact,
			 int flags,
			 const char* msg )
{
	DBVARIANT dbv;

	SIPE_DEBUG_INFO("SendMsg: flags <%x> msg <%s>", flags, msg);

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		LOCK;
		sipe_core_im_send(pr->sip, dbv.pszVal, msg);
		UNLOCK;
		sipe_miranda_SendProtoAck( pr, hContact, 1, ACKRESULT_SUCCESS, ACKTYPE_MESSAGE, NULL );
		DBFreeVariant(&dbv);
	} else {
		sipe_miranda_SendProtoAck( pr, hContact, 1, ACKRESULT_FAILED, ACKTYPE_MESSAGE, NULL );
	}
	return 1;
}

int sipe_miranda_RecvMsg(SIPPROTO *pr,
			 HANDLE hContact,
			 PROTORECVEVENT* pre)
{
//	char *msg = EliminateHtml( pre->szMessage, strlen(pre->szMessage));
//	mir_free(pre->szMessage);
//	pre->szMessage = msg;

	CCSDATA ccs = { hContact, PSR_MESSAGE, 0, ( LPARAM )pre };
	return CallService( MS_PROTO_RECVMSG, 0, ( LPARAM )&ccs );
}

void sipe_backend_im_topic(struct sipe_core_public *sipe_public,
			   const gchar *with,
			   const gchar *topic)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hContact;

	hContact = sipe_backend_buddy_find( sipe_public, with, NULL );
	if (!hContact)
	{
		_NIF();
	} else {
		sipe_miranda_AddEvent(pr, hContact, SIPE_EVENTTYPE_IM_TOPIC, time(NULL), DBEF_UTF, strlen(topic), (PBYTE)topic);
	}

}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
