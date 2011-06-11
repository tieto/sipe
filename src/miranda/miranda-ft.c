/**
 * @file miranda-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 Jakub Adam <jakub.adam@ktknet.cz>
 * Copyright (C) 2010 Tomáš Hrabčík <tomas.hrabcik@tieto.com>
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
#include "m_database.h"
#include "m_protomod.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"
#include "miranda-private.h"

struct sipe_backend_file_transfer {
	gboolean incoming;
};

void sipe_backend_ft_error(struct sipe_file_transfer *ft,
			   const gchar *errmsg)
{
	_NIF();
}

const gchar *sipe_backend_ft_get_error(SIPE_UNUSED_PARAMETER struct sipe_file_transfer *ft)
{
	_NIF();
	return NULL;
}

void sipe_backend_ft_deallocate(struct sipe_file_transfer *ft)
{
	g_free(ft->backend_private);
}

gssize sipe_backend_ft_read(struct sipe_file_transfer *ft,
			    guchar *data,
			    gsize size)
{
	_NIF();
	return 0;
}

gssize sipe_backend_ft_write(struct sipe_file_transfer *ft,
			     const guchar *data,
			     gsize size)
{
	_NIF();
	return 0;
}

void sipe_backend_ft_cancel_local(struct sipe_file_transfer *ft)
{
	_NIF();
}

void sipe_backend_ft_cancel_remote(struct sipe_file_transfer *ft)
{
	_NIF();
}

void sipe_backend_ft_incoming(struct sipe_core_public *sipe_public,
			      struct sipe_file_transfer *ft,
			      const gchar *who,
			      const gchar *file_name,
			      gsize file_size)
{
	SIPPROTO *pr = sipe_public->backend_private;
	PROTORECVFILET pre = {0};
	CCSDATA ccs;
	HANDLE hContact;

	hContact = sipe_backend_buddy_find( sipe_public, who, NULL );
	if (!hContact)
	{
		SIPE_DEBUG_INFO("Adding miranda contact for incoming transfer from <%s>", who);
		hContact = ( HANDLE )CallService( MS_DB_CONTACT_ADD, 0, 0 );
		CallService( MS_PROTO_ADDTOCONTACT, ( WPARAM )hContact,( LPARAM )pr->proto.m_szModuleName );
		DBWriteContactSettingByte( hContact, "CList", "NotOnList", 1 );
		sipe_miranda_setContactString( pr, hContact, SIP_UNIQUEID, who ); // name
	}

	ft->backend_private = g_new0(struct sipe_backend_file_transfer, 1);
	ft->backend_private->incoming = TRUE;

	pre.flags = PREF_TCHAR;
	pre.timestamp = time(NULL);
	pre.tszDescription = mir_a2t(file_name);
	pre.fileCount = 1;
	pre.ptszFiles = &pre.tszDescription;
	pre.lParam = (LPARAM)ft;

        ccs.szProtoService = PSR_FILE;
        ccs.hContact = hContact;
        ccs.wParam = 0;
        ccs.lParam = (LPARAM)&pre;
        CallService(MS_PROTO_CHAINRECV, 0, (LPARAM)&ccs);

}

gboolean
sipe_backend_ft_incoming_accept(struct sipe_file_transfer *ft,
				const gchar *ip,
				unsigned short port_min,
				unsigned short port_max)
{
	_NIF();
	return FALSE;
}

void
sipe_backend_ft_start(struct sipe_file_transfer *ft, struct sipe_backend_fd *fd,
                      const char* ip, unsigned port)
{
	_NIF();
}

gboolean
sipe_backend_ft_is_incoming(struct sipe_file_transfer *ft)
{
	return ft->backend_private->incoming;
}

HANDLE
sipe_miranda_SendFile( SIPPROTO *pr, HANDLE hContact, const PROTOCHAR* szDescription, PROTOCHAR** ppszFiles )
{
	struct sipe_file_transfer *ft = sipe_core_ft_allocate(pr->sip);
	DBVARIANT dbv;

	if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
		LOCK;
		ft->backend_private = g_new0(struct sipe_backend_file_transfer, 1);
		ft->backend_private->incoming = FALSE;
		sipe_core_ft_outgoing_init(ft, TCHAR2CHAR(ppszFiles[0]), 10, dbv.pszVal);
		UNLOCK;

		SIPE_DEBUG_INFO("SendFile: desc <%ls> name <%s> to <%s>", szDescription, TCHAR2CHAR(ppszFiles[0]), dbv.pszVal);
		DBFreeVariant( &dbv );
	}

	return NULL;
}

int
sipe_miranda_RecvFile( SIPPROTO *pr, HANDLE hContact, PROTOFILEEVENT* evt )
{
        CCSDATA ccs = { hContact, PSR_FILE, 0, (LPARAM)evt };
        return CallService(MS_PROTO_RECVFILET, 0, (LPARAM)&ccs);
}

HANDLE
sipe_miranda_FileAllow( SIPPROTO *pr, HANDLE hContact, HANDLE hTransfer, const PROTOCHAR* szPath )
{
	struct sipe_file_transfer *ft = (struct sipe_file_transfer *)hTransfer;
	sipe_core_ft_incoming_init(ft);
	return ft;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
