/**
 * @file miranda-ft.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"
#include "miranda-private.h"

struct sipe_backend_file_transfer {
	int dummy;
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
	_NIF();
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
	_NIF();
}

gboolean sipe_backend_ft_incoming_accept(struct sipe_file_transfer *ft,
					 const gchar *ip,
					 unsigned short port_min,
					 unsigned short port_max)
{
	_NIF();
	return FALSE;
}

void
sipe_backend_ft_start(struct sipe_file_transfer *ft, int fd,
		      const char* ip, unsigned port)
{
	_NIF();
}

gboolean
sipe_backend_ft_is_incoming(struct sipe_file_transfer *ft)
{
	_NIF();
	return FALSE;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
