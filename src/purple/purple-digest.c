/**
 * @file purple-digest.c
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

#include "glib.h"
#include "cipher.h"

#include "sipe-backend.h"

const guchar *sipe_backend_digest_sha1(const guchar *data, gsize length)
{
	static guchar digest[20];
	PurpleCipherContext *ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, data, length);
	purple_cipher_context_digest(ctx, sizeof(digest), digest, NULL);
	purple_cipher_context_destroy(ctx);
	return(digest);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
