/**
 * @file purple-private.h
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

/* Forward declarations */
struct sipe_core_public;
struct _PurpleAccount;
struct _PurpleConnection;
struct _PurpleSrvQueryData;

struct sipe_backend_private {
	struct sipe_core_public *public;
	struct _PurpleConnection *gc;
	struct _PurpleAccount *account;
	struct _PurpleSrvQueryData *dns_query;
	time_t last_keepalive;
};

/* Convenience macros */
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) account->gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) gc->proto_data)

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
