/**
 * @file sipe-core-private.h
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
struct sipe_service_data;

/**
 * Private part of the Sipe data structure
 *
 * This part contains the information only needed by the core
 */
struct sipe_account_data; /* to be removed... */
struct sipe_core_private {
	/**
	 * The public part is the first item, i.e. a pointer to the
	 * public part can also be used as a pointer to the private part.
	 */
	struct sipe_core_public public;

	/* SIP transport information */
	struct sipe_transport_connection *transport;
	const struct sipe_service_data *service_data;
	guint transport_type;
	gchar *server_name;
	guint  server_port;
	gchar *server_version;
	GSList *transactions;
	struct _sipe_media_call *media_call;

	/* Buddies */
	GHashTable *buddies;

	/* Scheduling system */
	GSList *timeouts;

	/* misc. stuff */
	gchar *useragent;

	/* the original data structure*/
	struct sipe_account_data *temporary;
};

/**
 * Flags - stored in sipe_core_public.flags but names not exported
 */
#define SIPE_CORE_PRIVATE_FLAG_xxx 0x80000000 /* place holder... */

#define SIPE_CORE_PUBLIC_FLAG_IS(flag)    \
	((sipe_private->public.flags & SIPE_CORE_FLAG_ ## flag) == SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PUBLIC_FLAG_SET(flag)   \
	(sipe_private->public.flags |= SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PUBLIC_FLAG_UNSET(flag)				\
	(sipe_private->public.flags &= ~SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_IS(flag)    \
	((sipe_private->public.flags & SIPE_CORE_PRIVATE_FLAG_ ## flag) == SIPE_CORE_PRIVATE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_SET(flag)   \
	(sipe_private->public.flags |= SIPE_CORE_PRIVATE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_UNSET(flag)				\
	(sipe_private->public.flags &= ~SIPE_CORE_PRIVATE_FLAG_ ## flag)

/* Convenience macros */
#define SIPE_CORE_PRIVATE ((struct sipe_core_private *)sipe_public)
#define SIPE_CORE_PUBLIC  ((struct sipe_core_public *)sipe_private)

/* Transition macros */
#define SIPE_ACCOUNT_DATA         SIPE_CORE_PRIVATE->temporary
#define SIPE_ACCOUNT_DATA_PRIVATE sipe_private->temporary
#define SIP_TO_CORE_PRIVATE (sip->private)
#define SIP_TO_CORE_PUBLIC (sip->public)

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
