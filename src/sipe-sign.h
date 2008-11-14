/*
 * sipe-sign.h
 *
 */

/* 
 * Copyright (C) 2008 Novell, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#ifndef _PIDGIN_SIPE_SIGN_H
#define _PIDGIN_SIPE_SIGN_H

#include <glib.h>
#include <time.h>

#include "cipher.h"
#include "circbuffer.h"
#include "dnsquery.h"
#include "dnssrv.h"
#include "network.h"
#include "proxy.h"
#include "prpl.h"
#include "sslconn.h"

#include "sipmsg.h"

struct sipmsg_breakdown {
	struct sipmsg * msg;
	gchar * rand;
	gchar * num;
	gchar * realm;
	gchar * target_name;
	gchar * call_id;
	gchar * cseq;
	gchar * from_url;
	gchar * from_tag;
	gchar * to_tag;
	gchar * expires;
};

void sipmsg_breakdown_parse(struct sipmsg_breakdown * msg, gchar * realm, gchar * target);
gchar* sipmsg_breakdown_get_string(struct sipmsg_breakdown * msgbd);
void sipmsg_breakdown_free(struct sipmsg_breakdown * msg);

#endif /* _PIDGIN_SIPE_SIGN_H */
