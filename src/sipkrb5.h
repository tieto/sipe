/*
 * @file sipkrb5.h
 *
 * Methods for using Kerberos authentication and signing with SIPE,
 * implemented with reference to
 *   - MS-SIP: http://msdn.microsoft.com/en-us/library/cc431510.aspx
 *
 * Authentication is known to be working, but the signing does not work at
 * all yet.
 *
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 Andrew Rechenberg
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

#ifndef _PIDGIN_SIPE_KRB5_H
#define _PIDGIN_SIPE_KRB5_H

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
#include <gssapi.h>

struct sipe_krb5_auth {
	const char * authuser;
	const char * realm;
	char * password;
	const char * hostname;
	const char * service;

	char * token;
	gchar * base64_token;

	gss_ctx_id_t * gss_context;
};

void purple_krb5_init_auth(struct sipe_krb5_auth *, const char *authuser, const char *realm, char *password, const char *hostname, const char *service);
void purple_krb5_gen_auth_token(struct sipe_krb5_auth * auth);

gchar * purple_krb5_get_mic(struct sipe_krb5_auth * auth, char * msg);
gchar * purple_krb5_get_mic_for_sipmsg(struct sipe_krb5_auth * auth, struct sipmsg * msg);

#endif /* _PIDGIN_SIPE_KRB5_H */
