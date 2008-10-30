/*
 * sipkrb5.c - Methods for Using Kerberos Authentication with SIP
 * per MS SIPAE
 *
 * http://msdn.microsoft.com/en-us/library/cc431510.aspx
 *
 */

/* 
 * Copyright (C)2008 Andrew Rechenberg
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

struct sipe_krb5_auth {
	const char * authuser;
	const char * realm;
	char * password;
	const char * hostname;
	const char * service;

	char * token;
	gchar * base64_token;

	//gss_ctx_id_t * gss_context;
};

void purple_krb5_init_auth(struct sipe_krb5_auth *, const char *authuser, const char *realm, char *password, const char *hostname, const char *service);
void purple_krb5_gen_auth_token(struct sipe_krb5_auth * auth);

#endif /* _PIDGIN_SIPE_KRB5_H */
