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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>
#include <errno.h>
#include <ctype.h>
#include <et/com_err.h>

#include "debug.h"
#include "util.h"

#include "sipkrb5.h"

void log_krb5_error(krb5_context ctx, krb5_error_code err, char * msg)
{
	const char * err_msg = krb5_get_error_message(ctx, err);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "%s; error: %s\n", msg, err_msg);
	krb5_free_error_message(ctx, err_msg);
}

void
purple_krb5_init_auth(struct sipe_krb5_auth * auth,
		      const char *authuser,
		      const char *realm,
		      char *password,
		      const char *hostname,
		      const char *service)
{
	auth->authuser = authuser;
	auth->realm = realm;
	auth->password = password;
	auth->hostname = hostname;
	auth->service = service;

	auth->token = NULL;
	auth->base64_token = NULL;
	//auth->gss_context = NULL;

	purple_krb5_gen_auth_token(auth);
}

void
purple_krb5_gen_auth_token(struct sipe_krb5_auth * auth)
{
	/* 
	 * Ideally we will check to see if a Kerberos ticket already exists in the 
	 * default Kerberos credential cache.  Right now we re-do everything all 
	 * the time.  
	 *
	 * XXX FIXME - Check for ticket already and create a KRB_AP_REQ from creds
	 *             we already have.
	 */

	krb5_context	context;
	krb5_principal	principal;
	krb5_creds	credentials;
	krb5_ccache	ccdef;
	krb5_error_code	retval;
	char *progname = 0;

	memset(&credentials, 0, sizeof(krb5_creds));

	// Initialize the KRB context
	if (retval = krb5_init_context(&context)) {
		log_krb5_error(context, retval, "krb5_init_context");
		return;
	}

	// Build a Kerberos principal and get a TGT if there isn't one already
	if (retval = krb5_build_principal(context, &principal, strlen(auth->realm), auth->realm, auth->authuser, NULL)) {
		log_krb5_error(context, retval, "krb5_build_principal");
		goto free_context;
	}

	if (retval = krb5_get_init_creds_password(context, &credentials, principal, auth->password, NULL, NULL, 0, NULL, NULL)) {
		log_krb5_error(context, retval, "krb5_get_init_creds_password");
		goto free_principal;
	}

	// Initialize default credentials cache
	if (retval = krb5_cc_default(context, &ccdef)) {
		log_krb5_error(context, retval, "krb5_cc_default");
		goto free_principal;
	}

	if (credentials.client == NULL) {
		log_krb5_error(context, retval, "credentials.client == NULL");
		goto free_principal;
	}

	if (retval = krb5_cc_initialize(context, ccdef, credentials.client)) {
		log_krb5_error(context, retval, "krb5_cc_initialize");
		goto free_principal;
	}

	// Store the TGT
	if (retval = krb5_cc_store_cred(context, ccdef, &credentials)) {
		log_krb5_error(context, retval, "krb5_cc_store_cred");
		goto free_principal;
	}

	// Prepare the AP-REQ
	krb5_data		inbuf, ap_req;
	krb5_auth_context	auth_context = NULL;

	inbuf.data = (char *)auth->hostname;
	inbuf.length = strlen((char *)auth->hostname);
	
	if ((retval = krb5_mk_req(context, &auth_context, AP_OPTS_MUTUAL_REQUIRED, (char *)auth->service, (char *)auth->hostname, &inbuf, ccdef, &ap_req))) {
		log_krb5_error(context, retval, "krb5_mk_req");
		goto free_principal;
	}

	auth->token = (char *)ap_req.data;
	auth->base64_token = purple_base64_encode(auth->token, ap_req.length);

	// Initialize the GSS layer
	//initialize_gss(auth, &(credentials.server));

	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "generated krb5 auth token and initialized GSS context\n");

	// Clean up
	free_principal:
	krb5_free_principal(context, principal);

	free_context:
	krb5_free_context(context);
}

