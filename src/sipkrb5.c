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

gchar *
purple_krb5_gen_auth_token(const gchar *authuser,
			   const gchar *realm,
			   const gchar * password,
			   const gchar *hostname,
			   const gchar *service)
{
	/* 
	 * Ideally we will check to see if a Kerberos ticket already exists in the 
	 * default Kerberos credential cache.  Right now we re-do everything all 
	 * the time.  
	 *
	 * XXX FIXME - Check for ticket already and create a KRB_AP_REQ from creds
	 *             we already have.
	 */
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "entered Kerberos code\r\n");
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "hostname: %s, length: %d\r\n", (char *)hostname, strlen((char *)hostname));


	gchar		*krb5_token;

	krb5_context	context;
	krb5_principal	principal;
	krb5_creds	credentials;
	krb5_ccache	ccdef;
	krb5_error_code	retval;
	char *progname = 0;

	memset(&credentials, 0, sizeof(krb5_creds));

	// Initialize the KRB context
	krb5_init_context(&context);

	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "KRB context initialized\r\n");

	// Build a Kerberos principal and get a TGT if there isn't one already
	krb5_build_principal(context, &principal, strlen(realm), realm, authuser, NULL);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "KRB principal built\r\n");

	krb5_get_init_creds_password(context, &credentials, principal, (char *)password, NULL, NULL, 0, NULL, NULL);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "Got TGT\r\n");

	// Initialize default credentials cache
	krb5_cc_default(context, &ccdef);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "Returned from krb5_cc_default\r\n");

	if (retval = krb5_cc_initialize(context, ccdef, credentials.client)) {
		com_err(progname, retval, "while initializing credentials cache\r\n");
		return NULL;
	}

	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "Default credentials cache initialized\r\n");

	// Store the TGT
	krb5_cc_store_cred(context, ccdef, &credentials);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "Stored TGT\r\n");

	// Prepare the AP-REQ
	krb5_data		inbuf, ap_req;
	krb5_auth_context	auth_context = NULL;

	inbuf.data = (char *)hostname;
	inbuf.length = strlen((char *)hostname);
	
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "Setup inbuf data - hostname: %s, length: %d\r\n", (char *)hostname, strlen((char *)hostname));

	if ((retval = krb5_mk_req(context, &auth_context, AP_OPTS_MUTUAL_REQUIRED, (char *)service, (char *)hostname, &inbuf, ccdef, &ap_req))) {
		purple_debug(PURPLE_DEBUG_MISC, "purple_krb5_gen_auth_token", "problem generating the KRB_AP_REQ\r\n");
		return NULL;
	}

	krb5_token = purple_base64_encode((gchar *)ap_req.data, ap_req.length);

	purple_debug(PURPLE_DEBUG_MISC, "purple_krb5_gen_auth_token", "token %s\r\n", (char *)krb5_token);

	// Clean up
	krb5_free_principal(context, principal);
	krb5_free_context(context);
	

	return krb5_token;
}
