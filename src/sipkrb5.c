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
#include <errno.h>
#include <ctype.h>
#include <et/com_err.h>

#include "debug.h"
#include "util.h"

#include <krb5.h>
#include <gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#include "sipkrb5.h"
#include "sipmsg.h"

void log_krb5_error(krb5_context ctx, krb5_error_code err, char * msg)
{
	const char * err_msg = krb5_get_error_message(ctx, err);
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "%s; error: %s\n", msg, err_msg);
	krb5_free_error_message(ctx, err_msg);
}

/* Taken from krb5's src/tests/gss-threads/gss-misc.c */

static void display_status_1(m, code, type)
     char *m;
     OM_uint32 code;
     int type;
{
     OM_uint32 maj_stat, min_stat;
     gss_buffer_desc msg;
     OM_uint32 msg_ctx;
     
     msg_ctx = 0;
     while (1) {
	  maj_stat = gss_display_status(&min_stat, code,
				       type, GSS_C_NULL_OID,
				       &msg_ctx, &msg);
	  purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "GSS-API error %s: %s\n", m, (char *)msg.value); 
	  (void) gss_release_buffer(&min_stat, &msg);
	  
	  if (!msg_ctx)
	       break;
     }
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 * 	msg		a string to be displayed with the message
 * 	maj_stat	the GSS-API major status code
 * 	min_stat	the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void display_status(msg, maj_stat, min_stat)
     char *msg;
     OM_uint32 maj_stat;
     OM_uint32 min_stat;
{
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/* End taken from krb5's src/tests/gss-threads/gss-misc.c */

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
	auth->gss_context = NULL;

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
	initialize_gss(auth, &(credentials.server));
	purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "generated krb5 auth token and initialized GSS context\n");

	// Clean up
	free_principal:
	krb5_free_principal(context, principal);

	free_context:
	krb5_free_context(context);
}

int initialize_gss(struct sipe_krb5_auth * auth, krb5_principal *principal)
{
	OM_uint32* ret_flags;
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	gss_name_t target_name;
	OM_uint32 maj_stat, min_stat, init_sec_min_stat;
	int token_flags;

	/*
	* Import the name into target_name.  Use send_tok to save
	* local variable space.
	*/
	//char * service_name = "sip";
	//char * service_name = "sip/ocs1.ocs.provo.novell.com";
	char * service_name = "sip@ocs1.ocs.provo.novell.com";
	send_tok.value = service_name;
	send_tok.length = strlen(service_name);
	//maj_stat = gss_import_name(&min_stat, &send_tok, GSS_C_NT_USER_NAME, &target_name);
	maj_stat = gss_import_name(&min_stat, &send_tok, GSS_C_NT_HOSTBASED_SERVICE, &target_name);

	if (maj_stat != GSS_S_COMPLETE) {
		display_status("parsing name", maj_stat, min_stat);
		return -1;
	}

	/*if (!v1_format) {
	if (send_token(s, TOKEN_NOOP|TOKEN_CONTEXT_NEXT, empty_token) < 0) {
	(void) gss_release_name(&min_stat, &target_name);
	return -1;
	}
	}*/

	/*
	* Perform the context-establishement loop.
	*
	* On each pass through the loop, token_ptr points to the token
	* to send to the server (or GSS_C_NO_BUFFER on the first pass).
	* Every generated token is stored in send_tok which is then
	* transmitted to the server; every received token is stored in
	* recv_tok, which token_ptr is then set to, to be processed by
	* the next call to gss_init_sec_context.
	* 
	* GSS-API guarantees that send_tok's length will be non-zero
	* if and only if the server is expecting another token from us,
	* and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
	* and only if the server has another token to send us.
	*/

	token_ptr = GSS_C_NO_BUFFER;
	gss_ctx_id_t gss_no_context = GSS_C_NO_CONTEXT;
	auth->gss_context = &gss_no_context;
	//OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
	//OM_uint32 req_flags = 0; //GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;// | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
	OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;// | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;

	do {
		maj_stat = gss_init_sec_context(&init_sec_min_stat,
			GSS_C_NO_CREDENTIAL,
			auth->gss_context,
			target_name,
			gss_mech_krb5,
			req_flags,
			0, // 0 = default = 2 hrs
			GSS_C_NO_CHANNEL_BINDINGS,
			token_ptr,
			NULL,	/* ignore mech type */
			&send_tok,
			ret_flags, /* output */
			NULL);	/* ignore time_rec */

		if (token_ptr != GSS_C_NO_BUFFER) {
			free(recv_tok.value);
		}

		if (send_tok.length != 0) {
			purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "send_tok.length != 0, but not sending..\n");
			/*if (verbose) {
				printf("Sending init_sec_context token (size=%d)...",
					(int) send_tok.length);
			}*/
			/*if (send_token(s, v1_format?0:TOKEN_CONTEXT, &send_tok) < 0) {
				(void) gss_release_buffer(&min_stat, &send_tok);
				(void) gss_release_name(&min_stat, &target_name);
				if (*gss_context != GSS_C_NO_CONTEXT) {
					gss_delete_sec_context(&min_stat, gss_context,
					GSS_C_NO_BUFFER);
					*gss_context = GSS_C_NO_CONTEXT;
				}
				return -1;
			}*/
		} else {
			//purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "send_tok.length == 0, nothing to send\n");
		}

		(void) gss_release_buffer(&min_stat, &send_tok);

		if (maj_stat == GSS_S_COMPLETE && ret_flags != NULL) {
			purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "gss_init_sec_context req_flags = %d ret_flags = %d\n", req_flags, *ret_flags);
		}

		if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
			purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED; maj_stat = %d\n", maj_stat);
			display_status("initializing context", maj_stat, init_sec_min_stat);
			(void) gss_release_name(&min_stat, &target_name);

			if (*(auth->gss_context) != GSS_C_NO_CONTEXT) {
				gss_delete_sec_context(&min_stat, auth->gss_context, GSS_C_NO_BUFFER);
			}
			return -1;
		}

		if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "maj_stat == GSS_S_CONTINUE_NEEDED\n");
			/*if (verbose) {
				printf("continue needed...");
			}
			if (recv_token(s, &token_flags, &recv_tok) < 0) {
				(void) gss_release_name(&min_stat, &target_name);
				return -1;
			}
			token_ptr = &recv_tok;*/
		}

		/*if (verbose) {
			printf("\n");
		}*/
	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	(void) gss_release_name(&min_stat, &target_name);

	return 0;
}

/*
gchar *
purple_krb5_get_mic(struct sipe_krb5_auth * auth, char * msg)
{
	if (auth == NULL || auth->gss_context == NULL) {
		purple_debug(PURPLE_DEBUG_MISC, "sip_krb5", "gss_get_mic auth or auth->gss_context is null\n");
		return NULL;
	}

	gchar * mic = NULL;
	gss_buffer_desc msg_buf;
	msg_buf.value = msg;
	msg_buf.length = strlen(msg_buf.value) + 1;
	
	gss_buffer_desc mic_buf;
	OM_uint32 major, minor;

	if (major = gss_get_mic(&minor, *(auth->gss_context), GSS_C_QOP_DEFAULT, &msg_buf, &mic_buf)) {
		purple_debug(PURPLE_DEBUG_MISC, "gss_get_mic", "major is %d, minor is %d\n", major, minor);
		return NULL;
	}

	if (mic_buf.length > 0) {
		gchar mic_val [mic_buf.length * 2];
		guint8 * mic_int_ary = (guint8 *) mic_buf.value;
		int i, j;
		for (i = 0, j = 0; i < mic_buf.length; i++, j+=2) {
			g_sprintf(&mic_val[j], "%02x", mic_int_ary[i]);
		}
		mic = g_strdup(mic_val);
	} else {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "gss_get_mic MIC is empty\n");
	}

	gss_release_buffer(&minor, &mic_buf);

	return mic;
}

gchar *
purple_krb5_get_mic_for_msg_breakdown(struct sipe_krb5_auth * auth, struct sipmsg_breakdown * msgbd)
{
	if (msgbd->realm == empty_string || msgbd->realm == NULL) {
		purple_debug(PURPLE_DEBUG_MISC, "sipkrb5", "realm NULL, so returning NULL MIC\n");
		return NULL;
	}

	gchar * response_str = msgbd->msg->response != 0 ? g_strdup_printf("<%d>", msgbd->msg->response) : empty_string;
	gchar * msg = g_strdup_printf(
		"<%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s>" // 1 - 11
		"<%s>%s", // 12 - 13
		"Kerberos", msgbd->rand, msgbd->num, msgbd->realm, msgbd->target_name, msgbd->call_id, msgbd->cseq,
		msgbd->msg->method, msgbd->from_url, msgbd->from_tag, msgbd->to_tag,
		msgbd->expires ? msgbd->expires : empty_string, response_str
	);

	gchar * mic = purple_krb5_get_mic(auth, msg);

	g_free(msg);
	if (response_str != empty_string) {
		g_free(response_str);
	}

	return mic;
}

gchar *
purple_krb5_get_mic_for_sipmsg(struct sipe_krb5_auth * auth, struct sipmsg * msg)
{
	struct sipmsg_breakdown sipbd;
	sipbd.msg = msg;
	sipmsg_breakdown_parse(&sipbd);

	gchar * mic = purple_krb5_get_mic_for_msg_breakdown(auth, &sipbd);
  
	sipmsg_breakdown_free(&sipbd);
	return mic;
}*/
