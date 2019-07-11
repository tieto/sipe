/**
 * @file sipe-sipmsg-tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2019 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * Some non-NTLM tests code was factored out from sipe-sec-ntlm-test.c:
 *
 *------------- Copyright notices from "sipe-sec-ntlm-tests.c" -------------
 * Copyright (C) 2011-2016 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
 * Copyright (C) 2008 Novell, Inc.
 *------------- Copyright notices from "sipe-sec-ntlm-tests.c" -------------
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-crypt.h"
#include "sipe-mime.h"
#include "sipe-rtf.h"
#include "sipe-sign.h"
#include "sipe-utils.h"
#include "sip-transport.h"
#include "sipmsg.h"

#include "uuid.h"

/*
 * Stubs
 */
gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG(%d): %s\n", level, msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	gchar *newformat = g_strdup_printf("DEBUG(%d): %s\n", level, format);

	va_start(ap, format);
	vprintf(newformat, ap);
	va_end(ap);

	g_free(newformat);
}

gchar *sipe_backend_markup_css_property(SIPE_UNUSED_PARAMETER const gchar *style,
					SIPE_UNUSED_PARAMETER const gchar *option)
{
	return(NULL);
}

void sipe_mime_parts_foreach(SIPE_UNUSED_PARAMETER const gchar *type,
			     SIPE_UNUSED_PARAMETER const gchar *body,
			     SIPE_UNUSED_PARAMETER sipe_mime_parts_cb callback,
			     SIPE_UNUSED_PARAMETER gpointer user_data)
{
}

gchar *sipe_rtf_to_html(SIPE_UNUSED_PARAMETER const gchar *rtf)
{
	return(NULL);
}

const gchar *sip_transport_epid(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private)
{
	return(NULL);
}

const gchar *sip_transport_ip_address(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private)
{
	return(NULL);
}

/* needed when linking against NSS */
void md4sum(const uint8_t *data, uint32_t length, uint8_t *digest);
void md4sum(SIPE_UNUSED_PARAMETER const uint8_t *data,
	    SIPE_UNUSED_PARAMETER uint32_t length,
	    SIPE_UNUSED_PARAMETER uint8_t *digest)
{
}

/*
 * Tester code
 */
static guint succeeded = 0;
static guint failed    = 0;

static void assert_equal(const char *expected, const gchar *got)
{
	if (sipe_strequal(expected, got)) {
		succeeded++;
	} else {
		printf("FAILED: %s\n        %s\n", got, expected);
		failed++;
	}
}

static void msg_tests(void) {
	/* Address parsing */
	{
		const gchar *responses[] = {
			"SIP/2.0 200 OK\r\n"
			"From: \"J.D. User\" <sip:foo.bar@company.com>;something else\r\n"
			"To: \"Test Recipient\" <SIP:test@recipient.com>\r\n"
			"X-Some-Header: <SiP:joe.header@test.com>\r\n"
			"Content-Length: 0\r\n"
			"\r\n",
			"SIP/2.0 200 OK\r\n"
			"From: sip:foo.bar@company.com;something else\r\n"
			"To: SIP:test@recipient.com\r\n"
			"X-Some-Header: SiP:joe.header@test.com\r\n"
			"Content-Length: 0\r\n"
			"\r\n",
			NULL
		};
		const gchar **resp;

		for (resp = responses; *resp; resp++) {
			struct sipmsg *msg = sipmsg_parse_msg(*resp);
			gchar *address;

			address = sipmsg_parse_from_address(msg);
			assert_equal("sip:foo.bar@company.com", address);
			g_free(address);

			address = sipmsg_parse_to_address(msg);
			assert_equal("SIP:test@recipient.com", address);
			g_free(address);

			address = sipmsg_parse_address_from_header(msg, "x-some-header");
			assert_equal("SiP:joe.header@test.com", address);
			g_free(address);

			sipmsg_free(msg);
		}
	}

	/* P-Asserted-Identity parsing */
	{
		const struct {
			const gchar *header;
			const gchar *sip_uri;
			const gchar *tel_uri;
		} testcases[] = {
			{
				"\"Cullen Jennings\" <sip:fluffy@cisco.com>",
				"sip:fluffy@cisco.com",
				NULL
			},
			{
				"tel:+14085264000",
				NULL,
				"tel:+14085264000"
			},
			{
				"\"Lunch, Lucas\" <sip:llucas@cisco.com>,<tel:+420123456;ext=88463>",
				"sip:llucas@cisco.com",
				"tel:+420123456;ext=88463"
			},
			{
				NULL,
				NULL,
				NULL
			},
		}, *testcase;

		for (testcase = testcases; testcase->header; testcase++) {
			gchar *sip_uri = NULL;
			gchar *tel_uri = NULL;

			sipmsg_parse_p_asserted_identity(testcase->header,
							 &sip_uri,
							 &tel_uri);
			assert_equal(testcase->sip_uri, sip_uri);
			assert_equal(testcase->tel_uri, tel_uri);

			g_free(tel_uri);
			g_free(sip_uri);
		}
	}

	/* Test Authentication Algorithm's v4 Signature String */
	{
		const gchar *response =
			"SIP/2.0 180 Ringing\r\n"
			"Authentication-Info: NTLM rspauth=\"010000003EA8D688BA51D5CD64000000\", srand=\"1B6D47A1\", snum=\"11\", opaque=\"357E6F72\", qop=\"auth\", targetname=\"LOC-COMPANYT-FE03.COMPANY.COM\", realm=\"SIP Communications Service\"\r\n"
			"Via: SIP/2.0/tls 192.168.44.10:50230;received=10.117.245.254;ms-received-port=50230;ms-received-cid=37ABE00\r\n"
			"FROM: \"Sender\"<sip:sender@company.com>;tag=2420628112;epid=54392f1bbf01\r\n"
			"TO: \"recipient\"<sip:recipient@company.com>;tag=7aee15546a;epid=3102EB8BD1\r\n"
			"CSEQ: 1 INVITE\r\n"
			"CALL-ID: 41CEg82ECa0AC8i3DD7mE673t9CF4b19DAxF780x\r\n"
			"RECORD-ROUTE: <sip:LOC-COMPANYT-OCSR2P01.COMPANY.COM:5061;transport=tls;ms-fe=LOC-COMPANYT-FE03.COMPANY.COM;opaque=state:F:T:Eu:Ci.R37abe00;lr;ms-route-sig=gdOGgL7NiL3hv_oBc0NdrJOxZk_r-8naq-k_DtpgAA>\r\n"
			"CONTACT: <sip:recipient@company.com;opaque=user:epid:-gLwenLTVVqy-Ak8TJn1ZAAA;gruu>;text;audio;video\r\n"
			"CONTENT-LENGTH: 0\r\n"
			"SUPPORTED: gruu-10\r\n"
			"ALLOW: UPDATE\r\n"
			"P-ASSERTED-IDENTITY: \"recipient\"<SIP:recipient@company.com>\r\n"
			"SERVER: RTCC/3.5.0.0 MCXService/3.5.0.0 communicator.NOKIAS60R2.JVP.EN_US/1.0.6875.0\r\n"
			"\r\n";
		const gchar *response_sig = "<NTLM><1B6D47A1><11><SIP Communications Service><LOC-COMPANYT-FE03.COMPANY.COM><41CEg82ECa0AC8i3DD7mE673t9CF4b19DAxF780x><1><INVITE><sip:sender@company.com><2420628112><sip:recipient@company.com><7aee15546a><SIP:recipient@company.com><><><180>";
		struct sipmsg_breakdown msgbd;
		gchar *msg_str;

		msgbd.msg = sipmsg_parse_msg(response);
		sipmsg_breakdown_parse(&msgbd,
				       "SIP Communications Service",
				       "LOC-COMPANYT-FE03.COMPANY.COM",
				       NULL);
		msg_str = sipmsg_breakdown_get_string(4, &msgbd);

		assert_equal(response_sig, msg_str);

		g_free(msg_str);
		sipmsg_free(msgbd.msg);
		sipmsg_breakdown_free(&msgbd);
	}

	/* Test parsing of address fields where URIs wrapped in "<...>" */
	{
		const gchar *response =
			"SIP/2.0 180 Ringing\r\n"
			"Authentication-Info: NTLM rspauth=\"010000003EA8D688BA51D5CD64000000\", srand=\"1B6D47A1\", snum=\"11\", opaque=\"357E6F72\", qop=\"auth\", targetname=\"bar\", realm=\"foo\"\r\n"
			"From: sip:sender@company.com;tag=2420628112;epid=54392f1bbf01\r\n"
			"To: sip:recipient@company.com;tag=7aee15546a;epid=3102EB8BD1\r\n"
			"CSeq: 1 INVITE\r\n"
			"Call-ID: 41CEg82ECa0AC8i3DD7mE673t9CF4b19DAxF780x\r\n"
			"Content-Length: 0\r\n"
			"P-Asserted-Identity: <SIP:recipient@company.com>\r\n"
			"\r\n";
		const gchar *response_sig = "<NTLM><1B6D47A1><11><foo><bar><41CEg82ECa0AC8i3DD7mE673t9CF4b19DAxF780x><1><INVITE><sip:sender@company.com><2420628112><sip:recipient@company.com><7aee15546a><SIP:recipient@company.com><><><180>";
		struct sipmsg_breakdown msgbd;
		gchar *msg_str;

		msgbd.msg = sipmsg_parse_msg(response);
		sipmsg_breakdown_parse(&msgbd,
				       "foo",
				       "bar",
				       NULL);
		msg_str = sipmsg_breakdown_get_string(4, &msgbd);

		assert_equal(response_sig, msg_str);

		g_free(msg_str);
		sipmsg_free(msgbd.msg);
		sipmsg_breakdown_free(&msgbd);
	}

	/* UUID tests - begin tests from MS-SIPRE */
	{
		const char *testEpid     = "01010101";
		const char *expectedUUID = "4b1682a8-f968-5701-83fc-7c6741dc6697";
		gchar *gotUUID           = generateUUIDfromEPID(testEpid);

		assert_equal(expectedUUID, gotUUID);

		g_free(gotUUID);
	}
}

int main(SIPE_UNUSED_PARAMETER int argc,
	 SIPE_UNUSED_PARAMETER char *argv[])
{
	/* Initialization for crypto backend (test mode) */
	sipe_crypto_init(FALSE);

	msg_tests();

	printf("Result: %d PASSED %d FAILED\n", succeeded, failed);
	return(failed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
