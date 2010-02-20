/**
 * @file tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
 *
 * Implemented with reference to the follow documentation:
 *   - http://davenport.sourceforge.net/ntlm.html
 *   - MS-NLMP: http://msdn.microsoft.com/en-us/library/cc207842.aspx
 *   - MS-SIP : http://msdn.microsoft.com/en-us/library/cc246115.aspx
 *
 * Build and run with (adjust as needed to your build platform!)
 *
 * $ gcc -I /usr/include/libpurple \
 *       -I /usr/include/dbus-1.0 -I /usr/lib/dbus-1.0/include \
 *       -I /usr/include/glib-2.0 -I /usr/lib/glib-2.0/include \
 *       -o tests tests.c sipe-sign.c sipmsg.c sip-sec.c uuid.c -lpurple
 * ./tests
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

#include <glib.h>
#include <stdlib.h>

#include "sipe-sign.h"
#include "sip-sec-ntlm.c"

#include "dbus-server.h"

#include "uuid.h"

static int successes = 0;
static int failures = 0;

void assert_equal(const char * expected, const guchar * got, int len, gboolean stringify)
{
	const gchar * res = (gchar *) got;
	gchar to_str[len*2];

	if (stringify) {
		int i, j;
		for (i = 0, j = 0; i < len; i++, j+=2) {
			g_sprintf(&to_str[j], "%02X", (got[i]&0xff));
		}
		len *= 2;
		res = to_str;
	}

	printf("expected: %s\n", expected);
	printf("received: %s\n", res);

	if (strncmp(expected, res, len) == 0) {
		successes++;
		printf("PASSED\n");
	} else {
		failures++;
		printf("FAILED\n");
	}
}

int main()
{
	printf ("Starting Tests\n");

	// Initialization that Pidgin would normally do
	g_type_init();
	purple_signals_init();
	purple_util_init();
	purple_debug_init();
	purple_dbus_init();
	purple_ciphers_init();

	/* These tests are from the MS-SIPE document */

	char * password = "Password";
	char * user = "User";
	char * domain = "Domain";
	guchar client_challenge [] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
	/* server challenge */
	guchar nonce [] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	/* 16 bytes */
	guchar exported_session_key[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

	printf ("\nTesting MD4()\n");
	guchar md4 [16];
	MD4 ((const unsigned char *)"message digest", 14, md4);
	assert_equal("D9130A8164549FE818874806E1C7014B", md4, 16, TRUE);

	printf ("\nTesting MD5()\n");
	guchar md5 [16];
	MD5 ((const unsigned char *)"message digest", 14, md5);
	assert_equal("F96B697D7CB7938D525A2F31AAF161D0", md5, 16, TRUE);

	printf ("\nTesting HMAC_MD5()\n");
	guchar hmac_md5 [16];
	HMAC_MD5 ((const unsigned char *)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16, (const unsigned char *)"Hi There", 8, hmac_md5);
	assert_equal("9294727A3638BB1C13F48EF8158BFC9D", hmac_md5, 16, TRUE);

	printf ("\nTesting LMOWFv1()\n");
	guchar response_key_lm [16];
	LMOWFv1 (password, user, domain, response_key_lm);
	assert_equal("E52CAC67419A9A224A3B108F3FA6CB6D", response_key_lm, 16, TRUE);

	printf ("\nTesting LM Response Generation\n");
	guchar lm_challenge_response [24];
	DESL (response_key_lm, nonce, lm_challenge_response);
	assert_equal("98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13", lm_challenge_response, 24, TRUE);

	printf ("\n\nTesting NTOWFv1()\n");
	guchar response_key_nt [16];
	NTOWFv1 (password, user, domain, response_key_nt);
	assert_equal("A4F49C406510BDCAB6824EE7C30FD852", response_key_nt, 16, TRUE);

	printf ("\n\nTesting NTOWFv2()\n");
	guchar response_key_nt_v2 [16];
	NTOWFv2 (password, user, domain, response_key_nt_v2);
	assert_equal("0C868A403BFD7A93A3001EF22EF02E3F", response_key_nt_v2, 16, TRUE);

	printf ("\nTesting NT Response Generation\n");
	guchar nt_challenge_response [24];
	DESL (response_key_nt, nonce, nt_challenge_response);
	assert_equal("67C43011F30298A2AD35ECE64F16331C44BDBED927841F94", nt_challenge_response, 24, TRUE);

	printf ("\n\nTesting Session Base Key and Key Exchange Generation\n");
	guchar session_base_key [16];
	MD4(response_key_nt, 16, session_base_key);
	guchar key_exchange_key [16];
	KXKEY(NEGOTIATE_FLAGS, session_base_key, lm_challenge_response, nonce, key_exchange_key);
	assert_equal("D87262B0CDE4B1CB7499BECCCDF10784", session_base_key, 16, TRUE);
	assert_equal("D87262B0CDE4B1CB7499BECCCDF10784", key_exchange_key, 16, TRUE);

	printf ("\n\nTesting Encrypted Session Key Generation\n");
	guchar encrypted_random_session_key [16];
	RC4K (key_exchange_key, exported_session_key, 16, encrypted_random_session_key);
	assert_equal("518822B1B3F350C8958682ECBB3E3CB7", encrypted_random_session_key, 16, TRUE);
//////
	guint32 flags = NEGOTIATE_FLAGS | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;	

	printf ("\n\n(Extended session seurity) Testing LM Response Generation\n");
	memcpy(lm_challenge_response, client_challenge, 8);
	Z (lm_challenge_response+8, 16);
	assert_equal("AAAAAAAAAAAAAAAA00000000000000000000000000000000", lm_challenge_response, 24, TRUE);

	printf ("\n\n(Extended session seurity) Testing Key Exchange\n");
	KXKEY(flags, session_base_key, lm_challenge_response, nonce, key_exchange_key);
	assert_equal("EB93429A8BD952F8B89C55B87F475EDC", key_exchange_key, 16, TRUE);	

	printf ("\n\n(Extended session seurity) Testing NT Response Generation\n");	
	unsigned char prehash [16];
	unsigned char hash [16];
	memcpy(prehash, nonce, 8);
	memcpy(prehash + 8, client_challenge, 8);
	MD5 (prehash, 16, hash);
	DESL (response_key_nt, hash, nt_challenge_response);
	assert_equal("7537F803AE367128CA458204BDE7CAF81E97ED2683267232", nt_challenge_response, 24, TRUE);

	/* End tests from the MS-SIPE document */

	// Test from http://davenport.sourceforge.net/ntlm.html#ntlm1Signing
	printf ("\n\nTesting Signature Algorithm\n");
	guchar sk [] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xe5, 0x38, 0xb0};
	assert_equal (
		"0100000078010900397420FE0E5A0F89",
		(guchar *) MAC(NEGOTIATE_FLAGS, "jCIFS", sk, 0x00090178, 0, 8),
		32, FALSE
	);

	// Verify signature of SIPE message received from OCS 2007 after authenticating with pidgin-sipe
	printf ("\n\nTesting MS-SIPE Example Message Signing\n");
	char * msg1 = "<NTLM><0878F41B><1><SIP Communications Service><ocs1.ocs.provo.novell.com><8592g5DCBa1694i5887m0D0Bt2247b3F38xAE9Fx><3><REGISTER><sip:gabriel@ocs.provo.novell.com><2947328781><B816D65C2300A32CFA6D371F2AF537FD><900><200>";
	guchar exported_session_key2 [] = { 0x5F, 0x02, 0x91, 0x53, 0xBC, 0x02, 0x50, 0x58, 0x96, 0x95, 0x48, 0x61, 0x5E, 0x70, 0x99, 0xBA };
	assert_equal (
		"0100000000000000BF2E52667DDF6DED",
		(guchar *) MAC(NEGOTIATE_FLAGS, msg1, exported_session_key2, 0, 100, 16),
		32, FALSE
	);

	// Verify parsing of message and signature verification
	printf ("\n\nTesting MS-SIPE Example Message Parsing, Signing, and Verification\n");
	char * msg2 = "SIP/2.0 200 OK\r\nms-keep-alive: UAS; tcp=no; hop-hop=yes; end-end=no; timeout=300\r\nAuthentication-Info: NTLM rspauth=\"0100000000000000BF2E52667DDF6DED\", srand=\"0878F41B\", snum=\"1\", opaque=\"4452DFB0\", qop=\"auth\", targetname=\"ocs1.ocs.provo.novell.com\", realm=\"SIP Communications Service\"\r\nFrom: \"Gabriel Burt\"<sip:gabriel@ocs.provo.novell.com>;tag=2947328781;epid=1234567890\r\nTo: <sip:gabriel@ocs.provo.novell.com>;tag=B816D65C2300A32CFA6D371F2AF537FD\r\nCall-ID: 8592g5DCBa1694i5887m0D0Bt2247b3F38xAE9Fx\r\nCSeq: 3 REGISTER\r\nVia: SIP/2.0/TLS 164.99.194.49:10409;branch=z9hG4bKE0E37DBAF252C3255BAD;received=164.99.195.20;ms-received-port=10409;ms-received-cid=1E00\r\nContact: <sip:164.99.195.20:10409;transport=tls;ms-received-cid=1E00>;expires=900\r\nExpires: 900\r\nAllow-Events: vnd-microsoft-provisioning,vnd-microsoft-roaming-contacts,vnd-microsoft-roaming-ACL,presence,presence.wpending,vnd-microsoft-roaming-self,vnd-microsoft-provisioning-v2\r\nSupported: adhoclist\r\nServer: RTC/3.0\r\nSupported: com.microsoft.msrtc.presence\r\nContent-Length: 0\r\n\r\n";
	struct sipmsg * msg = sipmsg_parse_msg(msg2);
	struct sipmsg_breakdown msgbd;
	msgbd.msg = msg;
	sipmsg_breakdown_parse(&msgbd, "SIP Communications Service", "ocs1.ocs.provo.novell.com");
	gchar * msg_str = sipmsg_breakdown_get_string(&msgbd);
	gchar * sig = purple_ntlm_sipe_signature_make (NEGOTIATE_FLAGS, msg_str, exported_session_key2);
	sipmsg_breakdown_free(&msgbd);
	assert_equal ("0100000000000000BF2E52667DDF6DED", (guchar *) sig, 32, FALSE);
	printf("purple_ntlm_verify_signature result = %i\n", purple_ntlm_verify_signature (sig, "0100000000000000BF2E52667DDF6DED"));


	/* begin tests from MS-SIPRE */

	const char *testEpid = "01010101";
	const char *expectedUUID = "4b1682a8-f968-5701-83fc-7c6741dc6697";
	gchar *calcUUID = generateUUIDfromEPID(testEpid);

	printf("\n\nTesting MS-SIPRE uuid derivation\n");
	
	assert_equal(expectedUUID, (guchar *) calcUUID, strlen(expectedUUID), FALSE);
	g_free(calcUUID);
	
	guchar addr[6];
	gchar nmac[6];
	
	int i,j;
	for (i = 0,j=0; i < 6; i++,j+=2) {
		g_sprintf(&nmac[j], "%02X", addr[i]);
	}

	printf("Mac: %s\n", g_strdup(nmac));

	/* end tests from MS-SIPRE */

	printf ("\nFinished With Tests; %d successs %d failures\n", successes, failures);

	return(0);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
