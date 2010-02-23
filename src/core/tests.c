/**
 * @file tests.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
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

#ifndef _WIN32
#include "dbus-server.h"
#endif

#include "uuid.h"

static int successes = 0;
static int failures = 0;

static void assert_equal(const char * expected, const guchar * got, int len, gboolean stringify)
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

	if (g_ascii_strncasecmp(expected, res, len) == 0) {
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
#ifndef _WIN32
	g_type_init();
#endif
	purple_signals_init();
	purple_util_init();
	purple_debug_init();
#ifndef _WIN32
	purple_dbus_init();
#endif
	purple_ciphers_init();
	purple_debug_set_enabled(TRUE);

	/* These tests are from the MS-SIPE document */

	const char * password = "Password";
	const char * user = "User";
	const char * domain = "Domain";
	const guchar client_challenge [] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
	/* server challenge */
	const guchar nonce [] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	/* 16 bytes */
	const guchar exported_session_key[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
	const guchar text [] = {0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00}; //P·l·a·i·n·t·e·x·t·


////// internal Cyphers tests ///////
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


////// NTLMv1 (without Extended Session Security) ///////	
	use_ntlm_v2 = FALSE;
	guint32 flags = 0
		| NTLMSSP_NEGOTIATE_KEY_EXCH
		| NTLMSSP_NEGOTIATE_56
		| NTLMSSP_NEGOTIATE_128
		| NTLMSSP_NEGOTIATE_VERSION
		| NTLMSSP_TARGET_TYPE_SERVER
		| NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_NEGOTIATE_NTLM
		| NTLMSSP_NEGOTIATE_SEAL
		| NTLMSSP_NEGOTIATE_SIGN
		| NTLMSSP_NEGOTIATE_OEM
		| NTLMSSP_NEGOTIATE_UNICODE;
		
	printf ("\n\nTesting Negotiation Flags\n");
	assert_equal("338202E2", (guchar*)(&flags), 4, TRUE);

	printf ("\n\nTesting LMOWFv1()\n");
	guchar response_key_lm [16];
	LMOWFv1 (password, user, domain, response_key_lm);
	assert_equal("E52CAC67419A9A224A3B108F3FA6CB6D", response_key_lm, 16, TRUE);

	printf ("\n\nTesting NTOWFv1()\n");
	guchar response_key_nt [16];
	NTOWFv1 (password, user, domain, response_key_nt);
	assert_equal("A4F49C406510BDCAB6824EE7C30FD852", response_key_nt, 16, TRUE);
	
	printf ("\n\nTesting LM Response Generation\n");
	printf ("Testing NT Response Generation\n");
	printf ("Testing Session Base Key\n");
	guchar nt_challenge_response [24];
	guchar lm_challenge_response [24];
	guchar session_base_key [16];

	compute_response(flags,
			 response_key_nt,
			 response_key_lm,
			 nonce,
			 client_challenge,
			 0,
			 NULL, /* target_info */
			 0,  /* target_info_len */
			 lm_challenge_response,	/* out */
			 nt_challenge_response,	/* out */
			 session_base_key);	/* out */

	assert_equal("98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13", lm_challenge_response, 24, TRUE);
	assert_equal("67C43011F30298A2AD35ECE64F16331C44BDBED927841F94", nt_challenge_response, 24, TRUE);
	assert_equal("D87262B0CDE4B1CB7499BECCCDF10784", session_base_key, 16, TRUE);

	printf ("\n\nTesting Key Exchange Key\n");
	guchar key_exchange_key [16];
	KXKEY(flags, session_base_key, lm_challenge_response, nonce, key_exchange_key);
	assert_equal("D87262B0CDE4B1CB7499BECCCDF10784", key_exchange_key, 16, TRUE);

	printf ("\n\nTesting Encrypted Session Key Generation\n");
	guchar encrypted_random_session_key [16];
	RC4K (key_exchange_key, 16, exported_session_key, 16, encrypted_random_session_key);
	assert_equal("518822B1B3F350C8958682ECBB3E3CB7", encrypted_random_session_key, 16, TRUE);

	printf ("\n\nTesting CRC32\n");
	gint32 crc = CRC32((char*)text, 18);
	assert_equal("7D84AA93", (guchar *)&crc, 4, TRUE);

	printf ("\n\nTesting Encryption\n");
	guchar client_seal_key [16];
	//SEALKEY (flags, exported_session_key, TRUE, client_seal_key);
	guchar buff [18 + 12];
	memcpy(buff, text, 18);
	guchar text_enc [18 + 12];
	guint32 *ptr = (guint32 *)(buff + 18);
	ptr[0] = 0; // random pad
	ptr[1] = crc;
	ptr[2] = 0; // zero
	RC4K (exported_session_key, 16, buff, 18 + 12, text_enc);
	//The point is to not reinitialize rc4 cypher
	//                                                   0          crc        0 (zero)
	assert_equal("56FE04D861F9319AF0D7238A2E3B4D457FB8" "45C844E5" "09DCD1DF" "2E459D36", text_enc, 18 + 12, TRUE);

	printf ("\n\nTesting MAC\n");
	// won't work in the case with sealing because RC4 is re-initialized inside.
	//gchar *mac = MAC (flags, (gchar*)text, 18, (guchar*)exported_session_key, 16, (guchar*)exported_session_key,16,  0x00000000,  0);
	ptr = (guint32 *)(text_enc + 18);	
	guint32 mac2 [4];
	mac2 [0] = 1; // version
	mac2 [1] = ptr [0];
	mac2 [2] = ptr [1];
	mac2 [3] = ptr [2] ^ ((guint32)0); // ^ seq
	assert_equal("0100000045C844E509DCD1DF2E459D36", (guchar*)mac2, 16, TRUE);


////// EXTENDED_SESSIONSECURITY ///////
	use_ntlm_v2 = FALSE;
	flags = 0
		| NTLMSSP_NEGOTIATE_56
		| NTLMSSP_NEGOTIATE_VERSION
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		| NTLMSSP_TARGET_TYPE_SERVER
		| NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_NEGOTIATE_NTLM
		| NTLMSSP_NEGOTIATE_SEAL
		| NTLMSSP_NEGOTIATE_SIGN
		| NTLMSSP_NEGOTIATE_OEM
		| NTLMSSP_NEGOTIATE_UNICODE;

	printf ("\n\n(Extended session security) Testing Negotiation Flags\n");
	assert_equal("33820A82", (guchar*)(&flags), 4, TRUE);
	
	/* NTOWFv1() is not different from the above test for the same */
	
	printf ("\n\n(Extended session security) Testing LM Response\n");
	printf ("(Extended session security) Testing NT Response\n");
	printf ("(Extended session security) Testing Session Base Key\n");
	compute_response(flags,
			 response_key_nt,
			 response_key_lm,
			 nonce,
			 client_challenge,
			 0,
			 NULL, /* target_info */
			 0,  /* target_info_len */
			 lm_challenge_response,	/* out */
			 nt_challenge_response,	/* out */
			 session_base_key);	/* out */
			 
	assert_equal("AAAAAAAAAAAAAAAA00000000000000000000000000000000", lm_challenge_response, 24, TRUE);
	assert_equal("7537F803AE367128CA458204BDE7CAF81E97ED2683267232", nt_challenge_response, 24, TRUE);
	assert_equal("D87262B0CDE4B1CB7499BECCCDF10784", session_base_key, 16, TRUE);
	
	printf ("\n\n(Extended session seurity) Testing Key Exchange Key\n");
	KXKEY(flags, session_base_key, lm_challenge_response, nonce, key_exchange_key);
	assert_equal("EB93429A8BD952F8B89C55B87F475EDC", key_exchange_key, 16, TRUE);
	
	printf ("\n\n(Extended session security) SIGNKEY\n");
	guchar client_sign_key [16];
	SIGNKEY (key_exchange_key, TRUE, client_sign_key);
	assert_equal("60E799BE5C72FC92922AE8EBE961FB8D", client_sign_key, 16, TRUE);

	printf ("\n\n(Extended session security) SEALKEY\n");
	SEALKEY (flags, key_exchange_key, TRUE, client_seal_key);
	assert_equal("04DD7F014D8504D265A25CC86A3A7C06", client_seal_key, 16, TRUE);

	printf ("\n\n(Extended session security) Testing Encryption\n");
	RC4K (client_seal_key, 16, text, 18, text_enc);
	assert_equal("A02372F6530273F3AA1EB90190CE5200C99D", text_enc, 18, TRUE);

	printf ("\n\n(Extended session security) Testing MAC\n");
	gchar *mac = MAC (flags,   (gchar*)text,18,   client_sign_key,16,   client_seal_key,16,   0,  0);
	assert_equal("01000000FF2AEB52F681793A00000000", (guchar*)mac, 32, FALSE);
	g_free(mac);


////// NTLMv2 ///////
	use_ntlm_v2 = TRUE;
	flags = 0
		| NTLMSSP_NEGOTIATE_KEY_EXCH
		| NTLMSSP_NEGOTIATE_56
		| NTLMSSP_NEGOTIATE_128
		| NTLMSSP_NEGOTIATE_VERSION
		| NTLMSSP_NEGOTIATE_TARGET_INFO
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		| NTLMSSP_TARGET_TYPE_SERVER
		| NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_NEGOTIATE_NTLM
		| NTLMSSP_NEGOTIATE_SEAL
		| NTLMSSP_NEGOTIATE_SIGN
		| NTLMSSP_NEGOTIATE_OEM
		| NTLMSSP_NEGOTIATE_UNICODE;

	printf ("\n\nTesting (NTLMv2) Negotiation Flags\n");
	assert_equal("33828AE2", (guchar*)(&flags), 4, TRUE);

	printf ("\n\nTesting NTOWFv2()\n");
	NTOWFv2 (password, user, domain, response_key_nt);
	NTOWFv2 (password, user, domain, response_key_lm);
	assert_equal("0C868A403BFD7A93A3001EF22EF02E3F", response_key_nt, 16, TRUE);


	printf ("\n\nTesting (NTLMv2) LM Response Generation\n");
	printf ("Testing (NTLMv2) NT Response Generation and Session Base Key\n");
/*
Challenge:
4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef00000000000000002400240044000000060070170000000f53006500720076006500720002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000

        NTLMSSP_NEGOTIATE_UNICODE
        NTLMSSP_NEGOTIATE_OEM
        NTLMSSP_NEGOTIATE_SIGN
        NTLMSSP_NEGOTIATE_SEAL
        NTLMSSP_NEGOTIATE_NTLM
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        NTLMSSP_TARGET_TYPE_SERVER
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        NTLMSSP_NEGOTIATE_TARGET_INFO
        NTLMSSP_NEGOTIATE_VERSION
        NTLMSSP_NEGOTIATE_128
        NTLMSSP_NEGOTIATE_KEY_EXCH
        NTLMSSP_NEGOTIATE_56
        target_name.len   : 12
        target_name.maxlen: 12
        target_name.offset: 56
        target_info.len   : 36
        target_info.maxlen: 36
        target_info.offset: 68
        product: 6.0.6000 (Windows Vista, Windows Server 2008, Windows 7 or Windows Server 2008 R2)
        ntlm_revision_current: 0x0F (NTLMSSP_REVISION_W2K3)
        target_name: Server
        MsvAvNbDomainName: Domain
        MsvAvNbComputerName: Server

target_name:
530065007200760065007200
target_info:
02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000

Response:
4e544c4d5353500003000000180018006c00000054005400840000000c000c00480000000800080054000000100010005c00000010001000d8000000358288e20501280a0000000f44006f006d00610069006e00550073006500720043004f004d005000550054004500520086c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000c5dad2544fc9799094ce1ce90bc9d03e


*/
	const guint64 time_val = 0;
	const gchar target_info [] = {
		0x02, 0x00, 0x0C, 0x00, //NetBIOS Domain name, 4 bytes
		0x44, 0x00, 0x6F, 0x00, 0x6D, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6E, 0x00, //D.o.m.a.i.n.  12bytes
		0x01, 0x00, 0x0C, 0x00, //NetBIOS Server name, 4 bytes
		0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, //S.e.r.v.e.r.  12bytes
		0x00, 0x00, 0x00, 0x00, //Av End, 4 bytes
		};
	const int target_info_len = 32+4;
	int ntlmssp_nt_resp_len = (16 + (32+target_info_len));
	guchar nt_challenge_response_v2 [ntlmssp_nt_resp_len];

	compute_response(flags,
			 response_key_nt,
			 response_key_lm,
			 nonce,
			 client_challenge,
			 time_val,
			 target_info, /* target_info */
			 target_info_len,  /* target_info_len */
			 lm_challenge_response,	/* out */
			 nt_challenge_response_v2,	/* out */
			 session_base_key);	/* out */

	assert_equal("86C35097AC9CEC102554764A57CCCC19AAAAAAAAAAAAAAAA", lm_challenge_response, 24, TRUE);		 
	assert_equal("68CD0AB851E51C96AABC927BEBEF6A1C", nt_challenge_response_v2, 16, TRUE);
	/* the ref string is taken from binary dump of AUTHENTICATE_MESSAGE */
	assert_equal("68CD0AB851E51C96AABC927BEBEF6A1C01010000000000000000000000000000AAAAAAAAAAAAAAAA0000000002000C0044006F006D00610069006E0001000C005300650072007600650072000000000000000000", nt_challenge_response_v2, ntlmssp_nt_resp_len, TRUE);
	assert_equal("8DE40CCADBC14A82F15CB0AD0DE95CA3", session_base_key, 16, TRUE);
	
	printf ("\n\nTesting (NTLMv2) Encrypted Session Key\n");
	// key_exchange_key = session_base_key for NTLMv2
	KXKEY(flags, session_base_key, lm_challenge_response, nonce, key_exchange_key);
	//RC4 encryption of the RandomSessionKey with the KeyExchangeKey:
	RC4K (key_exchange_key, 16, exported_session_key, 16, encrypted_random_session_key);
	assert_equal("C5DAD2544FC9799094CE1CE90BC9D03E", encrypted_random_session_key, 16, TRUE);
	
	printf ("\n\nTesting (NTLMv2) SIGNKEY\n");
	SIGNKEY (exported_session_key, TRUE, client_sign_key);
	assert_equal("4788DC861B4782F35D43FD98FE1A2D39", client_sign_key, 16, TRUE);

	printf ("\n\nTesting (NTLMv2) SEALKEY\n");
	SEALKEY (flags, exported_session_key, TRUE, client_seal_key);
	assert_equal("59F600973CC4960A25480A7C196E4C58", client_seal_key, 16, TRUE);

	printf ("\n\nTesting (NTLMv2) Encryption\n");
	RC4K (client_seal_key, 16, text, 18, text_enc);
	assert_equal("54E50165BF1936DC996020C1811B0F06FB5F", text_enc, 18, TRUE);

//	printf ("\n\nTesting (NTLMv2) Encryption\n");
//const guchar text2 [] = {0x50, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x74, 0x00, 0x65, 0x00, 0x78, 0x00, 0x74, 0x00
//			, 0x70, 0x35, 0x28, 0x51, 0xf2, 0x56, 0x43, 0x09}; //P·l·a·i·n·t·e·x·t·
//guchar text_enc2 [18+8];
//	RC4K (client_seal_key, 16, text2, 18+8, text_enc2);
//	assert_equal("54E50165BF1936DC996020C1811B0F06FB5F", text_enc2, 18+8, TRUE);

	printf ("\n\nTesting (NTLMv2) MAC (without RC4, as we don't keep its handle yet)\n");
	mac = MAC (flags & ~NTLMSSP_NEGOTIATE_KEY_EXCH,   (gchar*)text,18,   client_sign_key,16,   client_seal_key,16,   0,  0);
	assert_equal("0100000070352851F256430900000000", (guchar*)mac, 32, FALSE);
	g_free(mac);


	/* End tests from the MS-SIPE document */


////// davenport tests ///////
	// Test from http://davenport.sourceforge.net/ntlm.html#ntlm1Signing
	const gchar *text_j = "jCIFS";
	printf ("\n\n(davenport) Testing Signature Algorithm\n");
	guchar sk [] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xe5, 0x38, 0xb0};
	assert_equal (
		"0100000078010900397420FE0E5A0F89",
		(guchar *) MAC(NEGOTIATE_FLAGS, text_j, strlen(text_j), sk, 8,  sk,8,  0x00090178, 0),
		32, FALSE
	);

	// Tests from http://davenport.sourceforge.net/ntlm.html#ntlm2Signing
	printf ("\n\n(davenport) SIGNKEY\n");
	const guchar master_key [] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
	SIGNKEY (master_key, TRUE, client_sign_key);
	assert_equal("F7F97A82EC390F9C903DAC4F6ACEB132", client_sign_key, 16, TRUE);

	printf ("\n\n(davenport) Testing MAC - no Key Exchange flag\n");
	mac = MAC (flags & ~NTLMSSP_NEGOTIATE_KEY_EXCH, text_j, strlen(text_j), client_sign_key, 16,  client_sign_key,16,  0,  0);
	assert_equal("010000000A003602317A759A00000000", (guchar*)mac, 32, FALSE);
	g_free(mac);


////// SIPE internal tests ///////
	// Verify signature of SIPE message received from OCS 2007 after authenticating with pidgin-sipe
	printf ("\n\nTesting MS-SIPE Example Message Signing\n");
	char * msg1 = "<NTLM><0878F41B><1><SIP Communications Service><ocs1.ocs.provo.novell.com><8592g5DCBa1694i5887m0D0Bt2247b3F38xAE9Fx><3><REGISTER><sip:gabriel@ocs.provo.novell.com><2947328781><B816D65C2300A32CFA6D371F2AF537FD><900><200>";
	guchar exported_session_key2 [] = { 0x5F, 0x02, 0x91, 0x53, 0xBC, 0x02, 0x50, 0x58, 0x96, 0x95, 0x48, 0x61, 0x5E, 0x70, 0x99, 0xBA };
	assert_equal (
		"0100000000000000BF2E52667DDF6DED",
		(guchar *) MAC(NEGOTIATE_FLAGS, msg1, strlen(msg1), exported_session_key2, 16,  exported_session_key2,16,  0, 100),
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
	gchar * sig = purple_ntlm_sipe_signature_make (NEGOTIATE_FLAGS, msg_str, 0, exported_session_key2, exported_session_key2);
	sipmsg_breakdown_free(&msgbd);
	assert_equal ("0100000000000000BF2E52667DDF6DED", (guchar *) sig, 32, FALSE);
	printf("purple_ntlm_verify_signature result = %i\n", purple_ntlm_verify_signature (sig, "0100000000000000BF2E52667DDF6DED"));


////// UUID tests ///////
	/* begin tests from MS-SIPRE */

	const char *testEpid = "01010101";
	const char *expectedUUID = "4b1682a8-f968-5701-83fc-7c6741dc6697";
	gchar *calcUUID = generateUUIDfromEPID(testEpid);

	printf("\n\nTesting MS-SIPRE UUID derivation\n");

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
