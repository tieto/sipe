#include <glib.h>
#include <stdlib.h>
#include <zlib.h>

#include "sip-internal.h"
#include "sip-ntlm.c"

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
	char nonce [] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	char exported_session_key[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

	printf ("\nTesting LMOWFv1()\n");
	char response_key_lm [16];
	LMOWFv1 (password, user, domain, response_key_lm);
	printf("E52CAC67419A9A224A3B108F3FA6CB6D\n");
	print_hex_array(response_key_lm, 16);

	printf ("\nTesting LM Response Generation\n");
	char lm_challenge_response [24];
	DESL (response_key_lm, nonce, lm_challenge_response);
	printf("98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13\n");
	print_hex_array(lm_challenge_response, 24);

	printf ("\n\nTesting NTOWFv1()\n");
	char response_key_nt [16];
	NTOWFv1 (password, user, domain, response_key_nt);
	printf("A4F49C406510BDCAB6824EE7C30FD852\n");
	print_hex_array(response_key_nt, 16);

	printf ("\nTesting NT Response Generation\n");
	char nt_challenge_response [24];
	DESL (response_key_nt, nonce, nt_challenge_response);
	printf("67C43011F30298A2AD35ECE64F16331C44BDBED927841F94\n");
	print_hex_array(nt_challenge_response, 24);

	printf ("\n\nTesting Session Base Key and Key Exchange Generation\n");
	char session_base_key [16];
	MD4(response_key_nt, 16, session_base_key);
	char key_exchange_key [16];
	KXKEY(session_base_key, lm_challenge_response, key_exchange_key);
	printf("D87262B0CDE4B1CB7499BECCCDF10784\n");
	print_hex_array(session_base_key, 16);
	print_hex_array(key_exchange_key, 16);

	printf ("\n\nTesting Encrypted Session Key Generation\n");
	char encrypted_random_session_key [16];
	RC4K (key_exchange_key, exported_session_key, encrypted_random_session_key);
	printf("518822B1B3F350C8958682ECBB3E3CB7\n");
	print_hex_array(encrypted_random_session_key, 16);

	/* End tests from the MS-SIPE document */

	// Test from http://davenport.sourceforge.net/ntlm.html#ntlm1Signing
	printf ("\n\nTesting Signature Algorithm\n");
	char sk [] = {0x01, 0x02, 0x03, 0x04, 0x05, 0xe5, 0x38, 0xb0};
	purple_ntlm_signature_gen ("jCIFS", sk, 0, 0, "0100000078010900397420FE0E5A0F89", 8);


	// Test signing of SIPE message
	printf ("\n\nTesting SIPE Message Signing\n");
	char signing_key [] = {0x2C, 0x9F, 0x5B, 0x3C, 0x95, 0x12, 0x70, 0xFF, 0x4D, 0x64, 0x85, 0x4D, 0x7C, 0x2E, 0x53, 0x8B};
	char * msg1 = "<NTLM><F09C1A30><1><SIP Communications Service><ocs1.ocs.provo.novell.com><813CgE29BaFA37i186Bm8CC3t1A2AbDB34x0A66x><3><REGISTER><sip:gabriel@ocs.provo.novell.com><5628647192><B816D65C2300A32CFA6D371F2AF537FD><900><200>";
	char * rsp = "0100000000000000787BB2B9B80C5CEA";
	guint32 random_pad = 0xF09C1A30;
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 100, rsp, 5);
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 100, rsp, 8);
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 100, rsp, 16);
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 0, rsp, 5);
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 0, rsp, 8);
	purple_ntlm_signature_gen (msg1, signing_key, random_pad, 0, rsp, 16);


	printf ("\nFinished With Tests\n");
}
