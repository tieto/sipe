/**
 * @file sip-ntlm.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 * Modify        2007, Anibal Avelar <debianmx@gmail.com>
 *
 * Implemented with reference to the follow documentation:
 *   - http://davenport.sourceforge.net/ntlm.html
 *   - MS-NLMP: http://msdn.microsoft.com/en-us/library/cc207842.aspx
 *   - MS-SIP : http://msdn.microsoft.com/en-us/library/cc246115.aspx
 *
 * hashing done according to description of NTLM on
 * http://www.innovation.ch/java/ntlm.html
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
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* _WIN32 */
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */
#include "network.h"
#include "internal.h"
#endif /* _WIN32 */

#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif /* HAVE_LANGINFO_CODESET */
#include <zlib.h>

#include "debug.h"
#include "util.h"
#include "cipher.h"
#include "sip-ntlm.h"

#define NTLM_NEGOTIATE_NTLM2_KEY 0x00080000

struct challenge_message {
	guint8  protocol[8];     /* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	guint8  type;            /* 0x02 */
	guint8  zero1[7];
	short   msg_len;         /* 0x28 */
	guint8  zero2[2];
	guint32 flags;           /* 0x8201 */

	guint8  nonce[8];
	guint8  zero[8];
};

struct authenticate_message {
	guint8  protocol[8];     /* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	//guint32 type;            /* 0x03 */
	guint8  type;            /* 0x03 */
	guint8  zero1[3];
	
	guint16 lm_resp_len1;    /* LanManager response length (always 0x18)*/
	guint16 lm_resp_len2;    /* LanManager response length (always 0x18)*/
	//guint32 lm_resp_off;     /* LanManager response offset */
	guint16 lm_resp_off;     /* LanManager response offset */
	guint8  zero2[2];

	/* NtChallengeResponseFields */
	guint16 nt_resp_len1;    /* NT response length (always 0x18) */
	guint16 nt_resp_len2;    /* NT response length (always 0x18) */
	//guint32 nt_resp_off;     /* NT response offset */
	guint16 nt_resp_off;     /* NT response offset */
	guint8  zero3[2];

	/* DomainNameFields */
	guint16 dom_len1;        /* domain string length */
	guint16 dom_len2;        /* domain string length */
	//guint32 dom_off;         /* domain string offset (always 0x40) */
	guint16 dom_off;         /* domain string offset (always 0x40) */
	guint8  zero4[2];

	/* UserNameFields */
	guint16 user_len1;       /* username string length */
	guint16 user_len2;       /* username string length */
	//guint32 user_off;        /* username string offset */
	guint16 user_off;        /* username string offset */
	guint8  zero5[2];

	/* WorkstationFields */
	guint16 host_len1;       /* host string length */
	guint16 host_len2;       /* host string length */
	//guint32 host_off;        /* host string offset */
	guint16 host_off;        /* host string offset */
	guint8  zero6[2];

	/* EncryptedRandomSessionKeyFields */
	guint16	sess_len1;
	guint16	sess_len2;
	//guint32 sess_off;
	guint16 sess_off;
	guint8  zero7[2];

	guint32 flags;

	// don't care values
	// version
	// mic

	// payload
/*	guint32  flags2;  unknown, used in windows messenger
	guint32  flags3; */

#if 0
	guint8  dom[*];          /* domain string (unicode UTF-16LE) */
	guint8  user[*];         /* username string (unicode UTF-16LE) */
	guint8  host[*];         /* host string (unicode UTF-16LE) */
	guint8  lm_resp[*];      /* LanManager response */
	guint8  nt_resp[*];      /* NT response */
#endif
};

/* Private Methods */

static void setup_des_key(const unsigned char key_56[], char *key)
{
	key[0] = key_56[0];
	key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
	key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
	key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
	key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
	key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
	key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
	key[7] =  (key_56[6] << 1) & 0xFF;
}

static void des_ecb_encrypt(const char *plaintext, char *result, const char *key)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gsize outlen;
	
	cipher = purple_ciphers_find_cipher("des");
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_set_key(context, (guchar*)key);
	purple_cipher_context_encrypt(context, (guchar*)plaintext, 8, (guchar*)result, &outlen);
	purple_cipher_context_destroy(context);
}

static int 
unicode_strconvcopy(char *dest, const char *source, int remlen)
{
	iconv_t fd;
	char *inbuf = (char *) source;
	char *outbuf = dest;
	size_t inbytes = strlen(source);
	size_t outbytes = remlen;
#ifdef HAVE_LANGINFO_CODESET
	char *sys_cp = nl_langinfo(CODESET);
#else
        char *sys_cp = SIPE_DEFAULT_CODESET;
#endif /* HAVE_LANGINFO_CODESET */

	/* fall back to utf-8 */
	if (!sys_cp) sys_cp = "UTF8";

	fd = iconv_open("UTF16LE", sys_cp);
	iconv(fd, &inbuf, &inbytes, &outbuf, &outbytes);
	iconv_close(fd);
	return (remlen - outbytes);
}

// (k = 7 byte key, d = 8 byte data) returns 8 bytes in results
void
DES (const char *k, const char *d, char * results)
{
	char key[8];
	setup_des_key(k, key);
	des_ecb_encrypt(d, results, key);
}

// (K = 21 byte key, D = 8 bytes of data) returns 24 bytes in results:
void
DESL (char *k, const char *d, char * results)
{
	char keys[21];

	// Copy the first 16 bytes
	memcpy(keys, k, 16);

	// Zero out the last 5 bytes of the key
	memset(keys + 16, 0, 5);

	DES(keys,      d, results);
	DES(keys + 7,  d, results + 8);
	DES(keys + 14, d, results + 16);
}

void
MD4 (const char * d, int len, char * result)
{
	PurpleCipher * cipher = purple_ciphers_find_cipher("md4");
	PurpleCipherContext * context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar*)d, len);
	purple_cipher_context_digest(context, MD4_DIGEST_LEN, (guchar*)result, NULL);
	purple_cipher_context_destroy(context);
}


void
NTOWFv1 (const char* password, const char *user, const char *domain, char * result)
{
	int len = 2 * strlen(password); // utf16 should not be more
	char *unicode_password = g_new0(char, len);

	len = unicode_strconvcopy(unicode_password, password, len);
	MD4 (unicode_password, len, result);
	g_free(unicode_password);
}

void
MD5 (const char * d, int len, char * result)
{
	PurpleCipher * cipher = purple_ciphers_find_cipher("md5");
	PurpleCipherContext * context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar*)d, len);
	purple_cipher_context_digest(context, len, (guchar*)result, NULL);
	purple_cipher_context_destroy(context);
}

void
RC4K (const char * k, const char * d, char * result)
{
	PurpleCipherContext * context = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(context, "key_len", (gpointer)16);
	purple_cipher_context_set_key(context, k);
	purple_cipher_context_encrypt(context, (const guchar *)d, 16, result, NULL);
	purple_cipher_context_destroy(context);
}

void
KXKEY (const char * session_base_key, const char * lm_challenge_resonse, char * key_exchange_key)
{
	// Assume v1 and NTLMSSP_REQUEST_NON_NT_SESSION_KEY not set
	memcpy(key_exchange_key, session_base_key, 16);
}

// This method is only used for NTLM v2 session security w/ enhanced security negotiated
/*void
SIGNKEY (const char * random_session_key, gboolean client, char * result)
{
	char * magic = client
		? "session key to client-to-server signing key magic constant"
		: "session key to server-to-client signing key magic constant";

	int len = strlen(magic);
	char md5_input [16 + len];
	memcpy(md5_input, random_session_key, 16);
	memcpy(md5_input + 16, magic, len);

	MD5 (md5_input, len + 16, result);
}*/

void
LMOWFv1 (const char *password, const char *user, const char *domain, char *result)
{
	/* "KGS!@#$%" */
	unsigned char magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
	char uppercase_password[14];

	int len = strlen(password);
	if (len > 14) {
		len = 14;
	}

	// Uppercase password
	int i;
	for (i = 0; i < len; i++) {
		uppercase_password[i] = g_ascii_toupper(password[i]);
	}
 
	// Zero the rest
	for (; i < 14; i++) {
		uppercase_password[i] = 0;
	}
	
	DES (uppercase_password, magic, result);
	DES (uppercase_password + 7, magic, result + 8);
}

static void
NONCE(char *buffer, int num)
{
	int i;
	for (i = 0; i < num; i++) {
		buffer[i] = (char)(rand() & 0xff);
	}
}

/* End Private Methods */

gchar *purple_ntlm_parse_challenge(gchar *challenge, guint32 *flags) {
	gsize retlen;
	static gchar nonce[8];
	struct challenge_message *tmsg = (struct challenge_message*)purple_base64_decode((char*)challenge, &retlen);
	memcpy(nonce, tmsg->nonce, 8);

	purple_debug_info("sipe", "received NTLM NegotiateFlags = %X; OK? %i\n", tmsg->flags, tmsg->flags & NEGOTIATE_FLAGS == NEGOTIATE_FLAGS);

	if (flags) {
		*flags = tmsg->flags;
	}
	g_free(tmsg);
	return nonce;
}

void
print_hex_array(char * msg, int num)
{
	int k;
	for (k = 0; k < num; k++) {
		printf("0x%02X, ", msg[k]&0xff);
	}
	printf("\n");
}

void
print_hex_array_title(char * title, char * msg, int num)
{
	printf("%s:\n", title);
	print_hex_array(msg, num);
}

long
CRC32 (char * msg)
{
	long crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, msg, strlen(msg));
	char * ptr = (char*) &crc;
	//return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | (ptr[3] & 0xff);
	return crc;
}

gchar *
purple_ntlm_gen_signature (char * buf, char * signing_key, guint32 random_pad, long sequence, int key_len)
{
	gint32 plaintext [] = {0, CRC32(buf), sequence};

	guchar result [16];
	PurpleCipherContext *rc4 = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(rc4, "key_len", (gpointer)key_len);
	purple_cipher_context_set_key(rc4, signing_key);
	purple_cipher_context_encrypt(rc4, (const guchar *)plaintext, 12, result+4, NULL);
	purple_cipher_context_destroy(rc4);

	gint32 * res_ptr = (gint32 *)result;
	// Highest four bytes are the Version
	res_ptr[0] = 0x00000001;

	// Replace the first four bytes of the ciphertext with a counter value
	// currently set to this hardcoded value
	res_ptr[1] = random_pad;

	gchar signature [32];
	int i, j;
	for (i = 0, j = 0; i < 16; i++, j+=2) {
		g_sprintf(&signature[j], "%02X", result[i]);
	}

	//printf("sig: %s\n", signature);
	return g_strdup(signature);
}

gchar *
purple_ntlm_sipe_signature_make (char * msg, char * signing_key)
{
	return purple_ntlm_gen_signature(msg, signing_key, 0, 100, 16);
}

gboolean
purple_ntlm_verify_signature (char * a, char * b)
{
	// Make sure the last 16 bytes match
	gboolean ret = strncmp(a + 16, b + 16, 16) == 0;
	return ret;
}

gchar *
purple_ntlm_gen_authenticate(const gchar **ntlm_key, const gchar *user, const gchar *password, const gchar *hostname, const gchar *domain, const guint8 *nonce, guint32 *flags)
{
	int msglen = sizeof(struct authenticate_message) + 2*(strlen(domain)
				+ strlen(user)+ strlen(hostname) + NTLMSSP_NT_OR_LM_KEY_LEN)
				+ NTLMSSP_SESSION_KEY_LEN;
	struct authenticate_message *tmsg = g_malloc0(msglen);
	char *tmp;
	int remlen;

	/* authenticate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = 3;

	/* Set Negotiate Flags */
	tmsg->flags = NEGOTIATE_FLAGS;

	/* Domain */
	tmsg->dom_off = sizeof(struct authenticate_message);
	tmp = ((char*) tmsg) + tmsg->dom_off;
	remlen = ((char *)tmsg)+msglen-tmp;
	tmsg->dom_len1 = tmsg->dom_len2 = unicode_strconvcopy(tmp, domain, remlen);
	tmp += tmsg->dom_len1;
	remlen = ((char *)tmsg)+msglen-tmp;

	/* User */
	tmsg->user_off = tmsg->dom_off + tmsg->dom_len1;
	tmsg->user_len1 = tmsg->user_len2 = unicode_strconvcopy(tmp, user, remlen);
	tmp += tmsg->user_len1;
	remlen = ((char *)tmsg)+msglen-tmp;

	/* Host */
	tmsg->host_off = tmsg->user_off + tmsg->user_len1;
	tmsg->host_len1 = tmsg->host_len2 = unicode_strconvcopy(tmp, hostname, remlen);
	tmp += tmsg->host_len1;

	/* LM */
	tmsg->lm_resp_len1 = tmsg->lm_resp_len2 = NTLMSSP_NT_OR_LM_KEY_LEN;
	tmsg->lm_resp_off = tmsg->host_off + tmsg->host_len1;

	char response_key_lm [16];
	LMOWFv1 (password, user, domain, response_key_lm);
	char lm_challenge_response [NTLMSSP_NT_OR_LM_KEY_LEN];
	DESL (response_key_lm, nonce, lm_challenge_response);
	memcpy(tmp, lm_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* NT */
	tmsg->nt_resp_len1 = tmsg->nt_resp_len2 = NTLMSSP_NT_OR_LM_KEY_LEN;
	tmsg->nt_resp_off = tmsg->lm_resp_off + tmsg->lm_resp_len1;

	char response_key_nt [16];
	NTOWFv1 (password, user, domain, response_key_nt);
	char nt_challenge_response [NTLMSSP_NT_OR_LM_KEY_LEN];
	DESL (response_key_nt, nonce, nt_challenge_response);
	memcpy(tmp, nt_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* Session Key */
	tmsg->sess_len1 = tmsg->sess_len2 = NTLMSSP_SESSION_KEY_LEN;
	tmsg->sess_off = tmsg->nt_resp_off + tmsg->nt_resp_len1;

	char session_base_key [16];
	MD4(response_key_nt, 16, session_base_key);

	char key_exchange_key [16];
	KXKEY(session_base_key, lm_challenge_response, key_exchange_key);

	char exported_session_key[16];
	NONCE (exported_session_key, 16);

	*ntlm_key = g_strndup (exported_session_key, 16);

	char encrypted_random_session_key [16];
	RC4K (key_exchange_key, exported_session_key, encrypted_random_session_key);
	memcpy(tmp, encrypted_random_session_key, 16);
	tmp += NTLMSSP_SESSION_KEY_LEN;

	tmp = purple_base64_encode((guchar*) tmsg, msglen);
	purple_debug_info("sipe", "Generated NTLM AUTHENTICATE message\n");
	g_free(tmsg);
	return tmp;
}
