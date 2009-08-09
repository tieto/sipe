/**
 * @file sip-sec-ntlm.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@kinozal.tv>
 * Copyright (C) 2008 Novell, Inc.
 * Modify        2007, Anibal Avelar <avelar@gmail.com>
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
 *
 * Implemented with reference to the follow documentation:
 *   - http://davenport.sourceforge.net/ntlm.html
 *   - MS-NLMP: http://msdn.microsoft.com/en-us/library/cc207842.aspx
 *   - MS-SIP : http://msdn.microsoft.com/en-us/library/cc246115.aspx
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
#include <glib/gprintf.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* _WIN32 */
#include "libc_interface.h"
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */
#include "network.h"
#include "internal.h"
#endif /* _WIN32 */

#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif /* HAVE_LANGINFO_CODESET */

#include "util.h"
#include "cipher.h"

#include "sipe-utils.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-ntlm.h"


/***********************************************
 *
 * Start of merged code from original sip-ntlm.c
 *
 ***********************************************/

/* Negotiate flag required in connectionless NTLM
 *   0x00000001 = NTLMSSP_NEGOTIATE_UNICODE	(A)
 *   0x00000010 = NTLMSSP_NEGOTIATE_SIGN	(D)
 *   0x00000040 = NTLMSSP_NEGOTIATE_DATAGRAM	(F)
 *   0x00000200 = NTLMSSP_NEGOTIATE_NTLM	(H)
 *   0x00008000 = NTLMSSP_NEGOTIATE_ALWAYS_SIGN (M)
 *   0x40000000 = NTLMSSP_NEGOTIATE_KEY_EXCH	(W)
 */
#define NEGOTIATE_FLAGS 0x40008251
#define NTLM_NEGOTIATE_NTLM2_KEY 0x00080000

#define NTLMSSP_NT_OR_LM_KEY_LEN 24
#define NTLMSSP_SESSION_KEY_LEN  16
#define MD4_DIGEST_LEN 16

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

#ifndef HAVE_LANGINFO_CODESET
static char SIPE_DEFAULT_CODESET[] = "ANSI_X3.4-1968";
#endif

/* Private Methods */

static void setup_des_key(const unsigned char key_56[], unsigned char *key)
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

static void des_ecb_encrypt(const unsigned char *plaintext, unsigned char *result, const unsigned char *key)
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
unicode_strconvcopy(gchar *dest, const gchar *source, int remlen)
{
	GIConv fd;
	gchar *inbuf = (gchar *) source;
	gchar *outbuf = dest;
	size_t inbytes = strlen(source);
	size_t outbytes = remlen;
#ifdef HAVE_LANGINFO_CODESET
	char *sys_cp = nl_langinfo(CODESET);
#else
        char *sys_cp = SIPE_DEFAULT_CODESET;
#endif /* HAVE_LANGINFO_CODESET */

	/* fall back to utf-8 */
	if (!sys_cp) sys_cp = "UTF-8";

	fd = g_iconv_open("UTF-16LE", sys_cp);
	if( fd == (GIConv)-1 ) {
		purple_debug_error( "sipe", "iconv_open returned -1, cannot continue\n" );
	}
	g_iconv(fd, &inbuf, &inbytes, &outbuf, &outbytes);
	g_iconv_close(fd);
	return (remlen - outbytes);
}

// (k = 7 byte key, d = 8 byte data) returns 8 bytes in results
static void
DES (const unsigned char *k, const unsigned char *d, unsigned char * results)
{
	unsigned char key[8];
	setup_des_key(k, key);
	des_ecb_encrypt(d, results, key);
}

// (K = 21 byte key, D = 8 bytes of data) returns 24 bytes in results:
static void
DESL (unsigned char *k, const unsigned char *d, unsigned char * results)
{
	unsigned char keys[21];

	// Copy the first 16 bytes
	memcpy(keys, k, 16);

	// Zero out the last 5 bytes of the key
	memset(keys + 16, 0, 5);

	DES(keys,      d, results);
	DES(keys + 7,  d, results + 8);
	DES(keys + 14, d, results + 16);
}

static void
MD4 (const unsigned char * d, int len, unsigned char * result)
{
	PurpleCipher * cipher = purple_ciphers_find_cipher("md4");
	PurpleCipherContext * context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar*)d, len);
	purple_cipher_context_digest(context, MD4_DIGEST_LEN, (guchar*)result, NULL);
	purple_cipher_context_destroy(context);
}


static void
NTOWFv1 (const char* password, SIPE_UNUSED_PARAMETER const char *user, SIPE_UNUSED_PARAMETER const char *domain, unsigned char * result)
{
	int len = 2 * strlen(password); // utf16 should not be more
	unsigned char *unicode_password = g_new0(unsigned char, len);

	len = unicode_strconvcopy((gchar *) unicode_password, password, len);
	MD4 (unicode_password, len, result);
	g_free(unicode_password);
}

// static void
// MD5 (const char * d, int len, char * result)
// {
	// PurpleCipher * cipher = purple_ciphers_find_cipher("md5");
	// PurpleCipherContext * context = purple_cipher_context_new(cipher, NULL);
	// purple_cipher_context_append(context, (guchar*)d, len);
	// purple_cipher_context_digest(context, len, (guchar*)result, NULL);
	// purple_cipher_context_destroy(context);
// }

static void
RC4K (const unsigned char * k, const unsigned char * d, unsigned char * result)
{
	PurpleCipherContext * context = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(context, "key_len", (gpointer)16);
	purple_cipher_context_set_key(context, k);
	purple_cipher_context_encrypt(context, (const guchar *)d, 16, result, NULL);
	purple_cipher_context_destroy(context);
}

static void
KXKEY (const unsigned char * session_base_key, SIPE_UNUSED_PARAMETER const unsigned char * lm_challenge_resonse, unsigned char * key_exchange_key)
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

static void
LMOWFv1 (const char *password, SIPE_UNUSED_PARAMETER const char *user, SIPE_UNUSED_PARAMETER const char *domain, unsigned char *result)
{
	/* "KGS!@#$%" */
	unsigned char magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
	unsigned char uppercase_password[14];
	int i;

	int len = strlen(password);
	if (len > 14) {
		len = 14;
	}

	// Uppercase password
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
NONCE(unsigned char *buffer, int num)
{
	int i;
	for (i = 0; i < num; i++) {
		buffer[i] = (rand() & 0xff);
	}
}

/* End Private Methods */

static gchar *purple_ntlm_parse_challenge(const char *challenge, guint32 *flags) {
	gsize retlen;
	static gchar nonce[8];
	struct challenge_message *tmsg = (struct challenge_message*)purple_base64_decode(challenge, &retlen);
	memcpy(nonce, tmsg->nonce, 8);

	purple_debug_info("sipe", "received NTLM NegotiateFlags = %X; OK? %i\n", tmsg->flags, (tmsg->flags & NEGOTIATE_FLAGS) == NEGOTIATE_FLAGS);

	if (flags) {
		*flags = tmsg->flags;
	}
	g_free(tmsg);
	return nonce;
}

// static void
// print_hex_array(char * msg, int num)
// {
	// int k;
	// for (k = 0; k < num; k++) {
		// printf("0x%02X, ", msg[k]&0xff);
	// }
	// printf("\n");
// }

// static void
// print_hex_array_title(char * title, char * msg, int num)
// {
	// printf("%s:\n", title);
	// print_hex_array(msg, num);
// }

/* source copy from gg's common.c */
static guint32 crc32_table[256];
static int crc32_initialized = 0;

static void crc32_make_table()
{
	guint32 h = 1;
	unsigned int i, j;

	memset(crc32_table, 0, sizeof(crc32_table));

	for (i = 128; i; i >>= 1) {
		h = (h >> 1) ^ ((h & 1) ? 0xedb88320L : 0);

		for (j = 0; j < 256; j += 2 * i)
			crc32_table[i + j] = crc32_table[j] ^ h;
	}

	crc32_initialized = 1;
}

static guint32 crc32(guint32 crc, const guint8 *buf, int len)
{
	if (!crc32_initialized)
		crc32_make_table();

	if (!buf || len < 0)
		return crc;

	crc ^= 0xffffffffL;

	while (len--)
		crc = (crc >> 8) ^ crc32_table[(crc ^ *buf++) & 0xff];

	return crc ^ 0xffffffffL;
}

static guint32
CRC32 (const char * msg)
{
	guint32 crc = 0L;//crc32(0L, Z_NULL, 0);
	crc = crc32(crc, (guint8 *) msg, strlen(msg));
	//char * ptr = (char*) &crc;
	//return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | (ptr[3] & 0xff);
	return crc;
}

static gchar *
purple_ntlm_gen_signature (const char * buf, unsigned char * signing_key, guint32 random_pad, long sequence, int key_len)
{
	gint32 *res_ptr;
	gint32 plaintext [] = {0, CRC32(buf), sequence};

	guchar result [16];
	gchar signature [32];
	int i, j;
	PurpleCipherContext *rc4 = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(rc4,"key_len", GINT_TO_POINTER(key_len));
      
	purple_cipher_context_set_key(rc4, signing_key);
	purple_cipher_context_encrypt(rc4, (const guchar *)plaintext, 12, result+4, NULL);
	purple_cipher_context_destroy(rc4);

	res_ptr = (gint32 *)result;
	// Highest four bytes are the Version
	res_ptr[0] = 0x00000001;

	// Replace the first four bytes of the ciphertext with a counter value
	// currently set to this hardcoded value
	res_ptr[1] = random_pad;

	for (i = 0, j = 0; i < 16; i++, j+=2) {
		g_sprintf(&signature[j], "%02X", result[i]);
	}

	//printf("sig: %s\n", signature);
	return g_strdup(signature);
}

static gchar *
purple_ntlm_sipe_signature_make (const char * msg, unsigned char * signing_key)
{
	return purple_ntlm_gen_signature(msg, signing_key, 0, 100, 16);
}

static gboolean
purple_ntlm_verify_signature (char * a, char * b)
{
	// Make sure the last 16 bytes match
	gboolean ret = g_ascii_strncasecmp(a + 16, b + 16, 16) == 0;
	return ret;
}

static gchar *
purple_ntlm_gen_authenticate(guchar **ntlm_key, const gchar *user, const gchar *password, const gchar *hostname, const gchar *domain, const guint8 *nonce, SIPE_UNUSED_PARAMETER guint32 *flags)
{
	int msglen = sizeof(struct authenticate_message) + 2*(strlen(domain)
				+ strlen(user)+ strlen(hostname) + NTLMSSP_NT_OR_LM_KEY_LEN)
				+ NTLMSSP_SESSION_KEY_LEN;
	struct authenticate_message *tmsg = g_malloc0(msglen);
	char *tmp;
	int remlen;
	unsigned char response_key_lm [16];
	unsigned char lm_challenge_response [NTLMSSP_NT_OR_LM_KEY_LEN];
	unsigned char response_key_nt [16];
	unsigned char nt_challenge_response [NTLMSSP_NT_OR_LM_KEY_LEN];
	unsigned char session_base_key [16];
	unsigned char key_exchange_key [16];
	unsigned char exported_session_key[16];
	unsigned char encrypted_random_session_key [16];

	/* authenticate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = 3;

	/* Set Negotiate Flags */
	tmsg->flags = NEGOTIATE_FLAGS;

	/* Domain */
	tmsg->dom_off = sizeof(struct authenticate_message);
	tmp = ((char*) tmsg) + sizeof(struct authenticate_message);
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

	LMOWFv1 (password, user, domain, response_key_lm);
	DESL (response_key_lm, nonce, lm_challenge_response);
	memcpy(tmp, lm_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* NT */
	tmsg->nt_resp_len1 = tmsg->nt_resp_len2 = NTLMSSP_NT_OR_LM_KEY_LEN;
	tmsg->nt_resp_off = tmsg->lm_resp_off + tmsg->lm_resp_len1;

	NTOWFv1 (password, user, domain, response_key_nt);
	DESL (response_key_nt, nonce, nt_challenge_response);
	memcpy(tmp, nt_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* Session Key */
	tmsg->sess_len1 = tmsg->sess_len2 = NTLMSSP_SESSION_KEY_LEN;
	tmsg->sess_off = tmsg->nt_resp_off + tmsg->nt_resp_len1;

	MD4(response_key_nt, 16, session_base_key);

	KXKEY(session_base_key, lm_challenge_response, key_exchange_key);

	NONCE (exported_session_key, 16);

	*ntlm_key = (guchar *) g_strndup ((gchar *) exported_session_key, 16);

	RC4K (key_exchange_key, exported_session_key, encrypted_random_session_key);
	memcpy(tmp, encrypted_random_session_key, 16);
	tmp += NTLMSSP_SESSION_KEY_LEN;

	tmp = purple_base64_encode(exported_session_key, 16);
	purple_debug_info("sipe", "Generated NTLM AUTHENTICATE message (%s)\n", tmp);
	g_free(tmp);

	tmp = purple_base64_encode((guchar*) tmsg, msglen);
	g_free(tmsg);
	return tmp;
}

/***********************************************
 *
 * End of merged code from original sip-ntlm.c
 *
 ***********************************************/

/* sip-sec-mech.h API implementation for NTLM */

/* Security context for NTLM */
typedef struct _context_ntlm {
	struct sip_sec_context common;
	char* domain;
	char *username;
	char *password;
	int step;
	guchar *key;
} *context_ntlm;


static sip_uint32
sip_sec_acquire_cred__ntlm(SipSecContext context,
			   const char *domain,
			   const char *username,
			   const char *password)
{
	context_ntlm ctx = (context_ntlm)context;
	
	ctx->domain   = strdup(domain);
	ctx->username = strdup(username);
	ctx->password = strdup(password);

	return SIP_SEC_E_OK;
}

static sip_uint32
sip_sec_init_sec_context__ntlm(SipSecContext context,
			  SipSecBuffer in_buff,
			  SipSecBuffer *out_buff,
			  SIPE_UNUSED_PARAMETER const char *service_name)
{
	context_ntlm ctx = (context_ntlm) context;
	
	purple_debug_info("sipe", "sip_sec_init_sec_context__ntlm: in use\n");

	ctx->step++;
	if (ctx->step == 1) {
		out_buff->length = 0;
		out_buff->value = NULL;
		// same behaviour as sspi
		return SIP_SEC_I_CONTINUE_NEEDED;

	} else 	{
		guchar *ntlm_key;
		guchar *nonce;
		guint32 flags;
		gchar *input_toked_base64;
		gchar *gssapi_data;

		input_toked_base64 = purple_base64_encode(in_buff.value,
							  in_buff.length);

		nonce = g_memdup(purple_ntlm_parse_challenge(input_toked_base64, &flags), 8);
		g_free(input_toked_base64);

		gssapi_data = purple_ntlm_gen_authenticate(&ntlm_key,
							   ctx->username,
							   ctx->password,
							   sipe_get_host_name(),
							   ctx->domain,
							   nonce,
							   &flags);
		g_free(nonce);

		out_buff->value = purple_base64_decode(gssapi_data, &(out_buff->length));
		g_free(gssapi_data);

		g_free(ctx->key);
		ctx->key = ntlm_key;
		return SIP_SEC_E_OK;
	}
}

/**
 * @param message a NULL terminated string to sign
 *
 */
static sip_uint32
sip_sec_make_signature__ntlm(SipSecContext context,
			const char *message,
			SipSecBuffer *signature)
{
	gchar *signature_hex = purple_ntlm_sipe_signature_make(message,
							       ((context_ntlm) context)->key);

	hex_str_to_bytes(signature_hex, signature);
	g_free(signature_hex);

	return SIP_SEC_E_OK;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return SIP_SEC_E_OK on success
 */
static sip_uint32
sip_sec_verify_signature__ntlm(SipSecContext context,
			  const char *message,
			  SipSecBuffer signature)
{
	char *signature_hex = bytes_to_hex_str(&signature);
	gchar *signature_calc = purple_ntlm_sipe_signature_make(message,
								((context_ntlm) context)->key);
	sip_uint32 res;

	if (purple_ntlm_verify_signature(signature_calc, signature_hex)) {
		res = SIP_SEC_E_OK;
	} else {
		res = SIP_SEC_E_INTERNAL_ERROR;
	}
	g_free(signature_calc);
	g_free(signature_hex);
	return(res);
}

static void
sip_sec_destroy_sec_context__ntlm(SipSecContext context)
{
	context_ntlm ctx = (context_ntlm) context;

	g_free(ctx->domain);
	g_free(ctx->username);
	g_free(ctx->password);
	g_free(ctx->key);
	g_free(ctx);
}

SipSecContext
sip_sec_create_context__ntlm(SIPE_UNUSED_PARAMETER SipSecAuthType type)
{
	context_ntlm context = g_malloc0(sizeof(struct _context_ntlm));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__ntlm;
	context->common.init_context_func     = sip_sec_init_sec_context__ntlm;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__ntlm;
	context->common.make_signature_func   = sip_sec_make_signature__ntlm;
	context->common.verify_signature_func = sip_sec_verify_signature__ntlm;

	return((SipSecContext) context);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
