/**
 * @file sip-sec-ntlm.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009, 2010 pier11 <pier11@operamail.com>
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

#include "sipe.h"
#include "sipe-utils.h"
#include "sip-sec-mech.h"
#include "sip-sec-ntlm.h"

/* [MS-NLMP] */
#define NTLMSSP_NEGOTIATE_UNICODE			0x00000001	/* A  */
#define NTLMSSP_NEGOTIATE_OEM				0x00000002	/* B  */
#define NTLMSSP_REQUEST_TARGET				0x00000004	/* C  */
#define r9						0x00000008	/* r9 */
#define NTLMSSP_NEGOTIATE_SIGN				0x00000010	/* D  */
#define NTLMSSP_NEGOTIATE_SEAL				0x00000020	/* E  */
#define NTLMSSP_NEGOTIATE_DATAGRAM			0x00000040	/* F  */
#define NTLMSSP_NEGOTIATE_LM_KEY			0x00000080	/* G  */
#define r8						0x00000100	/* r8 */
#define NTLMSSP_NEGOTIATE_NTLM				0x00000200	/* H  */
#define NTLMSSP_NEGOTIATE_NT_ONLY			0x00000400	/* I  */
#define anonymous					0x00000800	/* J  */
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED		0x00001000	/* K  */
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED	0x00002000	/* L  */
#define r7						0x00004000	/* r7 */
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN			0x00008000	/* M  */
#define NTLMSSP_TARGET_TYPE_DOMAIN			0x00010000	/* N  */
#define NTLMSSP_TARGET_TYPE_SERVER			0x00020000	/* O  */
#define r6						0x00040000	/* r6 */
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY	0x00080000	/* P  */
#define NTLMSSP_NEGOTIATE_IDENTIFY			0x00100000	/* Q  */
#define r5						0x00200000	/* r5 */
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY		0x00400000	/* R  */
#define NTLMSSP_NEGOTIATE_TARGET_INFO			0x00800000	/* S  */
#define r4						0x01000000	/* r4 */
#define NTLMSSP_NEGOTIATE_VERSION			0x02000000	/* T  */
#define r3						0x04000000	/* r3 */
#define r2						0x08000000	/* r2 */
#define r1						0x10000000	/* r1 */
#define NTLMSSP_NEGOTIATE_128				0x20000000	/* U  */
#define NTLMSSP_NEGOTIATE_KEY_EXCH			0x40000000	/* V  */
#define NTLMSSP_NEGOTIATE_56				0x80000000	/* W  */

/* AvId */
#define MsvAvEOL		0
#define MsvAvNbComputerName	1
#define MsvAvNbDomainName	2
#define MsvAvDnsComputerName	3
#define MsvAvDnsDomainName	4
/** @since Windows XP */
#define MsvAvDnsTreeName	5
/** @since Windows XP */
#define MsvAvFlags		6
/** @since Windows Vista */
#define MsvAvTimestamp		7
/** @since Windows Vista */
#define MsAvRestrictions	8
/** @since Windows 7 */
#define MsvAvTargetName		9
/** @since Windows 7 */
#define MsvChannelBindings	10

/***********************************************
 *
 * Start of merged code from original sip-ntlm.c
 *
 ***********************************************/

/* Negotiate flags required in connection-oriented NTLM */
#define NEGOTIATE_FLAGS_CONN \
	( NTLMSSP_NEGOTIATE_UNICODE | \
	  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | \
	  NTLMSSP_REQUEST_TARGET | \
	  NTLMSSP_NEGOTIATE_NTLM | \
	  NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
	  0)

/* Negotiate flags required in connectionless NTLM */
#define NEGOTIATE_FLAGS \
	( NTLMSSP_NEGOTIATE_UNICODE | \
	  NTLMSSP_NEGOTIATE_SIGN | \
	  NTLMSSP_NEGOTIATE_DATAGRAM | \
	  NTLMSSP_NEGOTIATE_NTLM | \
	  NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
	  NTLMSSP_NEGOTIATE_KEY_EXCH )

#define NTLM_NEGOTIATE_NTLM2_KEY 0x00080000

#define NTLMSSP_NT_OR_LM_KEY_LEN 24
#define NTLMSSP_SESSION_KEY_LEN  16
#define MD4_DIGEST_LEN 16

struct av_pair {
	guint16 av_id;
	guint16 av_len;
	/* value */
};

/* 8 bytes */
struct version {
	guint8  product_major_version;
	guint8  product_minor_version;
	guint16 product_build;
	guint8  zero2[3];
	guint8  ntlm_revision_current;
};

/* 8 bytes */
struct smb_header {
	guint16 len;
	guint16 maxlen;
	guint32 offset;
};

struct ntlm_message {
	guint8  protocol[8];     /* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	guint32 type;            /* 0x00000003 */
};

struct negotiate_message {
	guint8  protocol[8];		/* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0' */
	guint32 type;			/* 0x00000001 */
	guint32 flags;			/* 0xb203 */
	struct smb_header domain;
	struct smb_header host;
	struct version ver;
	/* payload
	 * - DomainName		(always ASCII)
	 * - WorkstationName	(always ASCII)
	 */
};

struct challenge_message {
	guint8  protocol[8];		/* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	guint32 type;			/* 0x00000002 */
	struct smb_header target_name;
	guint32 flags;			/* 0x8201 */
	guint8  nonce[8];
	guint8  zero1[8];
	struct smb_header target_info;
	struct version ver;
	/* payload
	 * - TargetName						(negotiated encoding)
	 * - TargetInfo (a sequence of AV_PAIR structures)	(always Unicode)
	 */
};

struct authenticate_message {
	guint8  protocol[8];     /* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	guint32 type;            /* 0x00000003 */
	/** LmChallengeResponseFields */
	struct smb_header lm_resp;
	/** NtChallengeResponseFields */
	struct smb_header nt_resp;
	/** DomainNameFields */
	struct smb_header domain;
	/** UserNameFields */
	struct smb_header user;
	/** WorkstationFields */
	struct smb_header host;
	/** EncryptedRandomSessionKeyFields */
	struct smb_header session_key;
	guint32 flags;
	struct version ver;
	guint8  mic[16];
	/* payload
	 * - LmChallengeResponse
	 * - NtChallengeResponse
	 * - DomainName			(negotiated encoding)
	 * - UserName			(negotiated encoding)
	 * - Workstation		(negotiated encoding)
	 * - EncryptedRandomSessionKey
	 */
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
	size_t outlen;

	cipher = purple_ciphers_find_cipher("des");
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_set_key(context, (guchar*)key);
	purple_cipher_context_encrypt(context, (guchar*)plaintext, 8, (guchar*)result, &outlen);
	purple_cipher_context_destroy(context);
}

static int
unicode_strconvcopy_dir(gchar *dest, const gchar *source, int remlen, gsize source_len, gboolean to_16LE)
{
	GIConv fd;
	gchar *inbuf = (gchar *) source;
	gchar *outbuf = dest;
	gsize inbytes = source_len;
	gsize outbytes = remlen;
#ifdef HAVE_LANGINFO_CODESET
	char *sys_cp = nl_langinfo(CODESET);
#else
        char *sys_cp = SIPE_DEFAULT_CODESET;
#endif /* HAVE_LANGINFO_CODESET */

	/* fall back to utf-8 */
	if (!sys_cp) sys_cp = "UTF-8";

	fd = to_16LE ? g_iconv_open("UTF-16LE", sys_cp) : g_iconv_open(sys_cp, "UTF-16LE");
	if( fd == (GIConv)-1 ) {
		purple_debug_error( "sipe", "iconv_open returned -1, cannot continue\n" );
	}
	g_iconv(fd, &inbuf, &inbytes, &outbuf, &outbytes);
	g_iconv_close(fd);
	return (remlen - outbytes);
}

static int
unicode_strconvcopy(gchar *dest, const gchar *source, int remlen)
{
	return unicode_strconvcopy_dir(dest, source, remlen, strlen(source), TRUE);
}

/* UTF-16LE to native encoding
 * Must be g_free'd after use */
static gchar *
unicode_strconvcopy_back(const gchar *source,
			 int len)
{
	char *res = NULL;
	int dest_len = 2 * len;
	gchar *dest = g_new0(gchar, dest_len);

	dest_len = unicode_strconvcopy_dir(dest, source, dest_len, len, FALSE);
	res = g_strndup(dest, dest_len);
	g_free(dest);

	return res;
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
MD5 (const unsigned char * d, int len, unsigned char * result)
{
	PurpleCipher * cipher = purple_ciphers_find_cipher("md5");
	PurpleCipherContext * context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar*)d, len);
	purple_cipher_context_digest(context, len, (guchar*)result, NULL);
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

static void
RC4K (const unsigned char * k, const unsigned char * d, unsigned char * result)
{
	PurpleCipherContext * context = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(context, "key_len", GUINT_TO_POINTER(16));
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

static void
Z(unsigned char *buffer, int num)
{
	int i;
	for (i = 0; i < num; i++) {
		buffer[i] = 0;
	}
}

/* End Private Methods */

static gchar *
sip_sec_ntlm_challenge_message_describe(struct challenge_message *cmsg);

static gchar *
purple_ntlm_parse_challenge(SipSecBuffer in_buff,
			    gboolean is_connection_based,
			    guint32 *flags)
{
	guint32 our_flags = is_connection_based ? NEGOTIATE_FLAGS_CONN : NEGOTIATE_FLAGS;
	static gchar nonce[8];
	struct challenge_message *cmsg = (struct challenge_message*)in_buff.value;

	memcpy(nonce, cmsg->nonce, 8);

	purple_debug_info("sipe", "received NTLM NegotiateFlags = %X; OK? %i\n", cmsg->flags, (cmsg->flags & our_flags) == our_flags);

	if (flags) {
		*flags = cmsg->flags;
	}
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
purple_ntlm_gen_signature (const char * buf, unsigned char * signing_key, guint32 random_pad, long sequence, unsigned long key_len)
{
	gint32 *res_ptr;
	gint32 plaintext [] = {0, CRC32(buf), sequence};

	guchar result [16];
	gchar signature [33];
	int i, j;
	PurpleCipherContext *rc4 = purple_cipher_context_new_by_name("rc4", NULL);
	purple_cipher_context_set_option(rc4, "key_len", GUINT_TO_POINTER(key_len));

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

#define IS_FLAG(flags, flag) ((neg_flags & flag) == flag)

static void
purple_ntlm_gen_authenticate(guchar **ntlm_key,
			     const gchar *user,
			     const gchar *password,
			     const gchar *hostname,
			     const gchar *domain,
			     const guint8 *nonce,
			     gboolean is_connection_based,
			     SipSecBuffer *out_buff,
			     SIPE_UNUSED_PARAMETER guint32 *flags)
{
	guint32 neg_flags = is_connection_based ? NEGOTIATE_FLAGS_CONN : NEGOTIATE_FLAGS;
	gboolean is_key_exch = IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_KEY_EXCH);
	int msglen = sizeof(struct authenticate_message) + 2*(strlen(domain)
				+ strlen(user)+ strlen(hostname) + NTLMSSP_NT_OR_LM_KEY_LEN)
				+ (is_key_exch ? NTLMSSP_SESSION_KEY_LEN : 0);
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

	NTOWFv1 (password, user, domain, response_key_nt);
	LMOWFv1 (password, user, domain, response_key_lm);

	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_LM_KEY)) {
		// @TODO do not even reference nt_challenge_response
		Z (nt_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
		DESL (response_key_lm, nonce, lm_challenge_response);
	} else if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
		unsigned char client_challenge [8];
		unsigned char z16 [16];
		unsigned char prehash [16];
		unsigned char hash [16];

		NONCE (client_challenge, 8);

		/* nt_challenge_response */
		memcpy(prehash, nonce, 8);
		memcpy(prehash + 8, client_challenge, 8);
		MD5 (prehash, 16, hash);
		DESL (response_key_nt, hash, nt_challenge_response);

		/* lm_challenge_response */
		Z (z16, 16);
		memcpy(lm_challenge_response, client_challenge, 8);
		memcpy(lm_challenge_response + 8, z16, 16);
	} else {
		DESL (response_key_nt, nonce, nt_challenge_response);
		if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_NT_ONLY)) {
			memcpy(lm_challenge_response, nt_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
		} else {
			DESL (response_key_lm, nonce, lm_challenge_response);
		}
	}

	/* authenticate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = 3;

	/* Set Negotiate Flags */
	tmsg->flags = neg_flags;

	/* Domain */
	tmsg->domain.offset = sizeof(struct authenticate_message);
	tmp = ((char*) tmsg) + sizeof(struct authenticate_message);
	remlen = ((char *)tmsg)+msglen-tmp;
	tmsg->domain.len = tmsg->domain.maxlen = unicode_strconvcopy(tmp, domain, remlen);
	tmp += tmsg->domain.len;
	remlen = ((char *)tmsg)+msglen-tmp;

	/* User */
	tmsg->user.offset = tmsg->domain.offset + tmsg->domain.len;
	tmsg->user.len = tmsg->user.maxlen = unicode_strconvcopy(tmp, user, remlen);
	tmp += tmsg->user.len;
	remlen = ((char *)tmsg)+msglen-tmp;

	/* Host */
	tmsg->host.offset = tmsg->user.offset + tmsg->user.len;
	tmsg->host.len = tmsg->host.maxlen = unicode_strconvcopy(tmp, hostname, remlen);
	tmp += tmsg->host.len;

	/* LM */
	tmsg->lm_resp.len = tmsg->lm_resp.maxlen = NTLMSSP_NT_OR_LM_KEY_LEN;
	tmsg->lm_resp.offset = tmsg->host.offset + tmsg->host.len;
	memcpy(tmp, lm_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* NT */
	tmsg->nt_resp.len = tmsg->nt_resp.maxlen = NTLMSSP_NT_OR_LM_KEY_LEN;
	tmsg->nt_resp.offset = tmsg->lm_resp.offset + tmsg->lm_resp.len;
	memcpy(tmp, nt_challenge_response, NTLMSSP_NT_OR_LM_KEY_LEN);
	tmp += NTLMSSP_NT_OR_LM_KEY_LEN;

	/* Session Key */
	MD4(response_key_nt, 16, session_base_key);
	KXKEY(session_base_key, lm_challenge_response, key_exchange_key);

	if (is_key_exch)
	{
		tmsg->session_key.len = tmsg->session_key.maxlen = NTLMSSP_SESSION_KEY_LEN;
		tmsg->session_key.offset = tmsg->nt_resp.offset + tmsg->nt_resp.len;

		NONCE (exported_session_key, 16);
		RC4K (key_exchange_key, exported_session_key, encrypted_random_session_key);

		memcpy(tmp, encrypted_random_session_key, 16);
		tmp += NTLMSSP_SESSION_KEY_LEN;
	}
	else
	{
		tmsg->session_key.len = tmsg->session_key.maxlen = 0;
		tmsg->session_key.offset = tmsg->nt_resp.offset + tmsg->nt_resp.len;

		memcpy(exported_session_key, key_exchange_key, 16);
	}

	*ntlm_key = (guchar *)g_strndup((gchar *)exported_session_key, 16);

	tmp = purple_base64_encode(exported_session_key, 16);
	purple_debug_info("sipe", "Generated NTLM AUTHENTICATE session key: %s\n", tmp);
	g_free(tmp);

	out_buff->value = tmsg;
	out_buff->length = msglen;
}

/**
 * Generates Type 1 (Negotiate) message for connection-oriented cases (only)
 */
static void
purple_ntlm_gen_negotiate(SipSecBuffer *out_buff)
{
	int msglen = sizeof(struct negotiate_message);
	struct negotiate_message *tmsg = g_malloc0(msglen);

	/* negotiate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = 1;

	/* Set Negotiate Flags */
	tmsg->flags = NEGOTIATE_FLAGS_CONN;

	/* Domain */
	tmsg->domain.offset = sizeof(struct negotiate_message);
	tmsg->domain.len = tmsg->domain.maxlen = 0;

	/* Host */
	tmsg->host.offset = tmsg->domain.offset + tmsg->domain.len;
	tmsg->host.len = tmsg->host.maxlen = 0;

	/* Version */
	//tmsg->ver.product_major_version = 5;	/* 5.1.2600 (Windows XP SP2) */
	//tmsg->ver.product_minor_version = 1;
	//tmsg->ver.product_build = 2600;
	//tmsg->ver.ntlm_revision_current = 0x0F;	/* NTLMSSP_REVISION_W2K3 */

	out_buff->value = tmsg;
	out_buff->length = msglen;
}

/***********************************************
 *
 * End of merged code from original sip-ntlm.c
 *
 ***********************************************/

#define APPEND_NEG_FLAG(str, flags, flag, desc)	\
	if ((flags & flag) == flag) g_string_append_printf(str, "\t%s\n", desc);

static gchar *
sip_sec_ntlm_negotiate_flags_describe(guint32 flags)
{
	GString* str = g_string_new(NULL);

	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_UNICODE, "NTLMSSP_NEGOTIATE_UNICODE");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_OEM, "NTLMSSP_NEGOTIATE_OEM");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_REQUEST_TARGET, "NTLMSSP_REQUEST_TARGET");
	APPEND_NEG_FLAG(str, flags, r9, "r9");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_SIGN, "NTLMSSP_NEGOTIATE_SIGN");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_SEAL, "NTLMSSP_NEGOTIATE_SEAL");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_DATAGRAM, "NTLMSSP_NEGOTIATE_DATAGRAM");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_LM_KEY, "NTLMSSP_NEGOTIATE_LM_KEY");
	APPEND_NEG_FLAG(str, flags, r8, "r8");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_NTLM, "NTLMSSP_NEGOTIATE_NTLM");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_NT_ONLY, "NTLMSSP_NEGOTIATE_NT_ONLY");
	APPEND_NEG_FLAG(str, flags, anonymous, "anonymous");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED");
	APPEND_NEG_FLAG(str, flags, r7, "r7");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_ALWAYS_SIGN, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_TARGET_TYPE_DOMAIN, "NTLMSSP_TARGET_TYPE_DOMAIN");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_TARGET_TYPE_SERVER, "NTLMSSP_TARGET_TYPE_SERVER");
	APPEND_NEG_FLAG(str, flags, r6, "r6");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_IDENTIFY, "NTLMSSP_NEGOTIATE_IDENTIFY");
	APPEND_NEG_FLAG(str, flags, r5, "r5");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_REQUEST_NON_NT_SESSION_KEY, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_TARGET_INFO, "NTLMSSP_NEGOTIATE_TARGET_INFO");
	APPEND_NEG_FLAG(str, flags, r4, "r4");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_VERSION, "NTLMSSP_NEGOTIATE_VERSION");
	APPEND_NEG_FLAG(str, flags, r3, "r3");
	APPEND_NEG_FLAG(str, flags, r2, "r2");
	APPEND_NEG_FLAG(str, flags, r1, "r1");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_128, "NTLMSSP_NEGOTIATE_128");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_KEY_EXCH, "NTLMSSP_NEGOTIATE_KEY_EXCH");
	APPEND_NEG_FLAG(str, flags, NTLMSSP_NEGOTIATE_56, "NTLMSSP_NEGOTIATE_56");

	return g_string_free(str, FALSE);
}

#define AV_DESC(av, av_value, av_len, av_name) \
gchar *tmp = unicode_strconvcopy_back(av_value, av_len); \
g_string_append_printf(str, "\t%s: %s\n", av_name, tmp); \
g_free(tmp);

static gchar *
sip_sec_ntlm_describe_version(struct version *ver) {
	GString* str = g_string_new(NULL);
	gchar *ver_desc = "";
	gchar *ntlm_revision_desc = "";

	if (ver->product_major_version == 6) {
		ver_desc = "Windows Vista, Windows Server 2008, Windows 7 or Windows Server 2008 R2";
	} else if (ver->product_major_version == 5 && ver->product_minor_version == 2) {
		ver_desc = "Windows Server 2003";
	} else if (ver->product_major_version == 5 && ver->product_minor_version == 1) {
		ver_desc = "Windows XP SP2";
	}

	if (ver->ntlm_revision_current == 0x0F) {
		ntlm_revision_desc = "NTLMSSP_REVISION_W2K3";
	} else if (ver->ntlm_revision_current == 0x0A) {
		ntlm_revision_desc = "NTLMSSP_REVISION_W2K3_RC1";
	}

	g_string_append_printf(str, "\tproduct: %d.%d.%d (%s)\n",
		ver->product_major_version, ver->product_minor_version, ver->product_build, ver_desc);
	g_string_append_printf(str, "\tntlm_revision_current: 0x%02X (%s)\n", ver->ntlm_revision_current, ntlm_revision_desc);

	return g_string_free(str, FALSE);
}

static gchar *
sip_sec_ntlm_describe_smb_header(struct smb_header *header,
				 const char* name)
{
	GString* str = g_string_new(NULL);

	g_string_append_printf(str, "\t%s.len   : %d\n", name, header->len);
	g_string_append_printf(str, "\t%s.maxlen: %d\n", name, header->maxlen);
	g_string_append_printf(str, "\t%s.offset: %d\n", name, header->offset);

	return g_string_free(str, FALSE);
}

static gchar *
sip_sec_ntlm_negotiate_message_describe(struct negotiate_message *cmsg)
{
	GString* str = g_string_new(NULL);
	char *tmp;

	g_string_append(str, (tmp = sip_sec_ntlm_negotiate_flags_describe(cmsg->flags)));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->domain), "domain")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->host), "host")));
	g_free(tmp);

	tmp = sip_sec_ntlm_describe_version(&(cmsg->ver));
	g_string_append(str, tmp);
	g_free(tmp);

	if (cmsg->domain.len && cmsg->domain.offset) {
		gchar *domain = g_strndup(((gchar *)cmsg + cmsg->domain.offset), cmsg->domain.len);
		g_string_append_printf(str, "\tdomain: %s\n", domain);
		g_free(domain);
	}

	if (cmsg->host.len && cmsg->host.offset) {
		gchar *host = g_strndup(((gchar *)cmsg + cmsg->host.offset), cmsg->host.len);
		g_string_append_printf(str, "\thost: %s\n", host);
		g_free(host);
	}

	return g_string_free(str, FALSE);
}

static gchar *
sip_sec_ntlm_authenticate_message_describe(struct authenticate_message *cmsg)
{
	GString* str = g_string_new(NULL);
	char *tmp;
	SipSecBuffer buff;

	g_string_append(str, (tmp = sip_sec_ntlm_negotiate_flags_describe(cmsg->flags)));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->lm_resp), "lm_resp")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->nt_resp), "nt_resp")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->domain), "domain")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->user), "user")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->host), "host")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->session_key), "session_key")));
	g_free(tmp);

	tmp = sip_sec_ntlm_describe_version(&(cmsg->ver));
	g_string_append(str, tmp);
	g_free(tmp);

	/* mic */
	buff.length = 16;
	buff.value = cmsg->mic;
	g_string_append_printf(str, "\t%s: %s\n", "mic", (tmp = bytes_to_hex_str(&buff)));
	g_free(tmp);

	if (cmsg->lm_resp.len && cmsg->lm_resp.offset) {
		buff.length = cmsg->lm_resp.len;
		buff.value = (gchar *)cmsg + cmsg->lm_resp.offset;
		g_string_append_printf(str, "\t%s: %s\n", "lm_resp", (tmp = bytes_to_hex_str(&buff)));
		g_free(tmp);
	}

	if (cmsg->nt_resp.len && cmsg->nt_resp.offset) {
		buff.length = cmsg->nt_resp.len;
		buff.value = (gchar *)cmsg + cmsg->nt_resp.offset;
		g_string_append_printf(str, "\t%s: %s\n", "nt_resp", (tmp = bytes_to_hex_str(&buff)));
		g_free(tmp);
	}

	if (cmsg->domain.len && cmsg->domain.offset) {
		gchar *domain = unicode_strconvcopy_back(((gchar *)cmsg + cmsg->domain.offset), cmsg->domain.len);
		g_string_append_printf(str, "\t%s: %s\n", "domain", domain);
		g_free(domain);
	}

	if (cmsg->user.len && cmsg->user.offset) {
		gchar *user = unicode_strconvcopy_back(((gchar *)cmsg + cmsg->user.offset), cmsg->user.len);
		g_string_append_printf(str, "\t%s: %s\n", "user", user);
		g_free(user);
	}

	if (cmsg->host.len && cmsg->host.offset) {
		gchar *host = unicode_strconvcopy_back(((gchar *)cmsg + cmsg->host.offset), cmsg->host.len);
		g_string_append_printf(str, "\t%s: %s\n", "host", host);
		g_free(host);
	}

	if (cmsg->session_key.len && cmsg->session_key.offset) {
		buff.length = cmsg->session_key.len;
		buff.value = (gchar *)cmsg + cmsg->session_key.offset;
		g_string_append_printf(str, "\t%s: %s\n", "session_key", (tmp = bytes_to_hex_str(&buff)));
		g_free(tmp);
	}

	return g_string_free(str, FALSE);
}

static gchar *
sip_sec_ntlm_challenge_message_describe(struct challenge_message *cmsg)
{
	GString* str = g_string_new(NULL);
	char *tmp;

	g_string_append(str, (tmp = sip_sec_ntlm_negotiate_flags_describe(cmsg->flags)));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->target_name), "target_name")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->target_info), "target_info")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_version(&(cmsg->ver))));
	g_free(tmp);

	if (cmsg->target_name.len && cmsg->target_name.offset) {
		gchar *target_name = unicode_strconvcopy_back(((gchar *)cmsg + cmsg->target_name.offset), cmsg->target_name.len);
		g_string_append_printf(str, "\ttarget_name: %s\n", target_name);
		g_free(target_name);
	}

	if (cmsg->target_info.len && cmsg->target_info.offset) {
		void *target_info = ((gchar *)cmsg + cmsg->target_info.offset);
		struct av_pair *av = (struct av_pair*)target_info;

		while (av->av_id != MsvAvEOL) {
			gchar *av_value = ((gchar *)av) + 4;

			switch (av->av_id) {
				case MsvAvEOL:
					g_string_append_printf(str, "\t%s\n", "MsvAvEOL");
					break;
				case MsvAvNbComputerName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvNbComputerName")  break; }
				case MsvAvNbDomainName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvNbDomainName")  break; }
				case MsvAvDnsComputerName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvDnsComputerName")  break; }
				case MsvAvDnsDomainName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvDnsDomainName")  break; }
				case MsvAvDnsTreeName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvDnsTreeName")  break; }
				case MsvAvFlags:
					g_string_append_printf(str, "\t%s: %d\n", "MsvAvFlags", *((guint32*)av_value));
					break;
				case MsvAvTimestamp:
					g_string_append_printf(str, "\t%s\n", "MsvAvTimestamp");
					break;
				case MsAvRestrictions:
					g_string_append_printf(str, "\t%s\n", "MsAvRestrictions");
					break;
				case MsvAvTargetName:
					{ AV_DESC(av, av_value, av->av_len, "MsvAvTargetName")  break; }
				case MsvChannelBindings:
					g_string_append_printf(str, "\t%s\n", "MsvChannelBindings");
					break;
			}

			av = (struct av_pair*)(((guint8*)av) + 4 + av->av_len);
		}
	}

	return g_string_free(str, FALSE);
}

gchar *
sip_sec_ntlm_message_describe(SipSecBuffer buff)
{
	struct ntlm_message *msg;

	if (buff.length == 0 || buff.value == NULL || buff.length < 12) return NULL;

	msg = buff.value;
	if(strcmp("NTLMSSP", (char*)msg)) return NULL;

	if (msg->type == 1) return sip_sec_ntlm_negotiate_message_describe((struct negotiate_message *)msg);
	if (msg->type == 2) return sip_sec_ntlm_challenge_message_describe((struct challenge_message *)msg);
	if (msg->type == 3) return sip_sec_ntlm_authenticate_message_describe((struct authenticate_message *)msg);

	return NULL;
}

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

	/* NTLM requires a domain, username & password */
	if (!domain || !username || !password)
		return SIP_SEC_E_INTERNAL_ERROR;

	ctx->domain   = g_strdup(domain);
	ctx->username = g_strdup(username);
	ctx->password = g_strdup(password);

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
		if (!context->is_connection_based) {
			out_buff->length = 0;
			out_buff->value = NULL;
		} else {
			purple_ntlm_gen_negotiate(out_buff);
		}
		return SIP_SEC_I_CONTINUE_NEEDED;

	} else 	{
		guchar *ntlm_key;
		guchar *nonce;
		guint32 flags;
		gchar *tmp;

		if (!in_buff.value || !in_buff.length) {
			return SIP_SEC_E_INTERNAL_ERROR;
		}

		nonce = g_memdup(purple_ntlm_parse_challenge(in_buff, context->is_connection_based, &flags), 8);

		purple_ntlm_gen_authenticate(&ntlm_key,
					     ctx->username,
					     ctx->password,
					     (tmp = g_ascii_strup(sipe_get_host_name(), -1)),
					     ctx->domain,
					     nonce,
					     context->is_connection_based,
					     out_buff,
					     &flags);
		g_free(nonce);
		g_free(tmp);

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
