/**
 * @file sip-sec-ntlm.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

/*
 * Byte order policy:
 *
 *  - NTLM messages (byte streams) should be in LE (Little-Endian) byte order.
 *  - internal int16, int32, int64 should contain proper values.
 *     For example: 01 00 00 00 LE should be translated to (int32)1
 *  - When reading/writing from/to NTLM message appropriate conversion should
 *    be taken to properly present integer values. glib's "Byte Order Macros"
 *    should be used for that, for example GUINT32_FROM_LE
 *
 *    NOTE: The Byte Order Macros can have side effects!
 *          Do *NOT* make any calculations inside the macros!
 *
 *  - All calculations should be made in dedicated local variables (system-endian),
 *    not in NTLM (LE) structures.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#ifdef HAVE_LANGINFO_CODESET
#include <langinfo.h>
#endif /* HAVE_LANGINFO_CODESET */

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-ntlm.h"
#include "sipe-backend.h"
#include "sipe-crypt.h"
#include "sipe-digest.h"
#include "sipe-utils.h"

#include "md4.h"

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

/* time_t <-> (guint64) time_val conversion */
#define TIME_VAL_FACTOR 10000000
#define TIME_VAL_OFFSET 116444736000000000LL
#define TIME_T_TO_VAL(time_t)   (((guint64)(time_t)) * TIME_VAL_FACTOR + TIME_VAL_OFFSET)
#define TIME_VAL_TO_T(time_val) ((time_t)((GUINT64_FROM_LE((time_val)) - TIME_VAL_OFFSET) / TIME_VAL_FACTOR))

/* 8 bytes */
/* LE (Little Endian) byte order */
struct version {
	guint8  product_major_version;
	guint8  product_minor_version;
	guint16 product_build;
	guint8  zero2[3];
	guint8  ntlm_revision_current;
};

/*
 * NTLMv1 is no longer used except in tests. R.I.P.
 *
 * It remains in this file only for documentary purposes
 */
#ifdef _SIPE_COMPILING_TESTS
static gboolean use_ntlm_v2 = FALSE;

guint64 test_time_val = 0;		/* actual time in implementation */
guchar test_client_challenge [8];	/* random in implementation */
guchar test_random_session_key[16];	/* random in implementation */
struct version test_version;		/* hard-coded in implementation */
#endif

/* Minimum set of common features we need to work. */
/* we operate in NTLMv2 mode */
#define NEGOTIATE_FLAGS_COMMON_MIN \
	( NTLMSSP_NEGOTIATE_UNICODE | \
	  NTLMSSP_NEGOTIATE_NTLM | \
	  NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
	  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | \
	  NTLMSSP_NEGOTIATE_TARGET_INFO \
	)

/* Negotiate flags for connection-based mode. Nice to have but optional. */
#define NEGOTIATE_FLAGS_CONN \
	( NEGOTIATE_FLAGS_COMMON_MIN | \
	  NTLMSSP_NEGOTIATE_VERSION | \
	  NTLMSSP_NEGOTIATE_128 | \
	  NTLMSSP_NEGOTIATE_56 | \
	  NTLMSSP_REQUEST_TARGET \
	)

/* Extra negotiate flags required in connectionless NTLM */
#define NEGOTIATE_FLAGS_CONNLESS_EXTRA \
	( NTLMSSP_NEGOTIATE_SIGN | \
	  NTLMSSP_NEGOTIATE_DATAGRAM | \
	  NTLMSSP_NEGOTIATE_IDENTIFY | \
	  NTLMSSP_NEGOTIATE_KEY_EXCH \
	)

/* Negotiate flags required in connectionless NTLM */
#define NEGOTIATE_FLAGS_CONNLESS \
	( NEGOTIATE_FLAGS_CONN | \
	  NEGOTIATE_FLAGS_CONNLESS_EXTRA \
	)

#define NTLMSSP_LN_OR_NT_KEY_LEN  16
#define NTLMSSP_LM_RESP_LEN 24
#define NTLMSSP_SESSION_KEY_LEN  16

#define IS_FLAG(flags, flag) (((flags) & (flag)) == (flag))

/* 4 bytes */
/* LE (Little Endian) byte order */
struct av_pair {
	guint16 av_id;
	guint16 av_len;
	/* value */
};

/* to meet sparc's alignment requirement */
#define ALIGN_AV                                     \
	memcpy(&av_aligned, av, sizeof(av_aligned)); \
	av_id  = GUINT16_FROM_LE(av_aligned.av_id);  \
	av_len = GUINT16_FROM_LE(av_aligned.av_len)
#define ALIGN_AV_LOOP_START                          \
	struct av_pair av_aligned;                   \
	guint16 av_id;                               \
	guint16 av_len;                              \
	ALIGN_AV;				     \
	while (av_id != MsvAvEOL) {                  \
		gchar *av_value = ((gchar *)av) +    \
			sizeof(struct av_pair);      \
		switch (av_id)
#define ALIGN_AV_LOOP_END               \
		av = av_value + av_len; \
		ALIGN_AV;               \
	}

/* 8 bytes */
/* LE (Little Endian) byte order */
struct smb_header {
	guint16 len;
	guint16 maxlen;
	guint32 offset;
};

/* LE (Little Endian) byte order */
struct ntlm_message {
	guint8  protocol[8];     /* 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'*/
	guint32 type;            /* 0x00000003 */
};

/* LE (Little Endian) byte order */
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

/* LE (Little Endian) byte order */
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

/* LE (Little Endian) byte order */
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
	//guint8  mic[16];
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
#ifdef __sun__
static char SIPE_DEFAULT_CODESET[] = "US-ASCII";
#else
static char SIPE_DEFAULT_CODESET[] = "ANSI_X3.4-1968";
#endif
#endif

/* Private Methods */

/* Utility Functions */
static GIConv convert_from_utf16le = (GIConv)-1;
static GIConv convert_to_utf16le   = (GIConv)-1;

/* Analyzer only needs the _describe() functions */
#ifndef _SIPE_COMPILING_ANALYZER

static gsize
unicode_strconvcopy(gchar *dest, const gchar *source, gsize remlen)
{
	gsize inbytes  = strlen(source);
	gsize outbytes = remlen;
	if (remlen)
		g_iconv(convert_to_utf16le, (gchar **)&source, &inbytes, &dest, &outbytes);
	return(remlen - outbytes);
}

#endif /* !_SIPE_COMPILING_ANALYZER */

/* UTF-16LE to native encoding
 * Must be g_free'd after use */
static gchar *
unicode_strconvcopy_back(const gchar *source, gsize len)
{
	gsize outbytes = 2 * len;
	gchar *dest    = g_new0(gchar, outbytes + 1);
	gchar *outbuf  = dest;
	g_iconv(convert_from_utf16le, (gchar **)&source, &len, &outbuf, &outbytes);
	return dest;
}

/* Analyzer only needs the _describe() functions */
#ifndef _SIPE_COMPILING_ANALYZER

/* crc32 source copy from gg's common.c */
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
CRC32 (const char *msg, int len)
{
	guint32 crc = 0L;
	crc = crc32(crc, (guint8 *) msg, len);
	return crc;
}

/* Cyphers */

#ifdef _SIPE_COMPILING_TESTS
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

/* (k = 7 byte key, d = 8 byte data) returns 8 bytes in results */
static void
DES (const unsigned char *k, const unsigned char *d, unsigned char * results)
{
	unsigned char key[8];
	setup_des_key(k, key);
	sipe_crypt_des(key, d, 8, results);
}

/* (K = 21 byte key, D = 8 bytes of data) returns 24 bytes in results: */
static void
DESL (const unsigned char *k, const unsigned char *d, unsigned char * results)
{
	unsigned char keys[21];

	/* Copy the first 16 bytes */
	memcpy(keys, k, 16);

	/* Zero out the last 5 bytes of the key */
	memset(keys + 16, 0, 5);

	DES(keys,      d, results);
	DES(keys + 7,  d, results + 8);
	DES(keys + 14, d, results + 16);
}
#endif

#define RC4K(key, key_len, plain, plain_len, encrypted) \
	sipe_crypt_rc4((key), (key_len), (plain), (plain_len), (encrypted))

/* out 16 bytes */
static void MD4(const guchar *data, gsize length, guchar *digest)
{
	/*
	 * From Firefox's complementing implementation for NSS.
	 * NSS doesn't include MD4, because it is considered weak.
	 */
	md4sum(data, length, digest);
}

/* out 16 bytes */
#define MD5(d, len, result) sipe_digest_md5((d), (len), (result))

/* out 16 bytes */
/*
static void
HMACT64 (const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *result)
{
	int i;
	unsigned char ibuff[64 + data_len];
	unsigned char obuff[64 + 16];

	if (key_len > 64)
		key_len = 64;

        for (i = 0; i < key_len; i++) {
            ibuff[i] = key[i] ^ 0x36;
            obuff[i] = key[i] ^ 0x5c;
        }
        for (i = key_len; i < 64; i++) {
            ibuff[i] = 0x36;
            obuff[i] = 0x5c;
        }

	memcpy(ibuff+64, data, data_len);

	MD5 (ibuff, 64 + data_len, obuff+64);
	MD5 (obuff, 64 + 16, result);
}
#define HMAC_MD5 HMACT64
*/

/* out 16 bytes */
#define HMAC_MD5(key, key_len, data, data_len, result) \
	sipe_digest_hmac_md5((key), (key_len), (data), (data_len), (result))

/* NTLM Core Methods */

static void
NONCE(unsigned char *buffer, int num)
{
	int i;
	for (i = 0; i < num; i++) {
		buffer[i] = (rand() & 0xff);
	}
}

#ifdef _SIPE_COMPILING_TESTS
static void
Z(unsigned char *buffer, int num)
{
	memset(buffer, 0, num);
}

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
#endif

/*
Define NTOWFv1(Passwd, User, UserDom) as
  MD4(UNICODE(Passwd))
EndDefine
*/
/* out 16 bytes */
static void
NTOWFv1 (const char* password, SIPE_UNUSED_PARAMETER const char *user, SIPE_UNUSED_PARAMETER const char *domain, unsigned char *result)
{
	int len_u = 2 * strlen(password); // utf16 should not be more
	unsigned char *unicode_password = g_malloc(len_u);

	/* well, if allocation failed the rest will crash & burn soon anyway... */
	if (unicode_password) {
		len_u = unicode_strconvcopy((gchar *)unicode_password, password, len_u);
		MD4 (unicode_password, len_u, result);
		g_free(unicode_password);
	}
}

/*
Define NTOWFv2(Passwd, User, UserDom) as
  HMAC_MD5( MD4(UNICODE(Passwd)), ConcatenationOf( Uppercase(User), UserDom ) )
EndDefine
*/
/* out 16 bytes */
static void
NTOWFv2 (const char* password, const char *user, const char *domain, unsigned char *result)
{
	unsigned char response_key_nt_v1 [16];
	int len_user = user ? strlen(user) : 0;
	int len_domain = strlen(domain);
	int len_user_u = 2 * len_user; // utf16 should not be more
	int len_domain_u = 2 * len_domain; // utf16 should not be more
	unsigned char *user_upper = g_malloc(len_user + 1);
	unsigned char *buff = g_malloc((len_user + len_domain)*2);
	int i;

	/* Uppercase user */
	for (i = 0; i < len_user; i++) {
		user_upper[i] = g_ascii_toupper(user[i]);
	}
	user_upper[len_user] = 0;

	len_user_u = unicode_strconvcopy((gchar *)buff, (gchar *)user_upper, len_user_u);
	len_domain_u = unicode_strconvcopy((gchar *)(buff+len_user_u), (gchar *)domain, len_domain_u);

	NTOWFv1(password, user, domain, response_key_nt_v1);

	HMAC_MD5(response_key_nt_v1, 16, buff, len_user_u + len_domain_u, result);

	g_free(buff);
	g_free(user_upper);
}

static void
compute_response(const guint32 neg_flags,
		 const unsigned char *response_key_nt,
		 const unsigned char *response_key_lm,
		 const guint8 *server_challenge,
		 const guint8 *client_challenge,
		 const guint64 time_val,
		 const guint8 *target_info,
		 int target_info_len,
		 unsigned char *lm_challenge_response,
		 unsigned char *nt_challenge_response,
		 unsigned char *session_base_key)
{
#ifdef _SIPE_COMPILING_TESTS
	if (use_ntlm_v2)
	{
#endif
/*
Responserversion - The 1-byte response version. Currently set to 1.
HiResponserversion - The 1-byte highest response version understood by the client. Currently set to 1.
Time - The 8-byte little-endian time in GMT.
ServerName - The TargetInfo field structure of the CHALLENGE_MESSAGE payload.
ClientChallenge - The 8-byte challenge message generated by the client.
CHALLENGE_MESSAGE.ServerChallenge - The 8-byte challenge message generated by the server.

Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName) as
	Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6),		//8bytes -    0
				    Time,						//8bytes -    8
				    ClientChallenge,					//8bytes -   16
				    Z(4),						//4bytes -   24
				    ServerName,						//variable - 28
				    Z(4))						//4bytes -   28+target_info_len
	Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
	Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
	Set LmChallengeResponse to ConcatenationOf(
		HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
		ClientChallenge )
	Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
EndDefine
*/
		guint8 tmp [16];
		guint8 nt_proof_str [16];

		/* client_challenge (8) & temp (temp_len) buff */
		unsigned int temp_len = 8+8+8+4+target_info_len+4;
		guint64 *temp2 = g_malloc0(8 + temp_len);
		((guint8 *) temp2)[8+0] = 1;
		((guint8 *) temp2)[8+1] = 1;
		temp2[2] = GUINT64_TO_LE(time_val); /* should be int64 aligned: OK for sparc */
		memcpy(((guint8 *) temp2)+8+16, client_challenge, 8);
		memcpy(((guint8 *) temp2)+8+28, target_info, target_info_len);

		/* NTProofStr */
		//Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
		memcpy(temp2, server_challenge, 8);
		HMAC_MD5(response_key_nt, 16, (guint8*)temp2, 8+temp_len, nt_proof_str);

		/* NtChallengeResponse */
		//Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
		memcpy(nt_challenge_response, nt_proof_str, 16);
		memcpy(nt_challenge_response+16, temp2+1, temp_len);
		g_free(temp2);

		/* SessionBaseKey */
		//SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
		HMAC_MD5(response_key_nt, 16, nt_proof_str, 16, session_base_key);

		/* lm_challenge_response */
		memcpy(tmp, server_challenge, 8);
		memcpy(tmp+8, client_challenge, 8);
		HMAC_MD5(response_key_lm, 16, tmp, 16, lm_challenge_response);
		memcpy(lm_challenge_response+16, client_challenge, 8);

#ifndef _SIPE_COMPILING_TESTS
		/* Not used in NTLMv2 */
		(void)neg_flags;
#else
	}
	else
	{
		if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_LM_KEY)) {
			// @TODO do not even reference nt_challenge_response
			Z (nt_challenge_response, NTLMSSP_LM_RESP_LEN);
			DESL (response_key_lm, server_challenge, lm_challenge_response);
		} else if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
			unsigned char prehash [16];
			unsigned char hash [16];

			/* nt_challenge_response */
			memcpy(prehash, server_challenge, 8);
			memcpy(prehash + 8, client_challenge, 8);
			MD5 (prehash, 16, hash);
			DESL (response_key_nt, hash, nt_challenge_response);

			/* lm_challenge_response */
			memcpy(lm_challenge_response, client_challenge, 8);
			Z (lm_challenge_response+8, 16);
		} else {
			DESL (response_key_nt, server_challenge, nt_challenge_response);
			if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_NT_ONLY)) {
				memcpy(lm_challenge_response, nt_challenge_response, NTLMSSP_LM_RESP_LEN);
			} else {
				DESL (response_key_lm, server_challenge, lm_challenge_response);
			}
		}

		/* Session Key */
		MD4(response_key_nt, 16, session_base_key); // "User Session Key" -> "master key"
	}
#endif
}

static void
KXKEY ( guint32 flags,
	const unsigned char * session_base_key,
	const unsigned char * lm_challenge_resonse,
	const guint8 * server_challenge, /* 8-bytes, nonce */
	unsigned char * key_exchange_key)
{
#ifdef _SIPE_COMPILING_TESTS
	if (use_ntlm_v2)
	{
#else
		/* Not used in NTLMv2 */
		(void)flags;
		(void)lm_challenge_resonse;
		(void)server_challenge;
#endif
		memcpy(key_exchange_key, session_base_key, 16);
#ifdef _SIPE_COMPILING_TESTS
	}
	else
	{
		if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
			/*  Define KXKEY(SessionBaseKey, LmChallengeResponse, ServerChallenge) as
			        Set KeyExchangeKey to HMAC_MD5(SessionBaseKey, ConcatenationOf(ServerChallenge, LmChallengeResponse [0..7]))
			    EndDefine
			*/
			guint8 tmp[16];
			memcpy(tmp, server_challenge, 8);
			memcpy(tmp+8, lm_challenge_resonse, 8);
			HMAC_MD5(session_base_key, 16, tmp, 16, key_exchange_key);
		} else {
			/* Assume v1 and NTLMSSP_REQUEST_NON_NT_SESSION_KEY not set */
			memcpy(key_exchange_key, session_base_key, 16);
		}
	}
#endif
}

/*
     If (Mode equals "Client")
          Set SignKey to MD5(ConcatenationOf(RandomSessionKey,
          "session key to client-to-server signing key magic constant"))
     Else
          Set SignKey to MD5(ConcatenationOf(RandomSessionKey,
          "session key to server-to-client signing key magic constant"))
     Endif
*/
static void
SIGNKEY (const unsigned char * random_session_key, gboolean client, unsigned char * result)
{
	char * magic = client
		? "session key to client-to-server signing key magic constant"
		: "session key to server-to-client signing key magic constant";

	int len = strlen(magic) + 1;
	unsigned char *md5_input = g_malloc(16 + len);
	memcpy(md5_input, random_session_key, 16);
	memcpy(md5_input + 16, magic, len);

	MD5 (md5_input, len + 16, result);
	g_free(md5_input);
}

/*
Define SEALKEY(NegotiateFlags, RandomSessionKey, Mode) as
If (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag is set in NegFlg)
     If ( NTLMSSP_NEGOTIATE_128 is set in NegFlg)
          Set SealKey to RandomSessionKey
     ElseIf ( NTLMSSP_NEGOTIATE_56 flag is set in NegFlg)
         Set SealKey to RandomSessionKey[0..6]
     Else
         Set SealKey to RandomSessionKey[0..4]
     Endif

     If (Mode equals "Client")
         Set SealKey to MD5(ConcatenationOf(SealKey, "session key to client-to-server sealing key magic constant"))
     Else
         Set SealKey to MD5(ConcatenationOf(SealKey, "session key to server-to-client sealing key magic constant"))
     Endif

ElseIf (NTLMSSP_NEGOTIATE_56 flag is set in NegFlg)
     Set SealKey to ConcatenationOf(RandomSessionKey[0..6], 0xA0)
Else
     Set SealKey to ConcatenationOf(RandomSessionKey[0..4], 0xE5, 0x38, 0xB0)
Endif
EndDefine
*/
/* out 16 bytes or 8 bytes depending if Ext.Sess.Sec is negotiated */
static void
SEALKEY (guint32 flags, const unsigned char * random_session_key, gboolean client, unsigned char * result)
{
	if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY))
	{
		char * magic = client
			? "session key to client-to-server sealing key magic constant"
			: "session key to server-to-client sealing key magic constant";

		int len = strlen(magic) + 1;
		unsigned char *md5_input = g_malloc(16 + len);
		int key_len;

		if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_128)) {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 128-bit key (Extended session security)");
			key_len = 16;
		} else if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_56)) {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 56-bit key (Extended session security)");
			key_len = 7;
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 40-bit key (Extended session security)");
			key_len = 5;
		}

		memcpy(md5_input, random_session_key, key_len);
		memcpy(md5_input + key_len, magic, len);

		MD5 (md5_input, key_len + len, result);
		g_free(md5_input);
	}
	else if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_LM_KEY)) /* http://davenport.sourceforge.net/ntlm.html#ntlm1KeyWeakening */
	{
		if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_56)) {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 56-bit key");
			memcpy(result, random_session_key, 7);
			result[7] = 0xA0;
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 40-bit key");
			memcpy(result, random_session_key, 5);
			result[5] = 0xE5;
			result[6] = 0x38;
			result[7] = 0xB0;
		}
	}
	else
	{
		SIPE_DEBUG_INFO_NOFORMAT("NTLM SEALKEY(): 128-bit key");
		memcpy(result, random_session_key, 16);
	}
}

/*
= for Extended Session Security =
Version  (4 bytes): A 32-bit unsigned integer that contains the signature version. This field MUST be 0x00000001.
Checksum (8 bytes): An 8-byte array that contains the checksum for the message.
SeqNum   (4 bytes): A 32-bit unsigned integer that contains the NTLM sequence number for this application message.

= if Extended Session Security is NOT negotiated =
Version   (4 bytes): A 32-bit unsigned integer that contains the signature version. This field MUST be 0x00000001.
RandomPad (4 bytes): A 4-byte array that contains the random pad for the message.
Checksum  (4 bytes):  A 4-byte array that contains the checksum for the message.
SeqNum    (4 bytes): A 32-bit unsigned integer that contains the NTLM sequence number for this application message.
---
0x00000001, RC4K(RandomPad), RC4K(CRC32(Message)), RC4K(0x00000000) XOR (application supplied SeqNum)		-- RC4(X) xor X xor Y = RC4(Y)

Version(4), Checksum(8),  SeqNum(4)			-- for ext.sess.sec.
Version(4), RandomPad(4), Checksum(4), SeqNum(4)
*/
/** MAC(Handle, SigningKey, SeqNum, Message) */
/* out 16 bytes */
static void
MAC (guint32 flags,
     const char *buf,
     unsigned int buf_len,
     unsigned char *sign_key,
     unsigned long sign_key_len,
     unsigned char *seal_key,
     unsigned long seal_key_len,
     guint32 random_pad,
     guint32 sequence,
     guint32 *result)
{
	guint32 *res_ptr;

	if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)) {
		/*
		Define MAC(Handle, SigningKey, SeqNum, Message) as
			Set NTLMSSP_MESSAGE_SIGNATURE.Version to 0x00000001
			Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to
				HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7]
			Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to SeqNum
			Set SeqNum to SeqNum + 1
		EndDefine
		*/
		/* If a key exchange key is negotiated
		   Define MAC(Handle, SigningKey, SeqNum, Message) as
			Set NTLMSSP_MESSAGE_SIGNATURE.Version to 0x00000001
			Set NTLMSSP_MESSAGE_SIGNATURE.Checksum to RC4(Handle,
				HMAC_MD5(SigningKey, ConcatenationOf(SeqNum, Message))[0..7])
			Set NTLMSSP_MESSAGE_SIGNATURE.SeqNum to SeqNum
			Set SeqNum to SeqNum + 1
		   EndDefine
		*/

		unsigned char seal_key_ [16];
		guchar hmac[16];
		guint32 *tmp = g_malloc(4 + buf_len);

		/* SealingKey' = MD5(ConcatenationOf(SealingKey, SequenceNumber))
		   RC4Init(Handle, SealingKey')
		 */
		if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_DATAGRAM)) {
			guint32 tmp2[4+1];

			memcpy(tmp2, seal_key, seal_key_len);
			tmp2[4] = GUINT32_TO_LE(sequence);
			MD5 ((guchar *)tmp2, sizeof(tmp2), seal_key_);
		} else {
			memcpy(seal_key_, seal_key, seal_key_len);
		}

		SIPE_DEBUG_INFO_NOFORMAT("NTLM MAC(): Extented Session Security");

		res_ptr = result;
		res_ptr[0] = GUINT32_TO_LE(1); // 4 bytes
		res_ptr[3] = GUINT32_TO_LE(sequence);

		res_ptr = tmp;
		res_ptr[0] = GUINT32_TO_LE(sequence);
		memcpy(tmp+1, buf, buf_len);

		HMAC_MD5(sign_key, sign_key_len, (guchar *)tmp, 4 + buf_len, hmac);
		g_free(tmp);

		if (IS_FLAG(flags, NTLMSSP_NEGOTIATE_KEY_EXCH)) {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM MAC(): Key Exchange");
			RC4K(seal_key_, seal_key_len, hmac, 8, (guchar *)(result+1));
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("NTLM MAC(): *NO* Key Exchange");
			memcpy(result+1, hmac, 8);
		}
	} else {
		/* The content of the first 4 bytes is irrelevant */
		guint32 crc = CRC32(buf, strlen(buf));
		guint32 plaintext [] = {
			GUINT32_TO_LE(0),
			GUINT32_TO_LE(crc),
			GUINT32_TO_LE(sequence)
		}; // 4, 4, 4 bytes

		SIPE_DEBUG_INFO_NOFORMAT("NTLM MAC(): *NO* Extented Session Security");

		RC4K(seal_key, seal_key_len, (const guchar *)plaintext, 12, (guchar *)(result+1));

		res_ptr = result;
		// Highest four bytes are the Version
		res_ptr[0] = GUINT32_TO_LE(0x00000001); // 4 bytes

		// Replace the first four bytes of the ciphertext with the random_pad
		res_ptr[1] = GUINT32_TO_LE(random_pad); // 4 bytes
	}
}

/* End Core NTLM Methods */

/**
  * @param flags (out)		flags received from server
  * @param server_challenge	must be g_free()'d after use if requested
  * @param target_info		must be g_free()'d after use if requested
  */
static void
sip_sec_ntlm_parse_challenge(SipSecBuffer in_buff,
			     guint32 *flags,
			     guchar **server_challenge, /* 8 bytes */
			     guint64 *time_val,
			     guchar **target_info,
			     int *target_info_len)
{
	/* SipSecBuffer.value is g_malloc()'d: use (void *) to remove guint8 alignment */
	struct challenge_message *cmsg = (void *)in_buff.value;
	guint32 host_flags = GUINT32_FROM_LE(cmsg->flags);

	/* server challenge (nonce) */
	if (server_challenge) {
		*server_challenge = g_memdup(cmsg->nonce, 8);
	}

	/* flags */
	if (flags) {
		*flags = host_flags;
	}

	/* target_info */
	if (cmsg->target_info.len && cmsg->target_info.offset) {
		void *content = (gchar *)cmsg + GUINT32_FROM_LE(cmsg->target_info.offset);
		void *av      = content;
		guint16 len   = GUINT16_FROM_LE(cmsg->target_info.len);

		ALIGN_AV_LOOP_START
		{
			/* @since Vista */
		case MsvAvTimestamp:
			if (time_val) {
				guint64 tmp;

				/* to meet sparc's alignment requirement */
				memcpy(&tmp, av_value, sizeof(tmp));
				*time_val = GUINT64_FROM_LE(tmp);
			}
			break;
		}
		ALIGN_AV_LOOP_END;

		if (target_info_len) {
			*target_info_len = len;
		}
		if (target_info) {
			*target_info = g_memdup(content, len);
		}
	}
}

/**
 * @param client_sign_key (out)		must be g_free()'d after use
 * @param server_sign_key (out) 	must be g_free()'d after use
 * @param client_seal_key (out) 	must be g_free()'d after use
 * @param server_seal_key (out) 	must be g_free()'d after use
 * @param flags (in, out)		negotiated flags
 */
static gboolean
sip_sec_ntlm_gen_authenticate(guchar **client_sign_key,
			      guchar **server_sign_key,
			      guchar **client_seal_key,
			      guchar **server_seal_key,
			      const gchar *user,
			      const gchar *password,
			      const gchar *hostname,
			      const gchar *domain,
			      const guint8 *server_challenge, /* nonce */
			      const guint64 time_val,
			      const guint8 *target_info,
			      int target_info_len,
			      gboolean http,
			      SipSecBuffer *out_buff,
			      guint32 *flags)
{
	guint32 orig_flags = http ? NEGOTIATE_FLAGS_CONN : NEGOTIATE_FLAGS_CONNLESS;
	guint32 neg_flags = (*flags & orig_flags) | NTLMSSP_REQUEST_TARGET;
	int ntlmssp_nt_resp_len =
#ifdef _SIPE_COMPILING_TESTS
		use_ntlm_v2 ?
#endif
		(16 + (32+target_info_len))
#ifdef _SIPE_COMPILING_TESTS
		: NTLMSSP_LM_RESP_LEN
#endif
		;
	gsize msglen = sizeof(struct authenticate_message)
		+ 2*(strlen(domain) + strlen(user)+ strlen(hostname))
		+ NTLMSSP_LM_RESP_LEN + ntlmssp_nt_resp_len
		+ (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_KEY_EXCH) ? NTLMSSP_SESSION_KEY_LEN : 0);
	struct authenticate_message *tmsg;
	char *tmp;
	guint32 offset;
	guint16 len;
	unsigned char response_key_lm [NTLMSSP_LN_OR_NT_KEY_LEN]; /* 16 */
	unsigned char response_key_nt [NTLMSSP_LN_OR_NT_KEY_LEN]; /* 16 */
	unsigned char lm_challenge_response [NTLMSSP_LM_RESP_LEN]; /* 24 */
	unsigned char *nt_challenge_response = g_malloc(ntlmssp_nt_resp_len);  /* variable or 24 */
	unsigned char session_base_key [16];
	unsigned char key_exchange_key [16];
	unsigned char exported_session_key[16];
	unsigned char encrypted_random_session_key [16];
	unsigned char key [16];
	unsigned char client_challenge [8];
	guint64 time_vl = time_val ? time_val : TIME_T_TO_VAL(time(NULL));

	if (!IS_FLAG(*flags, NEGOTIATE_FLAGS_COMMON_MIN) ||
	    !(http || IS_FLAG(*flags, NEGOTIATE_FLAGS_CONNLESS_EXTRA)) ||
	    !nt_challenge_response) /* Coverity thinks ntlmssp_nt_resp_len could be 0 */
	{
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_ntlm_gen_authenticate: received incompatible NTLM NegotiateFlags, exiting.");
		g_free(nt_challenge_response);
		return FALSE;
	}

	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_128)) {
		neg_flags = neg_flags & ~NTLMSSP_NEGOTIATE_56;
	}

	tmsg = g_malloc0(msglen);

	NONCE (client_challenge, 8);

#ifdef _SIPE_COMPILING_TESTS
	memcpy(client_challenge, test_client_challenge, 8);
	time_vl = test_time_val ? test_time_val : time_vl;

	if (use_ntlm_v2) {

#endif
		NTOWFv2 (password, user, domain, response_key_nt);
		memcpy(response_key_lm, response_key_nt, NTLMSSP_LN_OR_NT_KEY_LEN);
#ifdef _SIPE_COMPILING_TESTS
	} else {
		NTOWFv1 (password, user, domain, response_key_nt);
		LMOWFv1 (password, user, domain, response_key_lm);
	}
#endif

	compute_response(neg_flags,
			 response_key_nt,
			 response_key_lm,
			 server_challenge,
			 client_challenge,
			 time_vl,
			 target_info,
			 target_info_len,
			 lm_challenge_response,	/* out */
			 nt_challenge_response,	/* out */
			 session_base_key);	/* out */

	/* same as session_base_key for
	 * - NTLNv1 w/o Ext.Sess.Sec and
	 * - NTLMv2
	 */
	KXKEY(neg_flags, session_base_key, lm_challenge_response, server_challenge, key_exchange_key);

	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		NONCE (exported_session_key, 16); // random master key
#ifdef _SIPE_COMPILING_TESTS
		memcpy(exported_session_key, test_random_session_key, 16);
#endif
		RC4K (key_exchange_key, 16, exported_session_key, 16, encrypted_random_session_key);
	} else {
		memcpy(exported_session_key, key_exchange_key, 16);
	}

	tmp = buff_to_hex_str(exported_session_key, 16);
	SIPE_DEBUG_INFO("NTLM AUTHENTICATE: exported session key (not encrypted): %s", tmp);
	g_free(tmp);

	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_SIGN) ||
	    IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_SEAL))
	{
		/* p.46
		   Set ClientSigningKey to SIGNKEY(ExportedSessionKey, "Client")
		   Set ServerSigningKey to SIGNKEY(ExportedSessionKey, "Server")
		*/
		SIGNKEY(exported_session_key, TRUE, key);
		*client_sign_key = g_memdup(key, 16);
		SIGNKEY(exported_session_key, FALSE, key);
		*server_sign_key = g_memdup(key, 16);
		SEALKEY(neg_flags, exported_session_key, TRUE, key);
		*client_seal_key = g_memdup(key, 16);
		SEALKEY(neg_flags, exported_session_key, FALSE, key);
		*server_seal_key = g_memdup(key, 16);
	}

	/* @TODO: */
	/* @since Vista
	If the CHALLENGE_MESSAGE TargetInfo field (section 2.2.1.2) has an MsvAvTimestamp present,
	the client SHOULD provide a MIC:
	- If there is an AV_PAIR structure (section 2.2.2.1) with the AvId field set to MsvAvFlags,
		- then in the Value field, set bit 0x2 to 1.
		- else add an AV_PAIR structure (section 2.2.2.1) and set the AvId field to MsvAvFlags
		and the Value field bit 0x2 to 1.
	- Populate the MIC field with the MIC.
	*/

	/* Connection-oriented:
	Set MIC to HMAC_MD5(ExportedSessionKey,
		ConcatenationOf( NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE_MIC0));
	   Connectionless:
	Set MIC to HMAC_MD5(ExportedSessionKey,
		ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
	*/

	/* on the server-side:
	If (NTLMSSP_NEGOTIATE_KEY_EXCH flag is set in NegFlg )
		Set ExportedSessionKey to RC4K(KeyExchangeKey, AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey)
		Set MIC to HMAC_MD5(ExportedSessionKey,
			ConcatenationOf( NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE_MIC0))
	Else
		Set ExportedSessionKey to KeyExchangeKey
		Set MIC to HMAC_MD5(KeyExchangeKey,
			ConcatenationOf( NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE_MIC0)) EndIf
	=====
	@since Vista
	If the AUTHENTICATE_MESSAGE indicates the presence of a MIC field,
	then the MIC value computed earlier MUST be compared to the MIC field in the message,
	and if the two MIC values are not equal, then an authentication failure MUST be returned.
	An AUTHENTICATE_MESSAGE indicates the presence of a MIC field if the TargetInfo field has
	an AV_PAIR structure whose two fields:
		- AvId == MsvAvFlags
		- Value bit 0x2 == 1
	@supported NT, 2000, XP
	If NTLM v2 authentication is used and the AUTHENTICATE_MESSAGE.NtChallengeResponse.
	TimeStamp (section 2.2.2.7) is more than MaxLifetime (section 3.1.1.1) difference from
	the server time, then the server SHOULD return a failure.
	===
	Connectionless:
	Set MIC to HMAC_MD5(ResponseKeyNT,
		ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE_MIC0))
	*/

	/* authenticate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = GUINT32_TO_LE(3);

	/* Initial offset */
	offset = sizeof(struct authenticate_message);
	tmp = ((char*) tmsg) + offset;

#define _FILL_SMB_HEADER(header)				     \
	tmsg->header.offset = GUINT32_TO_LE(offset);		     \
	tmsg->header.len = tmsg->header.maxlen = GUINT16_TO_LE(len); \
	tmp += len;						     \
	offset += len
#define _APPEND_STRING(header, src)				\
	len = unicode_strconvcopy(tmp, (src), msglen - offset); \
	_FILL_SMB_HEADER(header)
#define _APPEND_DATA(header, src, srclen) \
	len = (srclen);			  \
	memcpy(tmp, (src), len);	  \
	_FILL_SMB_HEADER(header)

	/* Domain */
	_APPEND_STRING(domain, domain);

	/* User */
	_APPEND_STRING(user, user);

	/* Host */
	_APPEND_STRING(host, hostname);

	/* LM */
	/* @since Windows 7
	   If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains a TargetInfo field,
	   the client SHOULD NOT send the LmChallengeResponse and SHOULD set the LmChallengeResponseLen
	   and LmChallengeResponseMaxLen fields in the AUTHENTICATE_MESSAGE to zero.
	*/
	_APPEND_DATA(lm_resp, lm_challenge_response, NTLMSSP_LM_RESP_LEN);

	/* NT */
	_APPEND_DATA(nt_resp, nt_challenge_response, ntlmssp_nt_resp_len);

	/* Session Key */
	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_KEY_EXCH))
	{
		_APPEND_DATA(session_key, encrypted_random_session_key, NTLMSSP_SESSION_KEY_LEN);
	}
	else
	{
		tmsg->session_key.offset = GUINT32_TO_LE(offset);
		tmsg->session_key.len = tmsg->session_key.maxlen = 0;
	}

	/* Version */
#ifdef _SIPE_COMPILING_TESTS
	memcpy(&(tmsg->ver), &test_version, sizeof(struct version));
#else
	if (IS_FLAG(neg_flags, NTLMSSP_NEGOTIATE_VERSION)) {
		tmsg->ver.product_major_version = 5;		/* 5.1.2600 (Windows XP SP2) */
		tmsg->ver.product_minor_version = 1;
		tmsg->ver.product_build = GUINT16_FROM_LE(2600);
		tmsg->ver.ntlm_revision_current = 0x0F;		/* NTLMSSP_REVISION_W2K3 */
	}
#endif

	/* Set Negotiate Flags */
	tmsg->flags = GUINT32_TO_LE(neg_flags);
	*flags = neg_flags;

	out_buff->value = (guint8 *)tmsg;
	out_buff->length = msglen;

	g_free(nt_challenge_response);

	return TRUE;
}

/**
 * Generates Type 1 (Negotiate) message for connection-oriented cases (only)
 */
static void
sip_sec_ntlm_gen_negotiate(SipSecBuffer *out_buff)
{
	guint32 offset;
	guint16 len;
	int msglen = sizeof(struct negotiate_message);
	struct negotiate_message *tmsg = g_malloc0(msglen);

	/* negotiate message initialization */
	memcpy(tmsg->protocol, "NTLMSSP\0", 8);
	tmsg->type = GUINT32_TO_LE(1);

	/* Set Negotiate Flags */
	tmsg->flags = GUINT32_TO_LE(NEGOTIATE_FLAGS_CONN);

	/* Domain */
	offset = sizeof(struct negotiate_message);
	tmsg->domain.offset = GUINT32_TO_LE(offset);
	tmsg->domain.len = tmsg->domain.maxlen = len = 0;

	/* Host */
	offset += len;
	tmsg->host.offset = GUINT32_TO_LE(offset);
	tmsg->host.len = tmsg->host.maxlen = len = 0;

	/* Version */
	tmsg->ver.product_major_version = 5;		/* 5.1.2600 (Windows XP SP2) */
	tmsg->ver.product_minor_version = 1;
	tmsg->ver.product_build = GUINT16_FROM_LE(2600);
	tmsg->ver.ntlm_revision_current = 0x0F;		/* NTLMSSP_REVISION_W2K3 */

	out_buff->value = (guint8 *)tmsg;
	out_buff->length = msglen;
}

static void
sip_sec_ntlm_sipe_signature_make(guint32 flags,
				 const char *msg,
				 guint32 random_pad,
				 unsigned char *sign_key,
				 unsigned char *seal_key,
				 guint32 *result)
{
	char *res;

	MAC(flags, msg, strlen(msg), sign_key, 16, seal_key, 16, random_pad, 100, result);

	res = buff_to_hex_str((guint8 *)result, 16);
	SIPE_DEBUG_INFO("NTLM calculated MAC: %s", res);
	g_free(res);
}

#endif /* !_SIPE_COMPILING_ANALYZER */

/* Describe NTLM messages functions */

#define APPEND_NEG_FLAG(str, flags, flag, desc)	\
	if ((flags & flag) == flag) g_string_append_printf(str, "\t%s\n", desc);

static gchar *
sip_sec_ntlm_negotiate_flags_describe(guint32 flags)
{
	GString* str = g_string_new(NULL);

	flags = GUINT32_FROM_LE(flags);

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

	g_string_append_printf(str, "\t%s.len   : %d\n", name, GUINT16_FROM_LE(header->len));
	g_string_append_printf(str, "\t%s.maxlen: %d\n", name, GUINT16_FROM_LE(header->maxlen));
	g_string_append_printf(str, "\t%s.offset: %d\n", name, GUINT32_FROM_LE(header->offset));

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
		gchar *domain = g_strndup(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->domain.offset)), GUINT16_FROM_LE(cmsg->domain.len));
		g_string_append_printf(str, "\tdomain: %s\n", domain);
		g_free(domain);
	}

	if (cmsg->host.len && cmsg->host.offset) {
		gchar *host = g_strndup(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->host.offset)), GUINT16_FROM_LE(cmsg->host.len));
		g_string_append_printf(str, "\thost: %s\n", host);
		g_free(host);
	}

	return g_string_free(str, FALSE);
}

static void
describe_av_pairs(GString* str, const void *av)
{
#define AV_DESC(av_name) \
	{ \
		gchar *tmp = unicode_strconvcopy_back(av_value, av_len); \
		g_string_append_printf(str, "\t%s: %s\n", av_name, tmp); \
		g_free(tmp); \
	}

	ALIGN_AV_LOOP_START
	{
	case MsvAvNbComputerName:
		AV_DESC("MsvAvNbComputerName");
		break;
	case MsvAvNbDomainName:
		AV_DESC("MsvAvNbDomainName");
		break;
	case MsvAvDnsComputerName:
		AV_DESC("MsvAvDnsComputerName");
		break;
	case MsvAvDnsDomainName:
		AV_DESC("MsvAvDnsDomainName");
		break;
	case MsvAvDnsTreeName:
		AV_DESC("MsvAvDnsTreeName");
		break;
	case MsvAvFlags:
		{
			guint32 flags;

			/* to meet sparc's alignment requirement */
			memcpy(&flags, av_value, sizeof(guint32));
			g_string_append_printf(str, "\t%s: %d\n", "MsvAvFlags", GUINT32_FROM_LE(flags));
		}
		break;
	case MsvAvTimestamp:
		{
			char *tmp;
			guint64 time_val;
			time_t time_t_val;

			/* to meet sparc's alignment requirement */
			memcpy(&time_val, av_value, sizeof(time_val));
			time_t_val = TIME_VAL_TO_T(time_val);

			g_string_append_printf(str, "\t%s: %s - %s", "MsvAvTimestamp", (tmp = buff_to_hex_str((guint8 *) av_value, 8)),
					       asctime(gmtime(&time_t_val)));
			g_free(tmp);
		}
		break;
	case MsAvRestrictions:
		g_string_append_printf(str, "\t%s\n", "MsAvRestrictions");
		break;
	case MsvAvTargetName:
		AV_DESC("MsvAvTargetName");
		break;
	case MsvChannelBindings:
		g_string_append_printf(str, "\t%s\n", "MsvChannelBindings");
		break;
	}
	ALIGN_AV_LOOP_END;
}

static gchar *
sip_sec_ntlm_authenticate_message_describe(struct authenticate_message *cmsg)
{
	GString* str = g_string_new(NULL);
	char *tmp;
	gsize value_len;
	guint8 *value;

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
	//g_string_append_printf(str, "\t%s: %s\n", "mic", (tmp = buff_to_hex_str(cmsg->mic, 16)));
	//g_free(tmp);

	if (cmsg->lm_resp.len && cmsg->lm_resp.offset) {
		value_len = GUINT16_FROM_LE(cmsg->lm_resp.len);
		value = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->lm_resp.offset);
		g_string_append_printf(str, "\t%s: %s\n", "lm_resp", (tmp = buff_to_hex_str(value, value_len)));
		g_free(tmp);
	}

	if (cmsg->nt_resp.len && cmsg->nt_resp.offset) {
		guint16 nt_resp_len_full = GUINT16_FROM_LE(cmsg->nt_resp.len);
		int nt_resp_len = nt_resp_len_full;

		value_len = nt_resp_len_full;
		value = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->nt_resp.offset);
		g_string_append_printf(str, "\t%s: %s\n", "nt_resp raw", (tmp = buff_to_hex_str(value, value_len)));
		g_free(tmp);

		if (nt_resp_len > 24) { /* NTLMv2 */
			nt_resp_len = 16;
		}

		value_len = nt_resp_len;
		value = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->nt_resp.offset);
		g_string_append_printf(str, "\t%s: %s\n", "nt_resp", (tmp = buff_to_hex_str(value, value_len)));
		g_free(tmp);

		if (nt_resp_len_full > 24) { /* NTLMv2 */
			/* Work around Debian/x86_64 compiler bug */
			/* const guint8 *temp = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->nt_resp.offset) + 16; */
			const guint offset = GUINT32_FROM_LE(cmsg->nt_resp.offset) + 16;
			const guint8 *temp = (guint8 *)cmsg + offset;
			const guint response_version = temp[0];
			const guint hi_response_version = temp[1];
			const guint8 *client_challenge = temp + 16;
			const guint8 *target_info = temp + 28;
			guint16 target_info_len = nt_resp_len_full - 16 - 32;
			guint64 time_val;
			time_t time_t_val;
			char *tmp;

			g_string_append_printf(str, "\t%s: %s\n", "target_info raw",
				(tmp = buff_to_hex_str((guint8 *)target_info, target_info_len)));
			g_free(tmp);

			/* This is not int64 aligned on sparc */
			memcpy((gchar *)&time_val, temp+8, sizeof(time_val));
			time_t_val = TIME_VAL_TO_T(time_val);

			g_string_append_printf(str, "\t%s: %d\n", "response_version", response_version);
			g_string_append_printf(str, "\t%s: %d\n", "hi_response_version", hi_response_version);

			g_string_append_printf(str, "\t%s: %s - %s", "time", (tmp = buff_to_hex_str((guint8 *)&time_val, 8)),
					       asctime(gmtime(&time_t_val)));
			g_free(tmp);

			g_string_append_printf(str, "\t%s: %s\n", "client_challenge", (tmp = buff_to_hex_str((guint8 *)client_challenge, 8)));
			g_free(tmp);

			describe_av_pairs(str, target_info);

			g_string_append_printf(str, "\t%s\n", "----------- end of nt_resp v2 -----------");
		}
	}

	if (cmsg->domain.len && cmsg->domain.offset) {
		gchar *domain = unicode_strconvcopy_back(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->domain.offset)), GUINT16_FROM_LE(cmsg->domain.len));
		g_string_append_printf(str, "\t%s: %s\n", "domain", domain);
		g_free(domain);
	}

	if (cmsg->user.len && cmsg->user.offset) {
		gchar *user = unicode_strconvcopy_back(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->user.offset)), GUINT16_FROM_LE(cmsg->user.len));
		g_string_append_printf(str, "\t%s: %s\n", "user", user);
		g_free(user);
	}

	if (cmsg->host.len && cmsg->host.offset) {
		gchar *host = unicode_strconvcopy_back(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->host.offset)), GUINT16_FROM_LE(cmsg->host.len));
		g_string_append_printf(str, "\t%s: %s\n", "host", host);
		g_free(host);
	}

	if (cmsg->session_key.len && cmsg->session_key.offset) {
		value_len = GUINT16_FROM_LE(cmsg->session_key.len);
		value = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->session_key.offset);
		g_string_append_printf(str, "\t%s: %s\n", "session_key", (tmp = buff_to_hex_str(value, value_len)));
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

	/* nonce (server_challenge) */
	g_string_append_printf(str, "\t%s: %s\n", "server_challenge", (tmp = buff_to_hex_str(cmsg->nonce, 8)));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->target_name), "target_name")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_smb_header(&(cmsg->target_info), "target_info")));
	g_free(tmp);

	g_string_append(str, (tmp = sip_sec_ntlm_describe_version(&(cmsg->ver))));
	g_free(tmp);

	if (cmsg->target_name.len && cmsg->target_name.offset) {
		gchar *target_name = unicode_strconvcopy_back(((gchar *)cmsg + GUINT32_FROM_LE(cmsg->target_name.offset)), GUINT16_FROM_LE(cmsg->target_name.len));
		g_string_append_printf(str, "\ttarget_name: %s\n", target_name);
		g_free(target_name);
	}

	if (cmsg->target_info.len && cmsg->target_info.offset) {
		guint8 *target_info = (guint8 *)cmsg + GUINT32_FROM_LE(cmsg->target_info.offset);
		guint16 target_info_len = GUINT16_FROM_LE(cmsg->target_info.len);

		g_string_append_printf(str, "\t%s: %s\n", "target_info raw", (tmp = buff_to_hex_str(target_info, target_info_len)));
		g_free(tmp);

		describe_av_pairs(str, target_info);
	}

	return g_string_free(str, FALSE);
}

static void
sip_sec_ntlm_message_describe(SipSecBuffer *buff,
			      const gchar *type)
{
	struct ntlm_message *msg;
	gchar *res = NULL;

	if (buff->length == 0 || buff->value == NULL || buff->length < 12) return;

	/* SipSecBuffer.value is g_malloc()'d: use (void *) to remove guint8 alignment */
	msg = (void *)buff->value;
	if(!sipe_strequal("NTLMSSP", (char*)msg)) return;

	switch (GUINT32_FROM_LE(msg->type)) {
	case 1: res = sip_sec_ntlm_negotiate_message_describe((struct negotiate_message *)msg);
		break;
	case 2: res = sip_sec_ntlm_challenge_message_describe((struct challenge_message *)msg);
		break;
	case 3: res = sip_sec_ntlm_authenticate_message_describe((struct authenticate_message *)msg);
		break;
	}

	SIPE_DEBUG_INFO("sip_sec_ntlm_message_describe: %s message is:\n%s",
			type, res);
	g_free(res);
}

/* Analyzer only needs the _describe() functions */
#ifndef _SIPE_COMPILING_ANALYZER

/* sip-sec-mech.h API implementation for NTLM */

/* Security context for NTLM */
typedef struct _context_ntlm {
	struct sip_sec_context common;
	const gchar *domain;
	const gchar *username;
	const gchar *password;
	guchar *client_sign_key;
	guchar *server_sign_key;
	guchar *client_seal_key;
	guchar *server_seal_key;
	guint32 flags;
} *context_ntlm;

#define SIP_SEC_FLAG_NTLM_INITIAL  0x00010000


static gboolean
sip_sec_acquire_cred__ntlm(SipSecContext context,
			   const gchar *domain,
			   const gchar *username,
			   const gchar *password)
{
	context_ntlm ctx = (context_ntlm)context;

	/*
	 * Our NTLM implementation does not support Single Sign-On.
	 * Thus username & password are required.
	 * NULL or empty domain is OK.
	 */
	if (is_empty(username) || is_empty(password))
		return FALSE;

	/* this is the first time we are allowed to set private flags */
	context->flags |= SIP_SEC_FLAG_NTLM_INITIAL;

	ctx->domain   = domain ? domain : "";
	ctx->username = username;
	ctx->password = password;

	return TRUE;
}

static gboolean
sip_sec_init_sec_context__ntlm(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       SIPE_UNUSED_PARAMETER const gchar *service_name)
{
	context_ntlm ctx = (context_ntlm) context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__ntlm: in use");

	/*
	 * If authentication was already completed, then this mean a new
	 * authentication handshake has started on the existing connection.
	 * We must throw away the old context, because we need a new one.
	 */
	if (context->flags & SIP_SEC_FLAG_COMMON_READY) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__ntlm: dropping old context");
		context->flags &= ~SIP_SEC_FLAG_COMMON_READY;
		context->flags |=  SIP_SEC_FLAG_NTLM_INITIAL;
	}

	if (context->flags & SIP_SEC_FLAG_NTLM_INITIAL) {
		context->flags &= ~SIP_SEC_FLAG_NTLM_INITIAL;

		/* HTTP */
		if (context->flags & SIP_SEC_FLAG_COMMON_HTTP) {
			sip_sec_ntlm_gen_negotiate(out_buff);
			sip_sec_ntlm_message_describe(out_buff, "Negotiate");
		/* SIP */
		} else {
			/* empty initial message for connection-less NTLM */
			out_buff->length = 0;
			out_buff->value = (guint8 *) g_strdup("");
		}
	} else 	{
		gboolean res;
		guchar *client_sign_key = NULL;
		guchar *server_sign_key = NULL;
		guchar *client_seal_key = NULL;
		guchar *server_seal_key = NULL;
		guchar *server_challenge = NULL;
		guint64 time_val = 0;
		guchar *target_info = NULL;
		int target_info_len = 0;
		guint32 flags;
		gchar *tmp;

		if (!in_buff.value || !in_buff.length) {
			return FALSE;
		}

		sip_sec_ntlm_message_describe(&in_buff, "Challenge");

		sip_sec_ntlm_parse_challenge(in_buff,
					     &flags,
					     &server_challenge, /* 8 bytes */
					     &time_val,
					     &target_info,
					     &target_info_len);

		res = sip_sec_ntlm_gen_authenticate(
					      &client_sign_key,
					      &server_sign_key,
					      &client_seal_key,
					      &server_seal_key,
					      ctx->username,
					      ctx->password,
					      (tmp = g_ascii_strup(g_get_host_name(), -1)),
					      ctx->domain,
					      server_challenge,
					      time_val,
					      target_info,
					      target_info_len,
					      context->flags & SIP_SEC_FLAG_COMMON_HTTP,
					      out_buff,
					      &flags);
		g_free(server_challenge);
		g_free(target_info);
		g_free(tmp);

		if (!res) {
			g_free(client_sign_key);
			g_free(server_sign_key);
			g_free(client_seal_key);
			g_free(server_seal_key);
			return res;
		}

		sip_sec_ntlm_message_describe(out_buff, "Authenticate");

		g_free(ctx->client_sign_key);
		ctx->client_sign_key = client_sign_key;

		g_free(ctx->server_sign_key);
		ctx->server_sign_key = server_sign_key;

		g_free(ctx->client_seal_key);
		ctx->client_seal_key = client_seal_key;

		g_free(ctx->server_seal_key);
		ctx->server_seal_key = server_seal_key;

		ctx->flags = flags;

		/* Authentication is completed */
		context->flags |= SIP_SEC_FLAG_COMMON_READY;
	}

	return TRUE;
}

/**
 * @param message a NULL terminated string to sign
 *
 */
static gboolean
sip_sec_make_signature__ntlm(SipSecContext context,
			     const gchar *message,
			     SipSecBuffer *signature)
{
	signature->length = 16;
	signature->value = g_malloc0(16);

	/* FIXME? We always use a random_pad of 0 */
	sip_sec_ntlm_sipe_signature_make(((context_ntlm) context)->flags,
					 message,
					 0,
					 ((context_ntlm) context)->client_sign_key,
					 ((context_ntlm) context)->client_seal_key,
					 /* SipSecBuffer.value is g_malloc()'d:
					  * use (void *) to remove guint8 alignment
					  */
					 (void *)signature->value);
	return TRUE;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return TRUE on success
 */
static gboolean
sip_sec_verify_signature__ntlm(SipSecContext context,
			       const gchar *message,
			       SipSecBuffer signature)
{
	context_ntlm ctx = (context_ntlm) context;
	guint32 mac[4];
	/* SipSecBuffer.value is g_malloc()'d: use (void *) to remove guint8 alignment */
	guint32 random_pad = GUINT32_FROM_LE(((guint32 *)((void *)signature.value))[1]);

	sip_sec_ntlm_sipe_signature_make(ctx->flags,
					 message,
					 random_pad,
					 ctx->server_sign_key,
					 ctx->server_seal_key,
					 mac);
	return(memcmp(signature.value, mac, 16) == 0);
}

static void
sip_sec_destroy_sec_context__ntlm(SipSecContext context)
{
	context_ntlm ctx = (context_ntlm) context;

	g_free(ctx->client_sign_key);
	g_free(ctx->server_sign_key);
	g_free(ctx->client_seal_key);
	g_free(ctx->server_seal_key);
	g_free(ctx);
}

static const gchar *
sip_sec_context_name__ntlm(SIPE_UNUSED_PARAMETER SipSecContext context)
{
	return("NTLM");
}

SipSecContext
sip_sec_create_context__ntlm(SIPE_UNUSED_PARAMETER guint type)
{
	context_ntlm context = g_malloc0(sizeof(struct _context_ntlm));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__ntlm;
	context->common.init_context_func     = sip_sec_init_sec_context__ntlm;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__ntlm;
	context->common.make_signature_func   = sip_sec_make_signature__ntlm;
	context->common.verify_signature_func = sip_sec_verify_signature__ntlm;
	context->common.context_name_func     = sip_sec_context_name__ntlm;

	return((SipSecContext) context);
}

gboolean sip_sec_password__ntlm(void)
{
	return(TRUE);
}

#endif /* !_SIPE_COMPILING_ANALYZER */

void sip_sec_init__ntlm(void)
{
#ifdef HAVE_LANGINFO_CODESET
	const char *sys_cp = nl_langinfo(CODESET);
#else
        const char *sys_cp = SIPE_DEFAULT_CODESET;
#endif /* HAVE_LANGINFO_CODESET */

	/* fall back to utf-8 */
	if (!sys_cp) sys_cp = "UTF-8";

	convert_from_utf16le = g_iconv_open(sys_cp, "UTF-16LE");
	if (convert_from_utf16le == (GIConv)-1) {
		SIPE_DEBUG_ERROR("g_iconv_open from UTF-16LE to %s failed",
				 sys_cp);
	}

	convert_to_utf16le = g_iconv_open("UTF-16LE", sys_cp);
	if (convert_to_utf16le == (GIConv)-1) {
		SIPE_DEBUG_ERROR("g_iconv_open from %s to UTF-16LE failed",
				 sys_cp);
	}
}

void sip_sec_destroy__ntlm(void)
{
	g_iconv_close(convert_to_utf16le);
	g_iconv_close(convert_from_utf16le);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
