/**
 * @file uuid.c
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

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "sipe-digest.h"
#include "uuid.h"

static const char *epid_ns_uuid = "fcacfb03-8a73-46ef-91b1-e5ebeeaba4fe";

/*
 * This assumes that the structure is correctly packed on all target
 * platforms, i.e. sizeof(uuid_t) == 16
 *
 * See also the test added to "configure". On Windows platform we know
 * that #pragma pack() exists and therefore can use it in the code.
 *
 */
#ifdef _WIN32
#pragma pack(push, 1)
#endif
typedef struct {
   guint32 time_low;
   guint16 time_mid;
   guint16 time_hi_and_version;
   guint8  clock_seq_hi_and_reserved;
   guint8  clock_seq_low;
   guint8  node[6];
} uuid_t;
#ifdef _WIN32
#pragma pack(pop)
#endif

#define UUID_OFFSET_TO_LAST_SEGMENT 24

static void readUUID(const char *string, uuid_t *uuid)
{
	int i;
	/* Some platforms don't allow scanning to char using %02hhx */
	short tmp1, tmp2;

	sscanf(string, "%08x-%04hx-%04hx-%02hx%02hx-", &uuid->time_low
			, &uuid->time_mid, &uuid->time_hi_and_version
			, &tmp1, &tmp2);
	uuid->clock_seq_hi_and_reserved = tmp1;
	uuid->clock_seq_low = tmp2;

	for(i=0;i<6;i++)
	{
		sscanf(&string[UUID_OFFSET_TO_LAST_SEGMENT+i*2], "%02hx", &tmp1);
		uuid->node[i] = tmp1;
	}
}

static void printUUID(uuid_t *uuid, char *string)
{
	int i;
	size_t pos;
	sprintf(string, "%08x-%04x-%04x-%02x%02x-", uuid->time_low
			, uuid->time_mid, uuid->time_hi_and_version
			, uuid->clock_seq_hi_and_reserved
			, uuid->clock_seq_low
			);
	pos = strlen(string);
	for(i=0;i<6;i++)
	{
		pos += sprintf(&string[pos], "%02x", uuid->node[i]);
	}
}

static void createUUIDfromHash(uuid_t *uuid, const unsigned char *hash)
{
	memcpy(uuid, hash, sizeof(uuid_t));
	uuid->time_hi_and_version &= GUINT16_TO_LE(0x0FFF);
	uuid->time_hi_and_version |= GUINT16_TO_LE(0x5000);
	uuid->clock_seq_hi_and_reserved &= 0x3F;
	uuid->clock_seq_hi_and_reserved |= 0x80;
}

char *generateUUIDfromEPID(const gchar *epid)
{
	uuid_t result;
	char buf[512];
	guchar digest[SIPE_DIGEST_SHA1_LENGTH];

	readUUID(epid_ns_uuid, &result);

	result.time_low = GUINT32_FROM_LE(result.time_low);
	result.time_mid = GUINT16_FROM_LE(result.time_mid);
	result.time_hi_and_version = GUINT16_FROM_LE(result.time_hi_and_version);

	memcpy(buf, &result, sizeof(uuid_t));
	strcpy(&buf[sizeof(uuid_t)], epid);

	sipe_digest_sha1((guchar *)buf, strlen(buf), digest);
	createUUIDfromHash(&result, digest);

	result.time_low = GUINT32_TO_LE(result.time_low);
	result.time_mid = GUINT16_TO_LE(result.time_mid);
	result.time_hi_and_version = GUINT16_TO_LE(result.time_hi_and_version);

	printUUID(&result, buf);
	return g_strdup(buf);
}

/**
 * Generates epid from user SIP URI, hostname and IP address.
 * Thus epid will be the same each start and
 * not needed to be persistent.
 *
 * Using MAC address proved to be poorly portable solution.
 *
 * Must be g_free()'d
 */
char *sipe_get_epid(const char *self_sip_uri,
			   const char *hostname,
			   const char *ip_address)
{
/* 6 last digits of hash */
#define SIPE_EPID_HASH_START 14
#define SIPE_EPID_HASH_END   SIPE_DIGEST_SHA1_LENGTH
#define SIPE_EPID_LENGTH     (2 * (SIPE_EPID_HASH_END - SIPE_EPID_HASH_START + 1))

	int i,j;
	char out[SIPE_EPID_LENGTH + 1];
	char *buf = g_strdup_printf("%s:%s:%s", self_sip_uri, hostname, ip_address);
	guchar hash[SIPE_DIGEST_SHA1_LENGTH];

	sipe_digest_sha1((guchar *) buf, strlen(buf), hash);
	for (i = SIPE_EPID_HASH_START, j = 0;
	     i < SIPE_EPID_HASH_END;
	     i++, j += 2) {
		g_sprintf(&out[j], "%02x", hash[i]);
	}
	out[SIPE_EPID_LENGTH] = 0;

	g_free(buf);
	return g_strdup(out);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
