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
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>


#ifndef _WIN32
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */
#include "internal.h"
#include <iphlpapi.h>
#endif /* _WIN32 */

#include <cipher.h>
#include <glib.h>
#include <glib/gprintf.h>
#include "uuid.h"

static const char *epid_ns_uuid = "fcacfb03-8a73-46ef-91b1-e5ebeeaba4fe";

#define UUID_OFFSET_TO_LAST_SEGMENT 24

void readUUID(const char *string, sipe_uuid_t *uuid)
{
	int i;
	sscanf(string, "%08x-%04hx-%04hx-%02hhx%02hhx-", &uuid->time_low
			, &uuid->time_mid, &uuid->time_hi_and_version
			, &uuid->clock_seq_hi_and_reserved
			, &uuid->clock_seq_low );

	for(i=0;i<6;i++)
	{
		sscanf(&string[UUID_OFFSET_TO_LAST_SEGMENT+i*2], "%02hhx", &uuid->node[i]);
	}
}

void printUUID(sipe_uuid_t *uuid, char *string)
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

void createUUIDfromHash(sipe_uuid_t *uuid, const unsigned char *hash)
{
	memcpy(uuid, hash, sizeof(sipe_uuid_t));
	uuid->time_hi_and_version &= 0x0FFF;
	uuid->time_hi_and_version |= 0x5000;
	uuid->clock_seq_hi_and_reserved &= 0x3F;
	uuid->clock_seq_hi_and_reserved |= 0x80;
}

char *generateUUIDfromEPID(const gchar *epid)
{
	sipe_uuid_t result;
	PurpleCipherContext *ctx;
	unsigned char hash[20];
	char buf[512];

	readUUID(epid_ns_uuid, &result);
	memcpy(buf, &result, sizeof(sipe_uuid_t));
	strcpy(&buf[sizeof(sipe_uuid_t)], epid);

	ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, (guchar *) buf, strlen(buf));
	purple_cipher_context_digest(ctx, sizeof(hash), hash, NULL);
	purple_cipher_context_destroy(ctx);

	createUUIDfromHash(&result, hash);
	printUUID(&result, buf);
	return g_strdup(buf);
}

/**
 * Generates epid from user SIP URI, hostname and IP address.
 * Thus epid will be the same each start and
 * not needed to be persistent.
 *
 * Using MAC address proved to be poorly portable solution.
 */
char *sipe_get_epid(const char *self_sip_uri,
			   const char *hostname,
			   const char *ip_address)
{
#define SIPE_EPID_HASH_START 15
#define SIPE_EPID_HASH_END   20
#define SIPE_EPID_LENGTH     (2 * (SIPE_EPID_HASH_END - SIPE_EPID_HASH_START + 1))

	int i,j;
	PurpleCipherContext *ctx;
	unsigned char hash[SIPE_EPID_HASH_END];
	char out[SIPE_EPID_LENGTH + 1];
	char *buf = g_strdup_printf("%s:%s:%s", self_sip_uri, hostname, ip_address);

	ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, (guchar *)buf, strlen(buf));
	purple_cipher_context_digest(ctx, sizeof(hash), hash, NULL);
	purple_cipher_context_destroy(ctx);

	for (i = SIPE_EPID_HASH_START, j = 0;
	     i <= SIPE_EPID_HASH_END;
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
