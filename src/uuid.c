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

#include <purple.h>
#include <glib.h>
#include "uuid.h"

static const char *epid_ns_uuid = "fcacfb03-8a73-46ef-91b1-e5ebeeaba4fe";

#define UUID_OFFSET_TO_LAST_SEGMENT 24

static void readUUID(const char *string, uuid_t *uuid)
{
	int i;
	sscanf(string, "%08x-%04x-%04x-%02x%02x-", &uuid->time_low
			, &uuid->time_mid, &uuid->time_hi_and_version
			, &uuid->clock_seq_hi_and_reserved
			, &uuid->clock_seq_low );

	for(i=0;i<6;i++)
	{
			sscanf(&string[UUID_OFFSET_TO_LAST_SEGMENT+i*2], "%02x", &uuid->node[i]);
	}
}

static void printUUID(uuid_t *uuid, char *string)
{
	int i;
	sprintf(string, "%08x-%04x-%04x-%02x%02x-", uuid->time_low
			, uuid->time_mid, uuid->time_hi_and_version
			, uuid->clock_seq_hi_and_reserved
			, uuid->clock_seq_low
			);
	for(i=0;i<6;i++)
	{
			sprintf(string, "%s%02x", string, uuid->node[i]);
	}
}

static void createUUIDfromHash(uuid_t *uuid, const unsigned char *hash)
{
	memcpy(uuid, hash, sizeof(uuid_t));
	uuid->time_hi_and_version &= 0x0FFF;
	uuid->time_hi_and_version |= 0x5000;
	uuid->clock_seq_hi_and_reserved &= 0x3F;
	uuid->clock_seq_hi_and_reserved |= 0x80;
}

char *generateUUIDfromEPID(const char *epid)
{
	uuid_t result;
	PurpleCipherContext *ctx;
	unsigned char hash[20];
	char buf[512];

	readUUID(epid_ns_uuid, &result);
	memcpy(buf, &result, sizeof(uuid_t));
	sprintf(&buf[sizeof(uuid_t)], epid);

	ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, buf, strlen(buf));
	purple_cipher_context_digest(ctx, sizeof(hash), hash, NULL);

	createUUIDfromHash(&result, hash);
	printUUID(&result, buf);
	return g_strdup(buf);
}
