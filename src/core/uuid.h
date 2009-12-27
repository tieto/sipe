/**
 * @file uuid.h
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

#ifndef SIPE_UUID_H_
#define SIPE_UUID_H_

#ifdef __NetBSD__
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

typedef struct _uuid_t {
   guint32 time_low;
   guint16 time_mid;
   guint16 time_hi_and_version;
   guint8  clock_seq_hi_and_reserved;
   guint8  clock_seq_low;
   guint8  node[6];
} sipe_uuid_t;

#ifdef __NetBSD__
#pragma pack()
#else
#pragma pack(pop)
#endif

char *generateUUIDfromEPID(const gchar *epid);
void printUUID(sipe_uuid_t *uuid, char *string);
void readUUID(const char *string, sipe_uuid_t *uuid);
void createUUIDfromHash(sipe_uuid_t *uuid, const unsigned char *hash);

char *sipe_get_epid(const char *self_sip_uri,
		    const char *hostname,
		    const char *ip_address);


#endif /* SIPE_UUID_H_ */
