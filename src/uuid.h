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

#pragma pack(push, 1)

typedef struct _uuid_t {
   unsigned       time_low;
   unsigned short time_mid;
   unsigned short time_hi_and_version;
   unsigned char  clock_seq_hi_and_reserved;
   unsigned char  clock_seq_low;
   unsigned char  node[6];
} sipe_uuid_t;

#pragma pack(pop)

char *generateUUIDfromEPID(const gchar *epid);

gchar *sipe_uuid_get_macaddr(const char *ip_address);


void printUUID(sipe_uuid_t *uuid, char *string);
void readUUID(const char *string, sipe_uuid_t *uuid);
void createUUIDfromHash(sipe_uuid_t *uuid, const unsigned char *hash);
long mac_addr_sys (const unsigned char *addr);


#endif /* SIPE_UUID_H_ */
