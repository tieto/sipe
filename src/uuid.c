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
#include <linux/if.h>
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
	sprintf(&buf[sizeof(sipe_uuid_t)], epid);

	ctx = purple_cipher_context_new_by_name("sha1", NULL);
	purple_cipher_context_append(ctx, buf, strlen(buf));
	purple_cipher_context_digest(ctx, sizeof(hash), hash, NULL);
	purple_cipher_context_destroy(ctx);

	createUUIDfromHash(&result, hash);
	printUUID(&result, buf);
	return g_strdup(buf);
}

#ifndef _WIN32
long mac_addr_sys (const char *addr)
{
/* implementation for Linux */
    struct ifreq ifr;
    struct ifreq *IFR;
    struct ifconf ifc;
    char buf[1024];
    int s, i;
    int ok = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s==-1) {
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ioctl(s, SIOCGIFCONF, &ifc);

    IFR = ifc.ifc_req;
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; IFR++) {

        strcpy(ifr.ifr_name, IFR->ifr_name);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                    ok = 1;
                    break;
                }
            }
        }
    }

    close(s);
    if (ok) {
        memmove((void *)addr, ifr.ifr_hwaddr.sa_data, 6);
    }
    else {
        return -1;
    }
    return 0;
}

#else

static char *get_mac_address_win(const char *ip_address)
{
	IP_ADAPTER_INFO AdapterInfo[16]; // for up to 16 NICs
	DWORD ulOutBufLen = sizeof(AdapterInfo);
	PIP_ADAPTER_INFO pAdapter_res = NULL;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;
	char *res = NULL;
	
	if ((dwRetVal = GetAdaptersInfo(AdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = AdapterInfo;
		pAdapter_res = pAdapter;
		while (pAdapter) {
			if (!g_ascii_strcasecmp(pAdapter->IpAddressList.IpAddress.String, ip_address)) {
				pAdapter_res = pAdapter;				
				break;
			}
			pAdapter = pAdapter->Next;
		}
	} else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
	}
	
	if (pAdapter_res) {
		gchar nmac[13];
		for (i = 0; i < pAdapter_res->AddressLength; i++) {
			g_sprintf(&nmac[(i*2)], "%02X", (int)pAdapter_res->Address[i]);
		}
		printf("NIC: %s, IP Address: %s, MAC Addres: %s\n", pAdapter_res->Description, pAdapter_res->IpAddressList.IpAddress.String, nmac);
		res = g_strdup(nmac);
	} else {
		res = g_strdup("01010101");
	}
	
	//@TODO free AdapterInfo
	return res;
}
#endif /* _WIN32 */

gchar * sipe_uuid_get_macaddr(const char *ip_address)
{
#ifndef _WIN32
	guchar addr[6];
	long mac_add = mac_addr_sys(addr);
	gchar nmac[13];
	
	if (mac_add == 0){
		int i,j;
		for (i = 0,j=0; i < 6; i++,j+=2) {
			g_sprintf(&nmac[j], "%02X", addr[i]);
		}
		return g_strdup(nmac);
	}
	return g_strdup_printf("01010101");  //Default
#else
	return get_mac_address_win(ip_address);
#endif /* _WIN32 */
}
