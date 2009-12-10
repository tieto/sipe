/**
 * @file sipe-cal.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
 *
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

#include <string.h>
#include <glib.h>

#include "debug.h"

#include <sipe.h>
#include <sipe-cal.h>

char *
sipe_cal_get_description(struct sipe_buddy *buddy)
{
	/* do lazy decode if necessary */
	if (!buddy->cal_free_busy && buddy->cal_free_busy_base64) {
		gsize cal_dec64_len;
		guchar *cal_dec64;
		int i;
		int j = 0;
		
		cal_dec64 = purple_base64_decode(buddy->cal_free_busy_base64, &cal_dec64_len);
		
		buddy->cal_free_busy = g_malloc0(cal_dec64_len * 4 + 1);
/* 
   http://msdn.microsoft.com/en-us/library/dd941537%28office.13%29.aspx
		00, Free (Fr)
		01, Tentative (Te)
		10, Busy (Bu)
		11, Out of facility (Oo)

   http://msdn.microsoft.com/en-us/library/aa566048.aspx	
		0  Free
		1  Tentative
		2  Busy
		3  Out of Office (OOF)
		4  No data
*/
		for (i = 0; i < cal_dec64_len; i++) {
			char tmp = cal_dec64[i];
			buddy->cal_free_busy[j++] = (tmp & 0x03) + 0x30;
			buddy->cal_free_busy[j++] = ((tmp >> 2) & 0x03) + 0x30;
			buddy->cal_free_busy[j++] = ((tmp >> 4) & 0x03) + 0x30;
			buddy->cal_free_busy[j++] = ((tmp >> 6) & 0x03) + 0x30;
		}
		buddy->cal_free_busy[j++] = '\0';
		
		purple_debug_info("sipe", "sipe_cal_get_description: buddy->cal_free_busy=\n%s\n", buddy->cal_free_busy);
	}
	
	
	return "";
}
