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
#include <time.h>
#include <glib.h>

#include "debug.h"

#include <sipe.h>
#include <sipe-cal.h>


static int
sipe_cal_get_current_status(guchar *free_busy,
			    time_t calStart,
			    int granularuty,
			    int *index)
{
	const char *nowStr;
	int res;
	int shift;
	time_t calEnd = calStart + strlen(free_busy)*granularuty*60 - 1;
	time_t now = time(NULL);
	
	if (!(now >= calStart && now <= calEnd)) return 4;
	
	nowStr = purple_utf8_strftime("%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
	printf("now=%s\n", nowStr);
	
	shift = (now - calStart) / (granularuty*60);
	*index = shift;
	printf("shift=%d\n", shift);

	res = free_busy[shift] - 0x30;
	
	return res;
}

static time_t
sipe_cal_get_switch_time(guchar *free_busy,
			 time_t calStart,
			 int granularuty,
			 int index,
			 int current_state)
{
	int i;
	
	if (index < 0 || index + 1 > strlen(free_busy)) return 0;
	
	for (i = index + 1; i < strlen(free_busy); i++) {
		int temp_status = free_busy[i] - 0x30;
		
		if ((current_state <  2 && temp_status >= 2) ||
		    (current_state >= 2 && temp_status  < 2)) 
		{
			break;
		}
	}
	printf("i_switch=%d\n", i);
	
	return calStart + i*granularuty*60;
}				   

char *
sipe_cal_get_description(struct sipe_buddy *buddy)
{
	time_t cal_start;
	int current_cal_state;
	time_t switch_time;
	const int granularity = 15; // Minutes
	int index;
	struct tm *switch_tm;
	char *res;
	const char *cal_states[] = {_("Free"),
				    _("Tentative"),
				    _("Busy"),
				    _("Out of Office"),
				    _("No data")};
	
	if (g_ascii_strcasecmp("PT15M", buddy->cal_granularity)) {
		purple_debug_info("sipe", "sipe_cal_get_description: granularity %s is unsupported, exiting.\n", buddy->cal_granularity);
		return NULL;
	}
	
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
	
	if (!buddy->cal_free_busy || !buddy->cal_granularity || !buddy->cal_start_time) return NULL;

	cal_start = purple_str_to_time(buddy->cal_start_time, FALSE, NULL, NULL, NULL);
	
	current_cal_state = sipe_cal_get_current_status(buddy->cal_free_busy, cal_start, granularity, &index);
	
	switch_time = sipe_cal_get_switch_time(buddy->cal_free_busy, cal_start, granularity, index, current_cal_state);	
	
	switch_tm = localtime(&switch_time);
	
	if (current_cal_state < 2 ) { //Free or Tentative
		res = g_strdup_printf(_("Free until %.2d:%.2d"),
				       switch_tm->tm_hour, switch_tm->tm_min);
	} else { //Busy or OOF
		res = g_strdup_printf(_("Currently %s. Free at %.2d:%.2d"),
				       cal_states[current_cal_state], switch_tm->tm_hour, switch_tm->tm_min);
	}
	
	return res;
}
