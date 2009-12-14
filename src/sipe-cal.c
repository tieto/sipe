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
#include <sipe-utils.h>
#include <sipe-nls.h>

/*
http://msdn.microsoft.com/en-us/library/aa565001.aspx

<?xml version="1.0"?>
<WorkingHours xmlns="http://schemas.microsoft.com/exchange/services/2006/types">
  <TimeZone>
    <Bias>480</Bias>
    <StandardTime>
      <Bias>0</Bias>
      <Time>02:00:00</Time>
      <DayOrder>1</DayOrder>
      <Month>11</Month>
      <DayOfWeek>Sunday</DayOfWeek>
    </StandardTime>
    <DaylightTime>
      <Bias>-60</Bias>
      <Time>02:00:00</Time>
      <DayOrder>2</DayOrder>
      <Month>3</Month>
      <DayOfWeek>Sunday</DayOfWeek>
    </DaylightTime>
  </TimeZone>
  <WorkingPeriodArray>
    <WorkingPeriod>
      <DayOfWeek>Monday Tuesday Wednesday Thursday Friday</DayOfWeek>
      <StartTimeInMinutes>600</StartTimeInMinutes>
      <EndTimeInMinutes>1140</EndTimeInMinutes>
    </WorkingPeriod>
  </WorkingPeriodArray>
</WorkingHours>

Desc:
<StandardTime>
   <Bias>int</Bias>
   <Time>string</Time>
   <DayOrder>short</DayOrder>
   <Month>short</Month>
   <DayOfWeek>Sunday or Monday or Tuesday or Wednesday or Thursday or Friday or Saturday</DayOfWeek>
   <Year>string</Year>
</StandardTime>
*/

struct sipe_cal_std_dst {
	int bias;           /* Ex.: -60 */
	gchar *time;        /* hh:mm:ss, 02:00:00 */
	int day_order;      /* 1..5 */
	int month;          /* 1..12 */
	gchar *day_of_week; /* Sunday or Monday or Tuesday or Wednesday or Thursday or Friday */
	gchar *year;        /* YYYY */
};

struct sipe_cal_working_hours {
	int bias;                     /* Ex.: 480 */
	struct sipe_cal_std_dst std;  /* StandardTime */
	struct sipe_cal_std_dst dst;  /* DaylightTime */
	gchar **day_of_week;          /* Sunday, Monday, Tuesday, Wednesday, Thursday, Friday */
	int start_time;               /* 0...1440 */
	int end_time;                 /* 0...1440 */
};

void
sipe_cal_free_working_hours(struct sipe_cal_working_hours *wh)
{
	if (!wh) return;

	g_free(wh->std.time);
	g_free(wh->std.day_of_week);
	g_free(wh->std.year);

	g_free(wh->dst.time);
	g_free(wh->dst.day_of_week);
	g_free(wh->dst.year);

	g_strfreev(wh->day_of_week);
}

static void
sipe_cal_parse_std_dst(xmlnode *xn_std_dst_time,
		       struct sipe_cal_std_dst* std_dst)
{
	xmlnode *node;
	gchar *tmp;

	if (!xn_std_dst_time) return;
	if (!std_dst) return;
/*
    <StandardTime>
      <Bias>0</Bias>
      <Time>02:00:00</Time>
      <DayOrder>1</DayOrder>
      <Month>11</Month>
      <DayOfWeek>Sunday</DayOfWeek>
    </StandardTime>
*/

	if ((node = xmlnode_get_child(xn_std_dst_time, "Bias"))) {
		std_dst->bias = atoi(tmp = xmlnode_get_data(node));
		g_free(tmp);
	}

	if ((node = xmlnode_get_child(xn_std_dst_time, "Time"))) {
		std_dst->time = xmlnode_get_data(node);
	}

	if ((node = xmlnode_get_child(xn_std_dst_time, "DayOrder"))) {
		std_dst->day_order = atoi(tmp = xmlnode_get_data(node));
		g_free(tmp);
	}

	if ((node = xmlnode_get_child(xn_std_dst_time, "Month"))) {
		std_dst->month = atoi(tmp = xmlnode_get_data(node));
		g_free(tmp);
	}

	if ((node = xmlnode_get_child(xn_std_dst_time, "DayOfWeek"))) {
		std_dst->day_of_week = xmlnode_get_data(node);
	}

	if ((node = xmlnode_get_child(xn_std_dst_time, "Year"))) {
		std_dst->year = xmlnode_get_data(node);
	}
}

void
sipe_cal_parse_working_hours(xmlnode *xn_working_hours,
			     struct sipe_buddy *buddy)
{
	xmlnode *xn_bias;
	xmlnode *xn_working_period;
	xmlnode *xn_standard_time;
	xmlnode *xn_daylight_time;
	gchar *tmp;

	if (!xn_working_hours) return;
/*
<WorkingHours xmlns="http://schemas.microsoft.com/exchange/services/2006/types">
  <TimeZone>
    <Bias>480</Bias>
    ...
  </TimeZone>
  <WorkingPeriodArray>
    <WorkingPeriod>
      <DayOfWeek>Monday Tuesday Wednesday Thursday Friday</DayOfWeek>
      <StartTimeInMinutes>600</StartTimeInMinutes>
      <EndTimeInMinutes>1140</EndTimeInMinutes>
    </WorkingPeriod>
  </WorkingPeriodArray>
</WorkingHours>
*/
	sipe_cal_free_working_hours(buddy->cal_working_hours);
	buddy->cal_working_hours = g_new0(struct sipe_cal_working_hours, 1);

	xn_bias = xmlnode_get_descendant(xn_working_hours, "TimeZone", "Bias", NULL);
	if (xn_bias) {
		buddy->cal_working_hours->bias = atoi(tmp = xmlnode_get_data(xn_bias));
		g_free(tmp);
	}

	xn_standard_time = xmlnode_get_descendant(xn_working_hours, "TimeZone", "StandardTime", NULL);
	xn_daylight_time = xmlnode_get_descendant(xn_working_hours, "TimeZone", "DaylightTime", NULL);

	sipe_cal_parse_std_dst(xn_standard_time, &((*buddy->cal_working_hours).std));
	sipe_cal_parse_std_dst(xn_daylight_time, &((*buddy->cal_working_hours).dst));

	xn_working_period = xmlnode_get_descendant(xn_working_hours, "WorkingPeriodArray", "WorkingPeriod", NULL);
	if (xn_working_period) {
		buddy->cal_working_hours->day_of_week =
			g_strsplit(xmlnode_get_data(xmlnode_get_child(xn_working_period, "DayOfWeek")), " ", 0);

		buddy->cal_working_hours->start_time =
			atoi(tmp = xmlnode_get_data(xmlnode_get_child(xn_working_period, "StartTimeInMinutes")));
		g_free(tmp);

		buddy->cal_working_hours->end_time =
			atoi(tmp = xmlnode_get_data(xmlnode_get_child(xn_working_period, "EndTimeInMinutes")));
		g_free(tmp);
	}
}

static int
sipe_cal_get_current_status(const gchar *free_busy,
			    time_t calStart,
			    int granularity,
			    int *index)
{
	int res;
	int shift;
	time_t calEnd = calStart + strlen(free_busy)*granularity*60 - 1;
	time_t now = time(NULL);

	if (!(now >= calStart && now <= calEnd)) return 4;

	shift = (now - calStart) / (granularity*60);
	*index = shift;

	res = free_busy[shift] - 0x30;

	return res;
}

static time_t
sipe_cal_get_switch_time(const gchar *free_busy,
			 time_t calStart,
			 int granularity,
			 int index,
			 int current_state,
			 int *to_state)
{
	size_t i;
	time_t ret = (time_t)-1;

	if ((index < 0) || ((size_t) (index + 1) > strlen(free_busy)))
		return ret;

	for (i = index + 1; i < strlen(free_busy); i++) {
		int temp_status = free_busy[i] - 0x30;
		
		if (current_state != temp_status) {
			*to_state = temp_status;
			return calStart + i*granularity*60;
		}
	}

	return ret;
}

char *
sipe_cal_get_description(struct sipe_buddy *buddy)
{
	time_t cal_start;
	int current_cal_state;
	time_t switch_time;
	int to_state;
	const int granularity = 15; // Minutes
	int index = 0;
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
		gsize i;
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

	switch_time = sipe_cal_get_switch_time(buddy->cal_free_busy, cal_start, granularity, index, current_cal_state, &to_state);

	switch_tm = localtime(&switch_time);

	if (current_cal_state < 1 ) { //Free
		res = g_strdup_printf(_("Free until %.2d:%.2d"),
				       switch_tm->tm_hour, switch_tm->tm_min);
	} else { //Tentative or Busy or OOF
		res = g_strdup_printf(_("Currently %s. %s at %.2d:%.2d"),
				       cal_states[current_cal_state], cal_states[to_state], switch_tm->tm_hour, switch_tm->tm_min);
	}

	return res;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
