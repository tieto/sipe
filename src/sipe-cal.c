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

#include <stdlib.h>


#define TIME_NULL   (time_t)-1
#define IS(time)    (time != TIME_NULL)

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
	gchar *day_of_week; /* Sunday or Monday or Tuesday or Wednesday or Thursday or Friday or Saturday */
	gchar *year;        /* YYYY */
};

struct sipe_cal_working_hours {
	int bias;                     /* Ex.: 480 */
	struct sipe_cal_std_dst std;  /* StandardTime */
	struct sipe_cal_std_dst dst;  /* DaylightTime */
	gchar *days_of_week;          /* Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday separated by space */
	int start_time;               /* 0...1440 */
	int end_time;                 /* 0...1440 */

	gchar *tz;                    /* aggregated timezone string as in TZ environment variable.
	                                 Ex.: TST+8TDT+1,M3.2.0/02:00:00,M11.1.0/02:00:00 */
};

/* not for translation, a part of XML Schema definitions */
static const char *wday_names[] = {"Sunday",
				   "Monday",
				   "Tuesday",
				   "Wednesday",
				   "Thursday",
				   "Friday",
				   "Saturday"};
static int
sipe_cal_get_wday(char *wday_name)
{
	int i;

	if (!wday_name) return -1;

	for (i = 0; i < 7; i++) {
		if (!strcmp(wday_names[i], wday_name)) {
			return i;
		}
	}

	return -1;
}

static void
sipe_setenv(const char *name,
	    const char *value)
{
#ifndef _WIN32
	setenv(name, value, 1);
#else
	int len = strlen(name) + 1 + strlen(value) + 1;
	char *str = g_malloc0(len);
	sprintf(str, "%s=%s", name, value);
	putenv(str);
#endif
}

static void
sipe_unsetenv(const char *name)
{
#ifndef _WIN32
	unsetenv(name);
#else
	int len = strlen(name) + 1 + 1;
	char *str = g_malloc0(len);
	sprintf(str, "%s=", name);
	putenv(str);
#endif
}

/**
 * Converts struct tm to Epoch time_t considering timezone.
 *
 * @param tz as defined for TZ environment variable.
 *
 * Reference: see timegm(3) - Linux man page
 */
static time_t
sipe_mktime_tz(struct tm *tm,
	       const char* tz)
{
	time_t ret;
	char *tz_old;

	tz_old = getenv("TZ");
	sipe_setenv("TZ", tz);
	tzset();

	ret = mktime(tm);

	if (tz_old) {
		sipe_setenv("TZ", tz_old);
	} else {
		sipe_unsetenv("TZ");
	}
	tzset();

	return ret;
}

/**
 * Converts Epoch time_t to struct tm considering timezone.
 *
 * @param tz as defined for TZ environment variable.
 *
 * Reference: see timegm(3) - Linux man page
 */
static struct tm *
sipe_localtime_tz(const time_t *time,
		  const char* tz)
{
	struct tm *ret;
	char *tz_old;

	tz_old = getenv("TZ");
	sipe_setenv("TZ", tz);
	tzset();

	ret = localtime(time);

	if (tz_old) {
		sipe_setenv("TZ", tz_old);
	} else {
		sipe_unsetenv("TZ");
	}
	tzset();

	return ret;
}

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

	g_free(wh->days_of_week);
	g_free(wh->tz);
	g_free(wh);
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
		buddy->cal_working_hours->days_of_week =
			xmlnode_get_data(xmlnode_get_child(xn_working_period, "DayOfWeek"));

		buddy->cal_working_hours->start_time =
			atoi(tmp = xmlnode_get_data(xmlnode_get_child(xn_working_period, "StartTimeInMinutes")));
		g_free(tmp);

		buddy->cal_working_hours->end_time =
			atoi(tmp = xmlnode_get_data(xmlnode_get_child(xn_working_period, "EndTimeInMinutes")));
		g_free(tmp);
	}

	/* TST+8TDT-1,M3.2.0/02:00:00,M11.1.0/02:00:00 */
	buddy->cal_working_hours->tz =
		g_strdup_printf("TST%dTDT%d,M%d.%d.%d/%s,M%d.%d.%d/%s",
				(buddy->cal_working_hours->bias + buddy->cal_working_hours->std.bias ) / 60,
				buddy->cal_working_hours->dst.bias / 60,
				
				buddy->cal_working_hours->std.month,
				buddy->cal_working_hours->std.day_order,
				sipe_cal_get_wday(buddy->cal_working_hours->std.day_of_week),
				buddy->cal_working_hours->std.time,
				
				buddy->cal_working_hours->dst.month,
				buddy->cal_working_hours->dst.day_order,
				sipe_cal_get_wday(buddy->cal_working_hours->dst.day_of_week),
				buddy->cal_working_hours->dst.time
				);
}

static int
sipe_cal_get_current_status(const gchar *free_busy,
			    time_t calStart,
			    int granularity,
			    int *index)
{
	int res = 4;
	int shift;
	time_t calEnd = calStart + strlen(free_busy)*granularity*60 - 1;
	time_t now = time(NULL);

	if (!(now >= calStart && now <= calEnd)) return res;

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
	time_t ret = TIME_NULL;

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

static time_t
sipe_cal_mktime_of_day(struct tm *sample_today_tm,
		       int shift_minutes,
		       char *tz)
{
	sample_today_tm->tm_sec  = 0;
	sample_today_tm->tm_min  = shift_minutes % 60;
	sample_today_tm->tm_hour = shift_minutes / 60;
	
	return sipe_mktime_tz(sample_today_tm, tz);	
}

/**
 * Returns work day start and end in Epoch time
 * considering the initial values are provided
 * in contact's local time zone.
 */
static void
sipe_cal_get_today_work_hours(struct sipe_cal_working_hours *wh,
			      time_t *start,
			      time_t *end,
			      time_t *next_start)
{
	time_t now = time(NULL);
	struct tm *remote_now_tm = sipe_localtime_tz(&now, wh->tz);

	if (!strstr(wh->days_of_week, wday_names[remote_now_tm->tm_wday])) { /* not a work day */
		*start = TIME_NULL;
		*end = TIME_NULL;
		*next_start = TIME_NULL;
		return;
	}

	*end = sipe_cal_mktime_of_day(remote_now_tm, wh->end_time, wh->tz);

	if (now < *end) {
		*start = sipe_cal_mktime_of_day(remote_now_tm, wh->start_time, wh->tz);		
		*next_start = TIME_NULL;
	} else { /* calculate start of tomorrow's work day if any */
		time_t tom = now + 24*60*60;
		struct tm *remote_tom_tm = sipe_localtime_tz(&tom, wh->tz);

		if (!strstr(wh->days_of_week, wday_names[remote_tom_tm->tm_wday])) { /* not a work day */
			*next_start = TIME_NULL;
		}

		*next_start = sipe_cal_mktime_of_day(remote_tom_tm, wh->start_time, wh->tz);
		*start = TIME_NULL;
	}
}

static int
sipe_cal_is_in_work_hours(const time_t time_in_question,
			  const time_t start,
			  const time_t end)
{
	return !((time_in_question >= end) || (IS(start) && time_in_question < start));
}

/**
 * Returns time closest to now. Choses only from times ahead of now.
 * Returns TIME_NULL otherwise.
 */
static time_t
sipe_cal_get_until(const time_t now,
		   const time_t switch_time,
		   const time_t start,
		   const time_t end,
		   const time_t next_start)
{
	time_t ret = TIME_NULL;
	int min_diff = now - ret;
	
	if (IS(switch_time) && switch_time > now && (switch_time - now) < min_diff) {
		min_diff = switch_time - now;
		ret = switch_time;
	}
	if (IS(start) && start > now && (start - now) < min_diff) {
		min_diff = start - now;
		ret = start;
	}
	if (IS(end) && end > now && (end - now) < min_diff) {
		min_diff = end - now;
		ret = end;
	}
	if (IS(next_start) && next_start > now && (next_start - now) < min_diff) {
		min_diff = next_start - now;
		ret = next_start;
	}
	return ret;
}

char *
sipe_cal_get_description(struct sipe_buddy *buddy)
{
	time_t cal_start;
	int current_cal_state;
	time_t now = time(NULL);
	time_t start = TIME_NULL;
	time_t end = TIME_NULL;
	time_t next_start = TIME_NULL;
	time_t switch_time;
	int to_state = 0;
	time_t until = TIME_NULL;
	const int granularity = 15; /* Minutes */
	int index = 0;
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
		g_free(cal_dec64);

		purple_debug_info("sipe", "sipe_cal_get_description: buddy->cal_free_busy=\n%s\n", buddy->cal_free_busy);
	}

	if (!buddy->cal_free_busy || !buddy->cal_granularity || !buddy->cal_start_time) return NULL;

	cal_start = purple_str_to_time(buddy->cal_start_time, FALSE, NULL, NULL, NULL);

	current_cal_state = sipe_cal_get_current_status(buddy->cal_free_busy, cal_start, granularity, &index);
	if (current_cal_state == 4) {
		purple_debug_info("sipe", "sipe_cal_get_description: calendar is undefined for present moment, exiting.\n");
		return NULL;
	}

	switch_time = sipe_cal_get_switch_time(buddy->cal_free_busy, cal_start, granularity, index, current_cal_state, &to_state);

	if (buddy->cal_working_hours) {
		sipe_cal_get_today_work_hours(buddy->cal_working_hours, &start, &end, &next_start);

		printf("Remote now time     : %s",                  asctime(sipe_localtime_tz(&now,        buddy->cal_working_hours->tz)));
		printf("Remote start time   : %s", IS(start)      ? asctime(sipe_localtime_tz(&start,      buddy->cal_working_hours->tz)) : "\n");
		printf("Remote end time     : %s", IS(end)        ? asctime(sipe_localtime_tz(&end,        buddy->cal_working_hours->tz)) : "\n");
		printf("Rem. next_start time: %s", IS(next_start) ? asctime(sipe_localtime_tz(&next_start, buddy->cal_working_hours->tz)) : "\n");	
	}

	/* Calendar: string calculations */
	
	/*	
	ALGORITHM (don't delete)
	(c)2009 pier11 <pier11@operamail.com>
	
	SOD =  Start of Work Day
	EOD =  End of Work Day
	NSOD = Start of tomorrow's Work Day
	SW =   Calendar status switch time

	if current_cal_state == Free
		until = min_t of SOD, EOD, NSOD, SW (min_t(x) = min(x-now) where x>now only)
	else
		until = SW

	if (!until)
		return "Currently %", current_cal_state
		
	if (until - now > 8H)
		if (current_cal_state == Free && !in work hours)
			return "Outside of working hours for next 8 hours"
		else 
			return "%s for next 8 hours", current_cal_state

	if (current_cal_state == Free)
		if (in work hours)
			"%s", current_cal_state
		else
			"Not working"
		" until %.2d:%.2d", until	    
	else
		"Currently %", current_cal_state
		if (until is in work hours)
			". %s at %.2d:%.2d", to_state, until
		else
			". Outside of working hours at at %.2d:%.2d", until

	*/
	
	if (current_cal_state < 1) { /* Free */
		until = sipe_cal_get_until(now, switch_time, start, end, next_start);
	} else {
		until = switch_time;
	}

	if (!IS(until)) {
		return g_strdup_printf(_("Currently %s"), cal_states[current_cal_state]);
	}

	if (until - now > 8*60*60) {
		if (current_cal_state < 1 && !sipe_cal_is_in_work_hours(now, start, end)) { /** Free & outside work hours */
			return g_strdup(_("Outside of working hours for next 8 hours"));
		} else {
			return g_strdup_printf(_("%s for next 8 hours"), cal_states[current_cal_state]);
		}
	}
	
	if (current_cal_state < 1) { /* Free */
		const char *tmp;
		struct tm *until_tm = localtime(&until);

		if (sipe_cal_is_in_work_hours(now, start, end)) {
			tmp = cal_states[current_cal_state];
		} else {
			tmp = _("Not working");
		}
		return g_strdup_printf(_("%s until %.2d:%.2d"), tmp, until_tm->tm_hour, until_tm->tm_min);
	} else { /* Tentative or Busy or OOF */
		char *tmp;
		char *res;
		struct tm *until_tm = localtime(&until);

		tmp = g_strdup_printf(_("Currently %s"), cal_states[current_cal_state]);
		if (sipe_cal_is_in_work_hours(until, start, end)) {
			res = g_strdup_printf(_("%s. %s at %.2d:%.2d"), tmp, cal_states[to_state], until_tm->tm_hour, until_tm->tm_min);
			g_free(tmp);
			return res;
		} else {
			res = g_strdup_printf(_("%s. Outside of working hours at %.2d:%.2d"),
					      tmp, until_tm->tm_hour, until_tm->tm_min);
			g_free(tmp);
			return res;
		}
	}
	
	/* End of - Calendar: string calculations */
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
