/**
 * @file sipe-cal.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-cal.h"
#include "sipe-http.h"
#include "sipe-nls.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/* Calendar backends */
#ifdef _WIN32
#include "sipe-domino.h"
#endif
#include "sipe-ews.h"

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

	time_t switch_time;
};

struct sipe_cal_working_hours {
	int bias;                     /* Ex.: 480 */
	struct sipe_cal_std_dst std;  /* StandardTime */
	struct sipe_cal_std_dst dst;  /* DaylightTime */
	gchar *days_of_week;          /* Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday separated by space */
	int start_time;               /* 0...1440 */
	int end_time;                 /* 0...1440 */

	gchar *tz;                    /* aggregated timezone string as in TZ environment variable.
	                                 Ex.: TST+8TDT+7,M3.2.0/02:00:00,M11.1.0/02:00:00 */
	/** separate simple strings for Windows platform as the proper TZ does not work there.
	 *  anyway, dynamic timezones would't work with just TZ
	 */
	gchar *tz_std;                /* Ex.: TST8 */
	gchar *tz_dst;                /* Ex.: TDT7 */
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
		if (sipe_strequal(wday_names[i], wday_name)) {
			return i;
		}
	}

	return -1;
}

void
sipe_cal_event_free(struct sipe_cal_event* cal_event)
{
	if (!cal_event) return;

	g_free(cal_event->subject);
	g_free(cal_event->location);
	g_free(cal_event);
}

void
sipe_cal_events_free(GSList *cal_events)
{
	if (!cal_events) return;
	sipe_utils_slist_free_full(cal_events,
				   (GDestroyNotify) sipe_cal_event_free);
}

void
sipe_cal_calendar_free(struct sipe_calendar *cal)
{
	if (cal) {
		g_free(cal->email);
		g_free(cal->legacy_dn);
		g_free(cal->as_url);
		g_free(cal->oof_url);
		g_free(cal->oab_url);
		g_free(cal->domino_url);
		g_free(cal->oof_state);
		g_free(cal->oof_note);
		g_free(cal->free_busy);
		g_free(cal->working_hours_xml_str);

		sipe_cal_events_free(cal->cal_events);

		if (cal->request)
			sipe_http_request_cancel(cal->request);
		sipe_http_session_close(cal->session);

		g_free(cal);
	}
}

void
sipe_cal_calendar_init(struct sipe_core_private *sipe_private)
{
	if (!sipe_private->calendar) {
		struct sipe_calendar *cal;
		const char *value;

		sipe_private->calendar = cal = g_new0(struct sipe_calendar, 1);
		cal->sipe_private = sipe_private;

		cal->email = g_strdup(sipe_private->email);

		/* user specified a service URL? */
		value = sipe_backend_setting(SIPE_CORE_PUBLIC, SIPE_SETTING_EMAIL_URL);
		if (!is_empty(value)) {
			cal->as_url  = g_strdup(value);
			cal->oof_url = g_strdup(value);
			cal->domino_url  = g_strdup(value);
		}
	}
	return;
}


char *
sipe_cal_event_describe(struct sipe_cal_event* cal_event)
{
	GString* str = g_string_new(NULL);
	const char *status = "";

	switch(cal_event->cal_status) {
		case SIPE_CAL_FREE:		status = "SIPE_CAL_FREE";	break;
		case SIPE_CAL_TENTATIVE:	status = "SIPE_CAL_TENTATIVE";	break;
		case SIPE_CAL_BUSY:		status = "SIPE_CAL_BUSY";	break;
		case SIPE_CAL_OOF:		status = "SIPE_CAL_OOF";	break;
		case SIPE_CAL_NO_DATA:		status = "SIPE_CAL_NO_DATA";	break;
	}

	g_string_append_printf(str, "\t%s: %s",   "start_time",
		IS(cal_event->start_time) ? asctime(localtime(&cal_event->start_time)) : "\n");
	g_string_append_printf(str, "\t%s: %s",   "end_time  ",
		IS(cal_event->end_time) ? asctime(localtime(&cal_event->end_time)) : "\n");
	g_string_append_printf(str, "\t%s: %s\n", "cal_status",  status);
	g_string_append_printf(str, "\t%s: %s\n", "subject   ",  cal_event->subject ? cal_event->subject : "");
	g_string_append_printf(str, "\t%s: %s\n", "location  ",  cal_event->location ? cal_event->location : "");
	g_string_append_printf(str, "\t%s: %s\n", "is_meeting",  cal_event->is_meeting ? "TRUE" : "FALSE");

	return g_string_free(str, FALSE);
}

char *
sipe_cal_event_hash(struct sipe_cal_event* event)
{
	/* no end_time as it dos not get published */
	/* no cal_status as it can change on publication */
	return g_strdup_printf("<%d><%s><%s><%d>",
				(int)event->start_time,
				event->subject ? event->subject : "",
				event->location ? event->location : "",
				event->is_meeting);
}

#define ENVIRONMENT_TIMEZONE "TZ"

static gchar *
sipe_switch_tz(const char *tz)
{
	gchar *tz_orig;

	tz_orig = g_strdup(g_getenv(ENVIRONMENT_TIMEZONE));
	g_setenv(ENVIRONMENT_TIMEZONE, tz, TRUE);
	tzset();
	return(tz_orig);
}

static void
sipe_reset_tz(gchar *tz_orig)
{
	if (tz_orig) {
		g_setenv(ENVIRONMENT_TIMEZONE, tz_orig, TRUE);
		g_free(tz_orig);
	} else {
		g_unsetenv(ENVIRONMENT_TIMEZONE);
	}
	tzset();
}

/**
 * Converts struct tm to Epoch time_t considering timezone.
 *
 * @param tz as defined for TZ environment variable.
 *
 * Reference: see timegm(3) - Linux man page
 */
time_t
sipe_mktime_tz(struct tm *tm,
	       const char* tz)
{
	time_t ret;
	gchar *tz_orig;

	tz_orig = sipe_switch_tz(tz);
	ret = mktime(tm);
	sipe_reset_tz(tz_orig);

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
	gchar *tz_orig;

	tz_orig = sipe_switch_tz(tz);
	ret = localtime(time);
	sipe_reset_tz(tz_orig);

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
	g_free(wh->tz_std);
	g_free(wh->tz_dst);
	g_free(wh);
}

/**
 * Returns time_t of daylight savings time start/end
 * in the provided timezone or otherwise
 * (time_t)-1 if no daylight savings time.
 */
static time_t
sipe_cal_get_std_dst_time(time_t now,
			  int bias,
			  struct sipe_cal_std_dst* std_dst,
			  struct sipe_cal_std_dst* dst_std)
{
	struct tm switch_tm;
	time_t res = TIME_NULL;
	struct tm *gm_now_tm;
	gchar **time_arr;

	if (std_dst->month == 0) return TIME_NULL;

	gm_now_tm = gmtime(&now);
	time_arr = g_strsplit(std_dst->time, ":", 0);

	switch_tm.tm_sec  = atoi(time_arr[2]);
	switch_tm.tm_min  = atoi(time_arr[1]);
	switch_tm.tm_hour = atoi(time_arr[0]);
	g_strfreev(time_arr);
	switch_tm.tm_mday  = std_dst->year ? std_dst->day_order : 1 /* to adjust later */ ;
	switch_tm.tm_mon   = std_dst->month - 1;
	switch_tm.tm_year  = std_dst->year ? atoi(std_dst->year) - 1900 : gm_now_tm->tm_year;
	switch_tm.tm_isdst = 0;
	/* to set tm_wday */
	res = sipe_mktime_tz(&switch_tm, "UTC");

	/* if not dynamic, calculate right tm_mday */
	if (!std_dst->year) {
		int switch_wday = sipe_cal_get_wday(std_dst->day_of_week);
		int needed_month;
		/* get first desired wday in the month */
		int delta = switch_wday >= switch_tm.tm_wday ? (switch_wday - switch_tm.tm_wday) : (switch_wday + 7 - switch_tm.tm_wday);
		switch_tm.tm_mday = 1 + delta;
		/* try nth order */
		switch_tm.tm_mday += (std_dst->day_order - 1) * 7;
		needed_month = switch_tm.tm_mon;
		/* to set settle date if ahead of allowed month dates */
		res = sipe_mktime_tz(&switch_tm, "UTC");
		if (needed_month != switch_tm.tm_mon) {
			/* moving 1 week back to stay within required month */
			switch_tm.tm_mday -= 7;
			/* to fix date again */
			res = sipe_mktime_tz(&switch_tm, "UTC");
		}
	}
	/* note: bias is taken from "switch to" structure */
	return res + (bias + dst_std->bias)*60;
}

static void
sipe_cal_parse_std_dst(const sipe_xml *xn_std_dst_time,
		       struct sipe_cal_std_dst *std_dst)
{
	const sipe_xml *node;
	gchar *tmp;

	if (!xn_std_dst_time) return;
	if (!std_dst) return;
/*
    <StandardTime>
      <Bias>0</Bias>
      <Time>02:00:00</Time>
      <DayOrder>1</DayOrder>
      <Month>11</Month>
      <Year>2009</Year>
      <DayOfWeek>Sunday</DayOfWeek>
    </StandardTime>
*/

	if ((node = sipe_xml_child(xn_std_dst_time, "Bias"))) {
		std_dst->bias = atoi(tmp = sipe_xml_data(node));
		g_free(tmp);
	}

	if ((node = sipe_xml_child(xn_std_dst_time, "Time"))) {
		std_dst->time = sipe_xml_data(node);
	}

	if ((node = sipe_xml_child(xn_std_dst_time, "DayOrder"))) {
		std_dst->day_order = atoi(tmp = sipe_xml_data(node));
		g_free(tmp);
	}

	if ((node = sipe_xml_child(xn_std_dst_time, "Month"))) {
		std_dst->month = atoi(tmp = sipe_xml_data(node));
		g_free(tmp);
	}

	if ((node = sipe_xml_child(xn_std_dst_time, "DayOfWeek"))) {
		std_dst->day_of_week = sipe_xml_data(node);
	}

	if ((node = sipe_xml_child(xn_std_dst_time, "Year"))) {
		std_dst->year = sipe_xml_data(node);
	}
}

void
sipe_cal_parse_working_hours(const sipe_xml *xn_working_hours,
			     struct sipe_buddy *buddy)
{
	const sipe_xml *xn_bias;
	const sipe_xml *xn_timezone;
	const sipe_xml *xn_working_period;
	const sipe_xml *xn_standard_time;
	const sipe_xml *xn_daylight_time;
	gchar *tmp;
	time_t now = time(NULL);
	struct sipe_cal_std_dst* std;
	struct sipe_cal_std_dst* dst;

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

	xn_timezone = sipe_xml_child(xn_working_hours, "TimeZone");
	xn_bias = sipe_xml_child(xn_timezone, "Bias");
	if (xn_bias) {
		buddy->cal_working_hours->bias = atoi(tmp = sipe_xml_data(xn_bias));
		g_free(tmp);
	}

	xn_standard_time = sipe_xml_child(xn_timezone, "StandardTime");
	xn_daylight_time = sipe_xml_child(xn_timezone, "DaylightTime");

	std = &((*buddy->cal_working_hours).std);
	dst = &((*buddy->cal_working_hours).dst);
	sipe_cal_parse_std_dst(xn_standard_time, std);
	sipe_cal_parse_std_dst(xn_daylight_time, dst);

	xn_working_period = sipe_xml_child(xn_working_hours, "WorkingPeriodArray/WorkingPeriod");
	if (xn_working_period) {
		/* NOTE: this can be NULL! */
		buddy->cal_working_hours->days_of_week =
			sipe_xml_data(sipe_xml_child(xn_working_period, "DayOfWeek"));

		buddy->cal_working_hours->start_time =
			atoi(tmp = sipe_xml_data(sipe_xml_child(xn_working_period, "StartTimeInMinutes")));
		g_free(tmp);

		buddy->cal_working_hours->end_time =
			atoi(tmp = sipe_xml_data(sipe_xml_child(xn_working_period, "EndTimeInMinutes")));
		g_free(tmp);
	}

	std->switch_time = sipe_cal_get_std_dst_time(now, buddy->cal_working_hours->bias, std, dst);
	dst->switch_time = sipe_cal_get_std_dst_time(now, buddy->cal_working_hours->bias, dst, std);

	/* TST8TDT7,M3.2.0/02:00:00,M11.1.0/02:00:00 */
	buddy->cal_working_hours->tz =
		g_strdup_printf("TST%dTDT%d,M%d.%d.%d/%s,M%d.%d.%d/%s",
				(buddy->cal_working_hours->bias + buddy->cal_working_hours->std.bias) / 60,
				(buddy->cal_working_hours->bias + buddy->cal_working_hours->dst.bias) / 60,

				buddy->cal_working_hours->dst.month,
				buddy->cal_working_hours->dst.day_order,
				sipe_cal_get_wday(buddy->cal_working_hours->dst.day_of_week),
				buddy->cal_working_hours->dst.time,

				buddy->cal_working_hours->std.month,
				buddy->cal_working_hours->std.day_order,
				sipe_cal_get_wday(buddy->cal_working_hours->std.day_of_week),
				buddy->cal_working_hours->std.time
				);
	/* TST8 */
	buddy->cal_working_hours->tz_std =
		g_strdup_printf("TST%d",
				(buddy->cal_working_hours->bias + buddy->cal_working_hours->std.bias) / 60);
	/* TDT7 */
	buddy->cal_working_hours->tz_dst =
		g_strdup_printf("TDT%d",
				(buddy->cal_working_hours->bias + buddy->cal_working_hours->dst.bias) / 60);
}

struct sipe_cal_event*
sipe_cal_get_event(GSList *cal_events,
		   time_t time_in_question)
{
	GSList *entry = cal_events;
	struct sipe_cal_event* cal_event;
	struct sipe_cal_event* res = NULL;

	if (!cal_events || !IS(time_in_question)) return NULL;

	while (entry) {
		cal_event = entry->data;
		/* event is in the past or in the future */
		if (cal_event->start_time >  time_in_question  ||
		    cal_event->end_time   <= time_in_question)
		{
			entry = entry->next;
			continue;
		}

		if (!res) {
			res = cal_event;
		} else {
			int res_status = (res->cal_status == SIPE_CAL_NO_DATA) ? -1 : res->cal_status;
			int cal_status = (cal_event->cal_status == SIPE_CAL_NO_DATA) ? -1 : cal_event->cal_status;
			if (res_status < cal_status) {
				res = cal_event;
			}
		}
		entry = entry->next;
	}
	return res;
}

static int
sipe_cal_get_status0(const gchar *free_busy,
		     time_t cal_start,
		     int granularity,
		     time_t time_in_question,
		     int *index)
{
	int res = SIPE_CAL_NO_DATA;
	int shift;
	time_t cal_end = cal_start + strlen(free_busy)*granularity*60 - 1;

	if (!(time_in_question >= cal_start && time_in_question <= cal_end)) return res;

	shift = (time_in_question - cal_start) / (granularity*60);
	if (index) {
		*index = shift;
	}

	res = free_busy[shift] - '0';

	return res;
}

/**
 * Returns time when current calendar state started
 */
static time_t
sipe_cal_get_since_time(const gchar *free_busy,
			time_t calStart,
			int granularity,
			int index,
			int current_state)
{
	int i;

	if ((index < 0) || ((size_t)(index + 1) > strlen(free_busy))) return 0;

	for (i = index; i >= 0; i--) {
		int temp_status = free_busy[i] - '0';

		if (current_state != temp_status) {
			return calStart + (i + 1)*granularity*60;
		}

		if (i == 0) return calStart;
	}

	return 0;
}
static char*
sipe_cal_get_free_busy(struct sipe_buddy *buddy);

int
sipe_cal_get_status(struct sipe_buddy *buddy,
		    time_t time_in_question,
		    time_t *since)
{
	time_t cal_start;
	const char* free_busy;
	int ret = SIPE_CAL_NO_DATA;
	time_t state_since;
	int index = -1;

	if (!buddy || !buddy->cal_start_time || !buddy->cal_granularity) {
		SIPE_DEBUG_INFO("sipe_cal_get_status: no calendar data1 for %s, exiting",
				  buddy ? (buddy->name ? buddy->name : "") : "");
		return SIPE_CAL_NO_DATA;
	}

	if (!(free_busy = sipe_cal_get_free_busy(buddy))) {
		SIPE_DEBUG_INFO("sipe_cal_get_status: no calendar data2 for %s, exiting", buddy->name);
		return SIPE_CAL_NO_DATA;
	}
	SIPE_DEBUG_INFO("sipe_cal_get_description: buddy->cal_free_busy=\n%s", free_busy);

	cal_start = sipe_utils_str_to_time(buddy->cal_start_time);

	ret = sipe_cal_get_status0(free_busy,
				   cal_start,
				   buddy->cal_granularity,
				   time_in_question,
				   &index);
	state_since = sipe_cal_get_since_time(free_busy,
					      cal_start,
					      buddy->cal_granularity,
					      index,
					      ret);

	if (since) *since = state_since;
	return ret;
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

	if ((index < 0) || ((size_t) (index + 1) > strlen(free_busy))) {
		*to_state = SIPE_CAL_NO_DATA;
		return ret;
	}

	for (i = index + 1; i < strlen(free_busy); i++) {
		int temp_status = free_busy[i] - '0';

		if (current_state != temp_status) {
			*to_state = temp_status;
			return calStart + i*granularity*60;
		}
	}

	return ret;
}

static const char*
sipe_cal_get_tz(struct sipe_cal_working_hours *wh,
                time_t time_in_question)
{
	time_t dst_switch_time = (*wh).dst.switch_time;
	time_t std_switch_time = (*wh).std.switch_time;
	gboolean is_dst = FALSE;

	/* No daylight savings */
	if (dst_switch_time == TIME_NULL) {
		return wh->tz_std;
	}

	if (dst_switch_time < std_switch_time) { /* North hemosphere - Europe, US */
		if (time_in_question >= dst_switch_time && time_in_question < std_switch_time) {
			is_dst = TRUE;
		}
	} else { /* South hemisphere - Australia */
		if (time_in_question >= dst_switch_time || time_in_question < std_switch_time) {
			is_dst = TRUE;
		}
	}

	if (is_dst) {
		return wh->tz_dst;
	} else {
		return wh->tz_std;
	}
}

static time_t
sipe_cal_mktime_of_day(struct tm *sample_today_tm,
		       const int shift_minutes,
		       const char *tz)
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
	const char *tz = sipe_cal_get_tz(wh, now);
	struct tm *remote_now_tm = sipe_localtime_tz(&now, tz);

	if (!(wh->days_of_week && strstr(wh->days_of_week, wday_names[remote_now_tm->tm_wday]))) {
		/* not a work day */
		*start = TIME_NULL;
		*end = TIME_NULL;
		*next_start = TIME_NULL;
		return;
	}

	*end = sipe_cal_mktime_of_day(remote_now_tm, wh->end_time, tz);

	if (now < *end) {
		*start = sipe_cal_mktime_of_day(remote_now_tm, wh->start_time, tz);
		*next_start = TIME_NULL;
	} else { /* calculate start of tomorrow's work day if any */
		time_t tom = now + 24*60*60;
		struct tm *remote_tom_tm = sipe_localtime_tz(&tom, sipe_cal_get_tz(wh, tom));

		if (!(wh->days_of_week && strstr(wh->days_of_week, wday_names[remote_tom_tm->tm_wday]))) {
			/* not a work day */
			*next_start = TIME_NULL;
		}

		*next_start = sipe_cal_mktime_of_day(remote_tom_tm, wh->start_time, sipe_cal_get_tz(wh, tom));
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

static char*
sipe_cal_get_free_busy(struct sipe_buddy *buddy)
{
/* do lazy decode if necessary */
	if (!buddy->cal_free_busy && buddy->cal_free_busy_base64) {
		gsize cal_dec64_len;
		guchar *cal_dec64;
		gsize i;
		int j = 0;

		cal_dec64 = g_base64_decode(buddy->cal_free_busy_base64, &cal_dec64_len);

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
#define TWO_BIT_MASK	0x03
			char tmp = cal_dec64[i];
			buddy->cal_free_busy[j++] = (tmp & TWO_BIT_MASK) + '0';
			buddy->cal_free_busy[j++] = ((tmp >> 2) & TWO_BIT_MASK) + '0';
			buddy->cal_free_busy[j++] = ((tmp >> 4) & TWO_BIT_MASK) + '0';
			buddy->cal_free_busy[j++] = ((tmp >> 6) & TWO_BIT_MASK) + '0';
		}
		buddy->cal_free_busy[j++] = '\0';
		g_free(cal_dec64);
	}

	return buddy->cal_free_busy;
}

char *
sipe_cal_get_freebusy_base64(const char* freebusy_hex)
{
	guint i = 0;
	guint j = 0;
	guint shift_factor = 0;
	guint len, res_len;
	guchar *res;
	gchar *res_base64;

	if (!freebusy_hex) return NULL;

	len = strlen(freebusy_hex);
	res_len = len / 4 + 1;
	res = g_malloc0(res_len);
	while (i < len) {
		res[j] |= (freebusy_hex[i++] - '0') << shift_factor;
		shift_factor += 2;
		if (shift_factor == 8) {
			shift_factor = 0;
			j++;
		}
	}

	res_base64 = g_base64_encode(res, shift_factor ? res_len : res_len - 1);
	g_free(res);
	return res_base64;
}

char *
sipe_cal_get_description(struct sipe_buddy *buddy)
{
	time_t cal_start;
	time_t cal_end;
	int current_cal_state;
	time_t now = time(NULL);
	time_t start = TIME_NULL;
	time_t end = TIME_NULL;
	time_t next_start = TIME_NULL;
	time_t switch_time;
	int to_state = SIPE_CAL_NO_DATA;
	time_t until = TIME_NULL;
	int index = 0;
	gboolean has_working_hours = (buddy->cal_working_hours != NULL);
	const char *free_busy;
	const char *cal_states[] = {_("Free"),
				    _("Tentative"),
				    _("Busy"),
				    _("Out of office"),
				    _("No data")};

	if (buddy->cal_granularity != 15) {
		SIPE_DEBUG_INFO("sipe_cal_get_description: granularity %d is unsupported, exiting.", buddy->cal_granularity);
		return NULL;
	}

	/* to lazy load if needed */
	free_busy = sipe_cal_get_free_busy(buddy);
	SIPE_DEBUG_INFO("sipe_cal_get_description: buddy->cal_free_busy=\n%s", free_busy ? free_busy : "");

	if (!buddy->cal_free_busy || !buddy->cal_granularity || !buddy->cal_start_time) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_cal_get_description: no calendar data, exiting");
		return NULL;
	}

	cal_start = sipe_utils_str_to_time(buddy->cal_start_time);
	cal_end = cal_start + 60 * (buddy->cal_granularity) * strlen(buddy->cal_free_busy);

	current_cal_state = sipe_cal_get_status0(free_busy, cal_start, buddy->cal_granularity, time(NULL), &index);
	if (current_cal_state == SIPE_CAL_NO_DATA) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_cal_get_description: calendar is undefined for present moment, exiting.");
		return NULL;
	}

	switch_time = sipe_cal_get_switch_time(free_busy, cal_start, buddy->cal_granularity, index, current_cal_state, &to_state);

	SIPE_DEBUG_INFO_NOFORMAT("\n* Calendar *");
	if (buddy->cal_working_hours) {
		sipe_cal_get_today_work_hours(buddy->cal_working_hours, &start, &end, &next_start);

		SIPE_DEBUG_INFO("Remote now timezone : %s", sipe_cal_get_tz(buddy->cal_working_hours, now));
		SIPE_DEBUG_INFO("std.switch_time(GMT): %s",
				IS((*buddy->cal_working_hours).std.switch_time) ? asctime(gmtime(&((*buddy->cal_working_hours).std.switch_time))) : "");
		SIPE_DEBUG_INFO("dst.switch_time(GMT): %s",
				IS((*buddy->cal_working_hours).dst.switch_time) ? asctime(gmtime(&((*buddy->cal_working_hours).dst.switch_time))) : "");
		SIPE_DEBUG_INFO("Remote now time     : %s",
			asctime(sipe_localtime_tz(&now, sipe_cal_get_tz(buddy->cal_working_hours, now))));
		SIPE_DEBUG_INFO("Remote start time   : %s",
			IS(start) ? asctime(sipe_localtime_tz(&start, sipe_cal_get_tz(buddy->cal_working_hours, start))) : "");
		SIPE_DEBUG_INFO("Remote end time     : %s",
			IS(end) ? asctime(sipe_localtime_tz(&end, sipe_cal_get_tz(buddy->cal_working_hours, end))) : "");
		SIPE_DEBUG_INFO("Rem. next_start time: %s",
			IS(next_start) ? asctime(sipe_localtime_tz(&next_start, sipe_cal_get_tz(buddy->cal_working_hours, next_start))) : "");
		SIPE_DEBUG_INFO("Remote switch time  : %s",
			IS(switch_time) ? asctime(sipe_localtime_tz(&switch_time, sipe_cal_get_tz(buddy->cal_working_hours, switch_time))) : "");
	} else {
		SIPE_DEBUG_INFO("Local now time      : %s",
			asctime(localtime(&now)));
		SIPE_DEBUG_INFO("Local switch time   : %s",
			IS(switch_time) ? asctime(localtime(&switch_time)) : "");
	}
	SIPE_DEBUG_INFO("Calendar End (GMT)  : %s", asctime(gmtime(&cal_end)));
	SIPE_DEBUG_INFO("current cal state   : %s", cal_states[current_cal_state]);
	SIPE_DEBUG_INFO("switch  cal state   : %s", cal_states[to_state]         );

	/* Calendar: string calculations */

	/*
	ALGORITHM (don't delete)
	(c)2009,2010 pier11 <pier11@operamail.com>

	SOD =  Start of Work Day
	EOD =  End of Work Day
	NSOD = Start of tomorrow's Work Day
	SW =   Calendar status switch time

	if current_cal_state == Free
		until = min_t of SOD, EOD, NSOD, SW (min_t(x) = min(x-now) where x>now only)
	else
		until = SW

	if (!until && (cal_period_end > now + 8H))
		until = cal_period_end

	if (!until)
		return "Currently %", current_cal_state

	if (until - now > 8H)
		if (current_cal_state == Free && (work_hours && !in work_hours(now)))
			return "Outside of working hours for next 8 hours"
		else
			return "%s for next 8 hours", current_cal_state

	if (current_cal_state == Free)
		if (work_hours && until !in work_hours(now))
			"Not working"
		else
			"%s", current_cal_state
		" until %.2d:%.2d", until
	else
		"Currently %", current_cal_state
		if (work_hours && until !in work_hours(until))
			". Outside of working hours at at %.2d:%.2d", until
		else
			". %s at %.2d:%.2d", to_state, until
	*/

	if (current_cal_state < 1) { /* Free */
		until = sipe_cal_get_until(now, switch_time, start, end, next_start);
	} else {
		until = switch_time;
	}

	if (!IS(until) && (cal_end - now > 8*60*60))
		until = cal_end;

	if (!IS(until)) {
		return g_strdup_printf(_("Currently %s"), cal_states[current_cal_state]);
	}

	if (until - now > 8*60*60) {
		/* Free & outside work hours */
		if (current_cal_state < 1 && has_working_hours && !sipe_cal_is_in_work_hours(now, start, end)) {
			return g_strdup(_("Outside of working hours for next 8 hours"));
		} else {
			return g_strdup_printf(_("%s for next 8 hours"), cal_states[current_cal_state]);
		}
	}

	if (current_cal_state < 1) { /* Free */
		const char *tmp;
		struct tm *until_tm = localtime(&until);

		if (has_working_hours && !sipe_cal_is_in_work_hours(now, start, end)) {
			tmp = _("Not working");
		} else {
			tmp = cal_states[current_cal_state];
		}
		return g_strdup_printf(_("%s until %.2d:%.2d"), tmp, until_tm->tm_hour, until_tm->tm_min);
	} else { /* Tentative or Busy or OOF */
		char *tmp;
		char *res;
		struct tm *until_tm = localtime(&until);

		tmp = g_strdup_printf(_("Currently %s"), cal_states[current_cal_state]);
		if (has_working_hours && !sipe_cal_is_in_work_hours(until, start, end)) {
			res = g_strdup_printf(_("%s. Outside of working hours at %.2d:%.2d"),
					      tmp, until_tm->tm_hour, until_tm->tm_min);
			g_free(tmp);
			return res;
		} else {
			res = g_strdup_printf(_("%s. %s at %.2d:%.2d"), tmp, cal_states[to_state], until_tm->tm_hour, until_tm->tm_min);
			g_free(tmp);
			return res;
		}
	}
	/* End of - Calendar: string calculations */
}

#define UPDATE_CALENDAR_INTERVAL	30*60	/* 30 min */

void sipe_core_update_calendar(struct sipe_core_public *sipe_public)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_core_update_calendar: started.");

	/* Do in parallel.
	 * If failed, the branch will be disabled for subsequent calls.
	 * Can't rely that user turned the functionality on in account settings.
	 */
	sipe_ews_update_calendar(SIPE_CORE_PRIVATE);
#ifdef _WIN32
	/* @TODO: UNIX integration missing */
	sipe_domino_update_calendar(SIPE_CORE_PRIVATE);
#endif

	/* schedule repeat */
	sipe_schedule_seconds(SIPE_CORE_PRIVATE,
			      "<+update-calendar>",
			      NULL,
			      UPDATE_CALENDAR_INTERVAL,
			      (sipe_schedule_action)sipe_core_update_calendar,
			      NULL);

	SIPE_DEBUG_INFO_NOFORMAT("sipe_core_update_calendar: finished.");
}

void sipe_cal_presence_publish(struct sipe_core_private *sipe_private,
			       gboolean do_publish_calendar)
{
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		if (do_publish_calendar)
			sipe_ocs2007_presence_publish(sipe_private, NULL);
		else
			sipe_ocs2007_category_publish(sipe_private);
	} else {
		sipe_ocs2005_presence_publish(sipe_private,
					      do_publish_calendar);
	}
}

void sipe_cal_delayed_calendar_update(struct sipe_core_private *sipe_private)
{
#define UPDATE_CALENDAR_DELAY		1*60	/* 1 min */

	/* only start periodic calendar updating if user hasn't disabled it */
	if (!SIPE_CORE_PUBLIC_FLAG_IS(DONT_PUBLISH))
		sipe_schedule_seconds(sipe_private,
				      "<+update-calendar>",
				      NULL,
				      UPDATE_CALENDAR_DELAY,
				      (sipe_schedule_action) sipe_core_update_calendar,
				      NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
