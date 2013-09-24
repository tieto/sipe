/**
 * @file sipe-cal.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

/* Forward declarations */
struct sipe_buddy;
struct sipe_core_private;
struct sipe_http_request;
struct sipe_http_session;
struct _sipe_xml;

/* Calendar statuses */
#define SIPE_CAL_FREE       0
#define SIPE_CAL_TENTATIVE  1
#define SIPE_CAL_BUSY       2
#define SIPE_CAL_OOF        3
#define SIPE_CAL_NO_DATA    4

/* Default granularity of FreeBusy data is 15 minutes */
#define SIPE_FREE_BUSY_GRANULARITY_SEC	(15*60)
/* FreeBusy stream duration in seconds. Defaults to 4 days */
#define SIPE_FREE_BUSY_PERIOD_SEC	(4*(24*60*60))

struct sipe_cal_event {
	time_t start_time;
	time_t end_time;
	/* SIPE_CAL_* */
	int cal_status;
	char *subject;
	char *location;
	int is_meeting;
};

/** For extracting our Calendar information from
  * external sources like Exchange, Lotus Domino.
  */
struct sipe_calendar {
	struct sipe_core_private *sipe_private;

	int state;
	char *email;
	char *legacy_dn;
	int is_ews_disabled;
	int is_domino_disabled;
	int is_updated;
	gboolean retry;
	gboolean ews_autodiscover_triggered;

	char *as_url;
	char *oof_url;
	char *oab_url;
	char *domino_url;

	char *oof_state; /* Enabled, Disabled, Scheduled */
	char *oof_note;
	time_t oof_start;
	time_t oof_end;
	time_t updated;
	gboolean published;

	struct sipe_http_session *session;
	struct sipe_http_request *request;

	time_t fb_start;
	/* hex form */
	char *free_busy;
	char *working_hours_xml_str;
	GSList *cal_events;
};

void
sipe_cal_event_free(struct sipe_cal_event* cal_event);

void
sipe_cal_events_free(GSList *cal_events);

void
sipe_cal_calendar_free(struct sipe_calendar *cal);

void
sipe_cal_calendar_init(struct sipe_core_private *sipe_private);

/**
 * Returns hash of Calendar Event for comparison.
 *
 * Must be g_free()'d after use.
 */
char *
sipe_cal_event_hash(struct sipe_cal_event* event);

/**
 * Describes Calendar event in human readable form.
 *
 * Must be g_free()'d after use.
 */
char *
sipe_cal_event_describe(struct sipe_cal_event* cal_event);

/**
 * Converts struct tm to Epoch time_t considering timezone.
 *
 * @param tz as defined for TZ environment variable.
 *
 * Reference: see timegm(3) - Linux man page
 */
time_t
sipe_mktime_tz(struct tm *tm,
	       const char* tz);

/**
 * Converts hex representation of freebusy string as
 * returned by Exchange Web Services to
 * condenced and base64 encoded form
 *
 * Must be g_free()'d after use.
 */
char *
sipe_cal_get_freebusy_base64(const char* freebusy_hex);

/** Contains buddy's working hours information */
struct sipe_cal_working_hours;

/**
 * Parses Working Hours from passed XML piece
 * and creates/fills struct sipe_cal_working_hours in struct sipe_buddy
 */
void
sipe_cal_parse_working_hours(const struct _sipe_xml *xn_working_hours,
			     struct sipe_buddy *buddy);

/**
 * Frees struct sipe_cal_working_hours
 */
void
sipe_cal_free_working_hours(struct sipe_cal_working_hours *wh);

/**
 * Returns user calendar information in text form.
 * Example: "Currently Busy. Free at 13:00"
 */
char *
sipe_cal_get_description(struct sipe_buddy *buddy);

/**
 * Returns calendar status SIPE_CAL_* at time specified.
 * Returns SIPE_CAL_NO_DATA if no calendar data availible.
 *
 * @param since (out)	Returns beginning time of the status.
 */
int
sipe_cal_get_status(struct sipe_buddy *buddy,
		    time_t time_in_question,
		    time_t *since);

/**
 * Returns calendar event at time in question.
 * If conflict, takes last event in the following
 * priority order: OOF, Busy, Tentative.
 */
struct sipe_cal_event*
sipe_cal_get_event(GSList *cal_events,
		   time_t time_in_question);

/**
 * Publish presence information
 */
void sipe_cal_presence_publish(struct sipe_core_private *sipe_private,
			       gboolean do_publish_calendar);

/**
 * Schedule calendar update
 */
void sipe_cal_delayed_calendar_update(struct sipe_core_private *sipe_private);
