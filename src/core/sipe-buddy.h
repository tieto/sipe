/**
 * @file sipe-buddy.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_cal_working_hours;

struct sipe_buddy {
	gchar *name;
	gchar *activity;
	gchar *meeting_subject;
	gchar *meeting_location;
	/* Sipe internal format for Note is HTML.
	 * All incoming plain text should be html-escaped
	 * for example by g_markup_escape_text()
	 */
	gchar *note;
	gboolean is_oof_note;
	time_t note_since;

	/* Calendar related fields */
	gchar *cal_start_time;
	int cal_granularity;
	gchar *cal_free_busy_base64;
	gchar *cal_free_busy;
	time_t cal_free_busy_published;
	/* for 2005 systems */
	int user_avail;
	time_t user_avail_since;
	time_t activity_since;
	const char *last_non_cal_status_id;
	gchar *last_non_cal_activity;

	struct sipe_cal_working_hours *cal_working_hours;

	gchar *device_name;
	GSList *groups;
	 /** flag to control sending 'context' element in 2007 subscriptions */
	gboolean just_added;
};
