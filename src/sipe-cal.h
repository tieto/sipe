/**
 * @file sipe-cal.h
 *
 * pidgin-sipe
 *
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

#include "xmlnode.h"

/* Calendar statuses */
#define SIPE_CAL_FREE       0
#define SIPE_CAL_TENTATIVE  1
#define SIPE_CAL_BUSY       2
#define SIPE_CAL_OOF        3
#define SIPE_CAL_NO_DATA    4


/** Contains buddy's working hours information */
struct sipe_cal_working_hours;

/**
 * Parses Working Hours from passed XML piece
 * and creates/fills struct sipe_cal_working_hours in struct sipe_buddy
 */
void
sipe_cal_parse_working_hours(xmlnode *xn_working_hours,
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
 * Returns current calendar status SIPE_CAL_*
 * Returns SIPE_CAL_NO_DATA if no calendar data availible.
 */
int
sipe_cal_get_current_status(struct sipe_buddy *buddy);
