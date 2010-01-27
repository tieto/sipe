/**
 * @file sipe-ews.h
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

#include "http-conn.h"

/**
 * Context
 */
struct sipe_ews {
	struct sipe_account_data *sip;

	int state;
	char *email;
	char *legacy_dn;
	HttpConnAuth *auth;
	PurpleAccount *account;
	int auto_disco_method;
	int is_disabled;
	int is_updated;

	char *as_url;
	char *oof_url;
	char *oab_url;
	
	char *oof_state; /* Enabled, Disabled, Scheduled */
	char *oof_note;
	time_t oof_start;
	time_t oof_end;
	time_t updated;
	gboolean published;
	
	HttpConn *http_conn;
	
	time_t fb_start;
	/* hex form */
	char *free_busy;
	char *working_hours_xml_str;
	GSList *cal_events;
};

/**
 * Connects to Exchange 2007/2010 Server's Web Services,
 * pulls out our Availability and Out-of-Office (OOF) information
 * and publishes it to Communications server.
 *
 * Advised schedule: 30 minutes.
 */
void
sipe_ews_update_calendar(struct sipe_account_data *sip);

/**
 * Returns OOF note if enabled in the moment
 * otherwise NULL.
 */
char *
sipe_ews_get_oof_note(struct sipe_ews *ews);

/**
 * Frees context
 */
void
sipe_ews_free(struct sipe_ews* ews);

