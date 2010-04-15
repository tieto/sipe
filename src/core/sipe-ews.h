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

/*
 * Interface dependencies:
 *
 * <time.h>
 * <glib.h>
 */

/* Forward declarations */
struct http_conn_auth;
struct http_conn_struct;
struct sipe_account_data;
struct _PurpleAccount;
struct sipe_calendar;

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
sipe_ews_get_oof_note(struct sipe_calendar *cal);
