/**
 * @file sipe-ews.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_calendar;
struct sipe_core_private;

/**
 * Connects to Exchange 2007/2010 Server's Web Services,
 * pulls out our Availability and Out-of-Office (OOF) information
 * and publishes it to Communications server.
 *
 * Advised schedule: 30 minutes.
 */
void
sipe_ews_update_calendar(struct sipe_core_private *sipe_private);

/**
 * Returns OOF note if enabled in the moment
 * otherwise NULL.
 */
char *
sipe_ews_get_oof_note(struct sipe_calendar *cal);
