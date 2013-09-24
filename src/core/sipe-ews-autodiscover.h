/**
 * @file sipe-ews-autodiscover.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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

/* Forward declarations */
struct sipe_core_private;

/* EWS data determined by autodiscover */
struct sipe_ews_autodiscover_data {
    const gchar *as_url;
    const gchar *ews_url;
    const gchar *legacy_dn;
    const gchar *oab_url;
    const gchar *oof_url;
};

/**
 *
 * EWS autodiscover callback
 *
 * @param sipe_private  SIPE core private data
 * @param ews_data      EWS autodiscover data (NULL when failed/aborted)
 * @param callback_data callback data
 */
typedef void (sipe_ews_autodiscover_callback)(struct sipe_core_private *sipe_private,
					      const struct sipe_ews_autodiscover_data *ews_data,
					      gpointer callback_data);

/**
 * Trigger EWS autodiscover
 *
 * @param sipe_private  SIPE core private data
 * @param callback      callback function
 * @param callback_data callback data
 */
void sipe_ews_autodiscover_start(struct sipe_core_private *sipe_private,
				 sipe_ews_autodiscover_callback *callback,
				 gpointer callback_data);

/**
 * Initialize EWS autodiscover data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_ews_autodiscover_init(struct sipe_core_private *sipe_private);

/**
 * Free EWS autodiscover data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_ews_autodiscover_free(struct sipe_core_private *sipe_private);
