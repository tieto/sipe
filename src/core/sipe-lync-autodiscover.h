/**
 * @file sipe-lync-autodiscover.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
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

/* Lync data determined by autodiscover */
struct sipe_lync_autodiscover_data {
    const gchar *server;
    guint        port;
};

/**
 * Lync autodiscover callback
 *
 * @param sipe_private  SIPE core private data
 * @param servers       list with Lync autodiscover data
 * @param callback_data callback data
 *
 * servers will be @c NULL when request got aborted.
 * last entry in the list will be a @c NULL entry.
 */
typedef void (sipe_lync_autodiscover_callback)(struct sipe_core_private *sipe_private,
					       GSList *servers,
					       gpointer callback_data);

/**
 * Free first callback data entry on the server list
 *
 * @param servers list given to callback (may be @c NULL)
 *
 * @return new list header
 */
GSList *sipe_lync_autodiscover_pop(GSList *servers);

/**
 * Trigger Lync autodiscover
 *
 * @param sipe_private  SIPE core private data
 * @param callback      callback function
 * @param callback_data callback data
 */
void sipe_lync_autodiscover_start(struct sipe_core_private *sipe_private,
				  sipe_lync_autodiscover_callback *callback,
				  gpointer callback_data);

/**
 * Initialize Lync autodiscover data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_lync_autodiscover_init(struct sipe_core_private *sipe_private);

/**
 * Free Lync autodiscover data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_lync_autodiscover_free(struct sipe_core_private *sipe_private);
