/**
 * @file sipe-subscriptions.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
struct sip_dialog;

/**
 * Subscriptions subsystem
 */
void sipe_subscriptions_init(struct sipe_core_private *sipe_private);
void sipe_subscriptions_unsubscribe(struct sipe_core_private *sipe_private);
void sipe_subscriptions_destroy(struct sipe_core_private *sipe_private);

/**
 * Subscriptions
 */
void sipe_subscribe_conference(struct sipe_core_private *sipe_private,
			       const gchar *id,
			       gboolean expires);

void sipe_subscribe_presence_single(struct sipe_core_private *sipe_private,
				    const gchar *uri,
				    const gchar *to);
void sipe_subscribe_presence_single_cb(struct sipe_core_private *sipe_private,
				       gpointer uri);
void sipe_subscribe_presence_initial(struct sipe_core_private *sipe_private);
void sipe_subscribe_poolfqdn_resource_uri(const gchar *host,
					  GSList *server,
					  struct sipe_core_private *sipe_private);

/**
 * Subscribe to all events the server supports after first registration
 *
 * @param sipe_private SIPE core private data
 */
void sipe_subscription_self_events(struct sipe_core_private *sipe_private);
