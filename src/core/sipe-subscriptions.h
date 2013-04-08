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
 * Does the server allow a subscription to a certain event?
 *
 * @param sipe_private SIPE core private data
 * @param event        subscription event (must not be @c NULL)
 */
gboolean sipe_subscription_is_allowed(struct sipe_core_private *sipe_private,
				      const gchar *event);


/**
 * Terminate subscription
 *
 * @param sipe_private SIPE core private data
 * @param event        subscription event to be removed (must not be @c NULL)
 * @param who          URI the subscription is associated with
 */
void sipe_subscription_terminate(struct sipe_core_private *sipe_private,
				 const gchar *event,
				 const gchar *who);

/**
 * Subscriptions
 */
void sipe_subscribe(struct sipe_core_private *sipe_private,
		    const gchar *uri,
		    const gchar *event,
		    const gchar *accept,
		    const gchar *addheaders,
		    const gchar *body,
		    struct sip_dialog *dialog);
void sipe_subscribe_presence_wpending(struct sipe_core_private *sipe_private,
				      void *unused);
void sipe_subscribe_roaming_acl(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_contacts(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_provisioning(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_provisioning_v2(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_self(struct sipe_core_private *sipe_private);

void sipe_subscribe_presence_single(struct sipe_core_private *sipe_private,
				    gpointer buddy_name);
void sipe_subscribe_presence_batched(struct sipe_core_private *sipe_private);
void sipe_subscribe_presence_batched_schedule(struct sipe_core_private *sipe_private,
					      const gchar *action_name,
					      const gchar *who,
					      GSList *buddies,
					      int timeout);
void sipe_subscribe_poolfqdn_resource_uri(const gchar *host,
					  GSList *server,
					  struct sipe_core_private *sipe_private);
