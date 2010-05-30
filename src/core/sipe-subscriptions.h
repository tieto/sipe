/**
 * @file sipe-subscriptions.h
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
struct sipe_core_private;
struct sipmsg;
struct transaction;

/**
 * Callback to process SUBSCRIBE responses
 */
gboolean process_subscribe_response(struct sipe_core_private *sipe_private,
				    struct sipmsg *msg,
				    struct transaction *trans);

/**
 * Subscriptions
 */
void sipe_subscribe_presence_wpending(struct sipe_core_private *sipe_private,
				      void *unused);
void sipe_subscribe_roaming_acl(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_contacts(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_provisioning(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_provisioning_v2(struct sipe_core_private *sipe_private);
void sipe_subscribe_roaming_self(struct sipe_core_private *sipe_private);
