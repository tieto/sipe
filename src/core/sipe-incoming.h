/**
 * @file sipe-incoming.h
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
struct sip_dialog;
struct sipmsg;

void process_incoming_bye(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg);
void process_incoming_cancel(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg);
void process_incoming_info(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg);
void process_incoming_invite(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg);
void process_incoming_message(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg);
void process_incoming_options(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg);
void process_incoming_refer(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg);

void sipe_incoming_cancel_delayed_invite(struct sipe_core_private *sipe_private,
					 struct sip_dialog *dialog);
