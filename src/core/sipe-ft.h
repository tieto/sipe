/**
 * @file sipe-ft.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 Jakub Adam <jakub.adam@tieto.com>
 * Copyright (C) 2010 Tomáš Hrabčík <tomas.hrabcik@tieto.com>
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
struct sipmsg;
struct sipe_core_private;
struct sipe_file_transfer;


/**
 * Deallocate file transfer data structure
 */
void sipe_ft_deallocate(struct sipe_file_transfer *ft);

/**
 * Called when remote peer wants to send a file.
 *
 * Function initializes libpurple filetransfer API structure and calls
 * purple_xfer_request().
 *
 * @param sipe_private Sipe core private data
 * @param msg          SIP message
 * @param body         parsed SIP message body as name-value pairs
 */
void sipe_ft_incoming_transfer(struct sipe_core_private *sipe_private,
			       struct sipmsg *msg,
			       const GSList *body);

/**
 * Handles incoming filetransfer message with ACCEPT invitation command.
 *
 * This message is sent during the negotiation phase when parameters of the
 * transfer like IP address or TCP port are going to be set up.
 *
 * @param sipe_private Sipe core private data
 * @param body         parsed SIP message body as name-value pairs
 */
void sipe_ft_incoming_accept(struct sipe_core_private *sipe_private,
			     const GSList *body);

/**
 * Called when remote peer cancels ongoing file transfer.
 *
 * Function dispatches the request to libpurple
 *
 * @param sipe_private Sipe core private data
 * @param body         SIP message body
 * @param body         parsed SIP message body as name-value pairs
 */
void sipe_ft_incoming_cancel(struct sipe_core_private *sipe_private,
			     const GSList *body);

/**
 * Parses file transfer message body and creates a list with name-value pairs
 *
 * @param body file transfer SIP message body
 *
 * @return GSList of name-value pairs parsed from message body, NULL if body has
 * incorrect format
 */
GSList *sipe_ft_parse_msg_body(const gchar *body);
