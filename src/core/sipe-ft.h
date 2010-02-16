/**
 * @file sipe-ft.h
 *
 * pidgin-sipe
 *
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

#include <libpurple/ft.h>
#include "sipmsg.h"

/**
 * Called when remote peer wants to send a file.
 *
 * Function initializes libpurple filetransfer API structure and calls
 * purple_xfer_request().
 *
 * @param account PurpleAccount corresponding to the request
 * @param msg     SIP message
 */
void sipe_ft_incoming_transfer(PurpleAccount *account, struct sipmsg *msg);
/**
 * Handles incoming filetransfer message with ACCEPT invitation command.
 *
 * This message is sent during the negotiation phase when parameters of the
 * transfer like IP address or TCP port are going to be set up.
 *
 * @param account PurpleAccount corresponding to the request
 * @param msg     SIP message
 */
void sipe_ft_incoming_accept(PurpleAccount *account, struct sipmsg *msg);
/**
 * Called when remote peer cancels ongoing file transfer.
 *
 * Function dispatches the request to libpurple
 *
 * @param account PurpleAccount corresponding to the request
 * @param msg     SIP message
 */
void sipe_ft_incoming_cancel(PurpleAccount *account, struct sipmsg *msg);
/**
 * Initiates outgoing file transfer, sending @c file to remote peer identified
 * by @c who.
 *
 * @param gc   a PurpleConnection
 * @param who  string identifying receiver of the file
 * @param file local file system path of the file to send
 */
void sipe_ft_send_file(PurpleConnection *gc, const char *who, const char *file);
/**
 * Creates new PurpleXfer structure representing a file transfer.
 *
 * @param gc  a PurpleConnection
 * @param who remote participant in the file transfer session
 */
PurpleXfer * sipe_ft_new_xfer(PurpleConnection *gc, const char *who);
