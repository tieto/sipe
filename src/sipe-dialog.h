/**
 * @file sipe-dialog.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 SIPE Project <http://sipe.sourceforge.net/>
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

/* dialog is the new term for call-leg */
struct sip_dialog {
	gchar *with; /* URI */
	gchar *endpoint_GUID;
	/** 
	 *  >0 - pro
	 *  <0 - contra
	 *   0 - didn't participate
	 */ 
	int election_vote;
	gchar *ourtag;
	gchar *theirtag;
	gchar *theirepid;
	gchar *callid;
	GSList *routes;
	gchar *request;
	GSList *supported; /* counterparty capabilities */
	int cseq;
	gboolean is_established;
	struct transaction *outgoing_invite;
};

/**
 * Free dialog structure
 *
 * @param dialog (in) Dialog to be freed. May be NULL.
 */
void free_dialog(struct sip_dialog *dialog);

/**
 * Fill dialog structure from SIP message
 *
 * @param msg      (in)     mesage
 * @param dialog   (in,out) dialog to fill
 * @param outgoing (in)     outgoing or incoming message
 */
void sipe_parse_dialog(const struct sipmsg *msg,
		       struct sip_dialog *dialog,
		       gboolean outgoing);
