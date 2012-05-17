/**
 * @file sipe-dialog.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-11 SIPE Project <http://sipe.sourceforge.net/>
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipe_delayed_invite;
struct sipmsg;

/* Helper macros to iterate over dialog list in a SIP session */
#define SIPE_DIALOG_FOREACH {                            \
	GSList *entry = session->dialogs;                \
	while (entry) {                                  \
		struct sip_dialog *dialog = entry->data; \
		entry = entry->next;
#define SIPE_DIALOG_FOREACH_END }}

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
	GSList *filetransfers;
	int cseq;
	/** corresponds to Session-Expires SIP header value */
	int expires;
	gboolean is_established;
	struct transaction *outgoing_invite;
        struct sipe_delayed_invite *delayed_invite;
};

/* Forward declaration */
struct sip_session;

/**
 * Free dialog structure
 *
 * @param dialog (in) Dialog to be freed. May be NULL.
 */
void sipe_dialog_free(struct sip_dialog *dialog);

/**
 * Add a new, empty dialog to a session
 *
 * @param session (in)
 *
 * @return dialog the new dialog structure
 */
struct sip_dialog *sipe_dialog_add(struct sip_session *session);

/**
 * Find a dialog in a session
 *
 * @param session (in) may be NULL
 * @param who (in) dialog identifier. May be NULL
 *
 * @return dialog the requested dialog or NULL
 */
struct sip_dialog *sipe_dialog_find(struct sip_session *session,
				    const gchar *who);

/**
 * Remove a dialog from a session
 *
 * @param session (in) may be NULL
 * @param who (in) dialog identifier. May be NULL
 */
void sipe_dialog_remove(struct sip_session *session, const gchar *who);

/**
 * Remove a dialog from a session
 *
 * @param session (in) may be NULL
 * @param dialog (in) dialog identifier. Should contain Call-ID, to-tag and from-tag
 *                    to unambiguously identify dialog. May be NULL
 */
void
sipe_dialog_remove_3(struct sip_session *session,
		     struct sip_dialog *dialog_in);

/**
 * Remove all dialogs from a session
 *
 * @param session (in)
 */
void sipe_dialog_remove_all(struct sip_session *session);

/**
 * Does a session have any dialogs?
 *
 * @param session (in)
 */
#define sipe_dialog_any(session) (session->dialogs != NULL)

/**
 * Return first dialog of a session
 *
 * @param session (in)
 */
#define sipe_dialog_first(session) ((struct sip_dialog *)session->dialogs->data)

/**
 * Fill dialog structure from SIP message
 *
 * @param dialog   (in,out) dialog to fill
 * @param msg      (in)     mesage
 * @param outgoing (in)     outgoing or incoming message
 */
void sipe_dialog_parse(struct sip_dialog *dialog,
		       const struct sipmsg *msg,
		       gboolean outgoing);
