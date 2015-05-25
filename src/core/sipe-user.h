/**
 * @file sipe-user.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
struct sip_session;
struct sipe_core_private;

/* Opaque ask context structure */
struct sipe_user_ask_ctx;

/**
 * Present error message in users session
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the conversation
 * @param message      message text
 */
void sipe_user_present_error(struct sipe_core_private *sipe_private,
			     struct sip_session *session,
			     const gchar *message);

/**
 * Present info message in users session
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the conversation
 * @param message      message text
 */
void sipe_user_present_info(struct sipe_core_private *sipe_private,
			    struct sip_session *session,
			    const gchar *message);

/**
 * Present error that his message wasn't delivered in users session
 *
 * @param sipe_private SIPE core private data
 * @param session      session for the conversation
 * @param sip_error    SIP error code or -1
 * @param sip_warning  SIP warning code or -1
 * @param who          URI of recipient
 * @param message      message text
 */
void sipe_user_present_message_undelivered(struct sipe_core_private *sipe_private,
					   struct sip_session *session,
					   int sip_error,
					   int sip_warning,
					   const gchar *who,
					   const gchar *message);

typedef void (* SipeUserAskCb)(struct sipe_core_private *, gpointer data);

/**
 * Present a query that is to be accepted or declined by the user
 *
 * @param sipe_private  SIPE core private data
 * @param message       Text of the query to be shown to user
 * @param accept_label  Label to be displayed on UI control that accepts query
 * @param accept_cb     callback function to be invoked when query is accepted
 * @param decline_label Label to be displayed on UI control that declines query
 * @param decline_cb    callback function to be invoked when query is declined
 * @param data          custom user data
 *
 * @return opaque sipe_user_ask_ctx pointer that can be used to close the query
 * before user answered it.
 */
struct sipe_user_ask_ctx * sipe_user_ask(struct sipe_core_private *sipe_private,
					 const gchar *message,
					 const gchar *accept_label,
					 SipeUserAskCb accept_cb,
					 const gchar *decline_label,
					 SipeUserAskCb decline_cb,
					 gpointer data);

typedef void (* SipeUserAskChoiceCb)(struct sipe_core_private *, gpointer data,
				     guint choice_id);

/**
 * Present a set of options one of which the user is to choose.
 *
 * @param sipe_core_private SIPE core private data
 * @param message           text message to be shown to the user
 * @param choices           list of choice options
 * @param callback          callback function to be invoked after user makes
 *                          a choice
 * @param data              custom user data to pass to callback
 */
struct sipe_user_ask_ctx * sipe_user_ask_choice(struct sipe_core_private *sipe_private,
						const gchar *message,
						GSList *choices,
						SipeUserAskChoiceCb callback,
						gpointer data);

/**
 * Closes the pending user query
 *
 * @param context sipe_user_ask_ctx pointer returned by sipe_user_ask()
 */
void sipe_user_close_ask(struct sipe_user_ask_ctx *context);
