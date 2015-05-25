/**
 * @file sipe-user.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-13 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-user.h"
#include "sipe-utils.h"

void sipe_user_present_info(struct sipe_core_private *sipe_private,
			    struct sip_session *session,
			    const gchar *message)
{
	sipe_backend_notify_message_info(SIPE_CORE_PUBLIC,
					 session->chat_session ? session->chat_session->backend : NULL,
					 session->with,
					 message);
}

void sipe_user_present_error(struct sipe_core_private *sipe_private,
			     struct sip_session *session,
			     const gchar *message)
{
	sipe_backend_notify_message_error(SIPE_CORE_PUBLIC,
					  session->chat_session ? session->chat_session->backend : NULL,
					  session->with,
					  message);
}

void sipe_user_present_message_undelivered(struct sipe_core_private *sipe_private,
					   struct sip_session *session,
					   int sip_error,
					   int sip_warning,
					   const gchar *who,
					   const gchar *message)
{
	char *msg, *msg_tmp, *msg_tmp2;
	const char *label;

	msg_tmp = message ? sipe_backend_markup_strip_html(message) : NULL;
	msg = msg_tmp ? g_strdup_printf("<font color=\"#888888\"></b>%s<b></font>", msg_tmp) : NULL;
	g_free(msg_tmp);
	/* Service unavailable; Server Internal Error; Server Time-out */
	if (sip_error == 606 && sip_warning == 309) { /* Not acceptable all. */ /* Message contents not allowed by policy */
		label = _("Your message or invitation was not delivered, possibly because it contains a hyperlink or other content that the system administrator has blocked.");
		g_free(msg);
		msg = NULL;
	} else if (sip_error == 500 || sip_error == 503 || sip_error == 504 || sip_error == 603) {
		label = _("This message was not delivered to %s because the service is not available");
	} else if (sip_error == 486) { /* Busy Here */
		label = _("This message was not delivered to %s because one or more recipients do not want to be disturbed");
	} else if (sip_error == 415) { /* Unsupported media type */
		label = _("This message was not delivered to %s because one or more recipients don't support this type of message");
	} else {
		label = _("This message was not delivered to %s because one or more recipients are offline");
	}

	msg_tmp = g_strdup_printf( "%s%s\n%s" ,
			msg_tmp2 = g_strdup_printf(label, who ? who : ""),
			msg ? ":" : "",
			msg ? msg : "");
	sipe_user_present_error(sipe_private, session, msg_tmp);
	g_free(msg_tmp2);
	g_free(msg_tmp);
	g_free(msg);
}

static gboolean process_info_typing_response(struct sipe_core_private *sipe_private,
					     struct sipmsg *msg,
					     SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	/* Indicates dangling IM session which needs to be dropped */
	if (msg->response == 408 || /* Request timeout */
	    msg->response == 480 || /* Temporarily Unavailable */
	    msg->response == 481) { /* Call/Transaction Does Not Exist */
		gchar *with = parse_from(sipmsg_find_header(msg, "To"));
		struct sip_session *session = sipe_session_find_im(sipe_private, with);
		struct sip_dialog *dialog = sipe_dialog_find(session, with);
		if (dialog)
			sipe_im_cancel_dangling(sipe_private, session, dialog, with,
						sipe_im_cancel_unconfirmed);
		g_free(with);
	}	
	return(TRUE);
}

void sipe_core_user_feedback_typing(struct sipe_core_public *sipe_public,
				    const gchar *to,
				    gboolean typing)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sip_session *session = sipe_session_find_im(sipe_private, to);
	struct sip_dialog *dialog = sipe_dialog_find(session, to);

	/* only enable this debug output while testing
	SIPE_DEBUG_INFO("sipe_core_user_feedback_typing session %p (%s) dialog %p (%s) established %s",
			session, session ? session->callid : "N/A",
			dialog, dialog ? dialog->callid : "N/A",
			(dialog && dialog->is_established) ? "YES" : "NO"); */

	if (session && dialog && dialog->is_established) {
		gchar *body = g_strdup_printf("<?xml version=\"1.0\"?>"
					      "<KeyboardActivity>"
					      " <status status=\"%s\" />"
					      "</KeyboardActivity>",
					      typing ? "type" : "idle");
		sip_transport_info(sipe_private,
				   "Content-Type: application/xml\r\n",
				   body,
				   dialog,
				   process_info_typing_response);
		g_free(body);
	}
}

struct sipe_user_ask_ctx {
	struct sipe_core_private *sipe_private;
	gpointer accept_cb;
	gpointer decline_cb;
	gpointer data;
};

struct sipe_user_ask_ctx * sipe_user_ask(struct sipe_core_private *sipe_private,
					 const gchar *message,
					 const gchar *accept_label,
					 SipeUserAskCb accept_cb,
					 const gchar *decline_label,
					 SipeUserAskCb decline_cb,
					 gpointer data)
{
	struct sipe_user_ask_ctx *ctx = g_new0(struct sipe_user_ask_ctx, 1);
	ctx->sipe_private = sipe_private;
	ctx->accept_cb = accept_cb;
	ctx->decline_cb = decline_cb;
	ctx->data = data;

	sipe_backend_user_ask(SIPE_CORE_PUBLIC, message,
			      accept_label, decline_label,
			      ctx);

	return ctx;
}

void sipe_core_user_ask_cb(gpointer context, gboolean accepted)
{
	struct sipe_user_ask_ctx *ctx = context;

	if (accepted && ctx->accept_cb)
		((SipeUserAskCb)ctx->accept_cb)(ctx->sipe_private, ctx->data);
	else if (ctx->decline_cb)
		((SipeUserAskCb)ctx->decline_cb)(ctx->sipe_private, ctx->data);

	g_free(ctx);
}

struct sipe_user_ask_ctx * sipe_user_ask_choice(struct sipe_core_private *sipe_private,
						const gchar *message,
						GSList *choices,
						SipeUserAskChoiceCb callback,
						gpointer data)
{
	struct sipe_user_ask_ctx *ctx = g_new0(struct sipe_user_ask_ctx, 1);
	ctx->sipe_private = sipe_private;
	ctx->accept_cb = callback;
	ctx->decline_cb = NULL;
	ctx->data = data;

	sipe_backend_user_ask_choice(SIPE_CORE_PUBLIC, message, choices, ctx);

	return ctx;
}

void sipe_core_user_ask_choice_cb(gpointer context, guint choice_id)
{
	struct sipe_user_ask_ctx *ctx = context;

	if (ctx->accept_cb) {
		((SipeUserAskChoiceCb)ctx->accept_cb)(ctx->sipe_private,
						      ctx->data, choice_id);
	}

	g_free(ctx);
}

void sipe_user_close_ask(struct sipe_user_ask_ctx *context)
{
	sipe_backend_user_close_ask(context);
	g_free(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
