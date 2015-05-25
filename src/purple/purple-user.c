/**
 * @file purple-user.c
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

#include "sipe-nls.h"

#include <glib.h>

#include "server.h"
#include "request.h"

#include "purple-private.h"

#if PURPLE_VERSION_CHECK(3,0,0)
#else
#define purple_serv_got_typing(c, n, t, s)	serv_got_typing(c, n, t, s)
#define purple_serv_got_typing_stopped(c, n)	serv_got_typing_stopped(c, n)
#define PURPLE_IM_TYPING PURPLE_TYPING
#endif

#include "sipe-backend.h"
#include "sipe-core.h"

#define SIPE_TYPING_RECV_TIMEOUT 6

void sipe_backend_user_feedback_typing(struct sipe_core_public *sipe_public,
				       const gchar *from)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	purple_serv_got_typing(purple_private->gc, from,
			       SIPE_TYPING_RECV_TIMEOUT,
			       PURPLE_IM_TYPING);
}

void sipe_backend_user_feedback_typing_stop(struct sipe_core_public *sipe_public,
					    const gchar *from)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	purple_serv_got_typing_stopped(purple_private->gc, from);
}

static void ask_cb(gpointer key, int choice)
{
	sipe_core_user_ask_cb(key, choice == 1);
}

void sipe_backend_user_ask(struct sipe_core_public *sipe_public,
			   const gchar *message,
			   const gchar *accept_label,
			   const gchar *decline_label,
			   gpointer key)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	purple_request_action(key, "Office Communicator", message,
			      NULL, 0,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_account(purple_private->account),
#else
			      purple_private->account, NULL, NULL,
#endif
			      key, 2,
			      accept_label, (PurpleRequestActionCb) ask_cb,
			      decline_label, (PurpleRequestActionCb) ask_cb);
}

void sipe_backend_user_close_ask(gpointer key)
{
	purple_request_close_with_handle(key);
}

static void ask_choice_accept_cb(gpointer key, PurpleRequestFields *fields)
{
	guint choice_id =
			GPOINTER_TO_INT(purple_request_fields_get_choice(fields, "choice"));

	sipe_core_user_ask_choice_cb(key, choice_id);
}

static void ask_choice_cancel_cb(gpointer key)
{
	sipe_core_user_ask_choice_cb(key, SIPE_CHOICE_CANCELLED);
}


void sipe_backend_user_ask_choice(struct sipe_core_public *sipe_public,
				  const gchar *message,
				  GSList *choices,
				  gpointer key)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	PurpleRequestFields *fields = purple_request_fields_new();
	PurpleRequestFieldGroup *group = purple_request_field_group_new(NULL);
	PurpleRequestField *field =
			purple_request_field_choice_new("choice", message, 0);

	guint i;
	for (i = 0; i != g_slist_length(choices); ++i) {
		purple_request_field_choice_add(field,
						g_slist_nth_data(choices, i)
#if PURPLE_VERSION_CHECK(3,0,0)
						, GUINT_TO_POINTER(i)
#endif
						);
	}

	purple_request_field_group_add_field(group, field);
	purple_request_fields_add_group(fields, group);

	purple_request_fields(key, "Microsoft Lync",
			      NULL, NULL, fields,
			      _("OK"), (GCallback)ask_choice_accept_cb,
			      _("Cancel"), (GCallback)ask_choice_cancel_cb,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_account(purple_private->account),
#else
			      purple_private->account, NULL, NULL,
#endif
			      key);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
