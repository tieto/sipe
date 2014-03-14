/**
 * @file purple-im.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <glib.h>

#include "server.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "conversations.h"
#else
#define purple_serv_got_im(c, w, m, f, t)	serv_got_im(c, w, m, f, t)
#endif

#include "purple-private.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

void sipe_backend_im_message(struct sipe_core_public *sipe_public,
			     const gchar *from,
			     const gchar *html)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	purple_serv_got_im(purple_private->gc,
		    from,
		    html,
		    0,
		    time(NULL));
}

void sipe_backend_im_topic(struct sipe_core_public *sipe_public,
			   const gchar *with,
			   const gchar *topic)
{
	PurpleAccount *account = sipe_public->backend_private->account;
	PurpleConversation *conv;
	gchar *msg;

	/*
	 * Ensure we have an open conversation with the buddy, otherwise
	 * message would be lost.
	 */
#if PURPLE_VERSION_CHECK(3,0,0)
	conv = (PurpleConversation *) purple_conversations_find_im_with_account(
#else
	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
#endif
						     with,
						     account);
	if (!conv)
#if PURPLE_VERSION_CHECK(3,0,0)
		conv = (PurpleConversation *) purple_im_conversation_new(
#else
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM,
#endif
					       account,
					       with);

	msg = g_strdup_printf(_("Conversation subject: %s"), topic);
	sipe_backend_notify_message_info(sipe_public,
					 (struct sipe_backend_chat_session *)conv,
					 with,
					 msg);
	g_free(msg);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
