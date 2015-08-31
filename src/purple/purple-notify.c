/**
 * @file purple-notify.c
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

#include <time.h>

#include <glib.h>

#include "conversation.h"
#include "notify.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "conversations.h"
#endif

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

static void notify_message(struct sipe_core_public *sipe_public,
			   PurpleMessageFlags flags,
			   struct sipe_backend_chat_session *backend_session,
			   const gchar *who,
			   const gchar *message)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleConversation *conv;

	if (backend_session) {
		conv = (PurpleConversation *) backend_session;
	} else {
#if PURPLE_VERSION_CHECK(3,0,0)
		conv = (PurpleConversation *) purple_conversations_find_im_with_account(
#else
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY,
#endif
							     who,
							     purple_private->account);
	}
	if (conv) {
#if PURPLE_VERSION_CHECK(3,0,0)
		purple_conversation_write_system_message(conv, message, flags);
#else
		purple_conversation_write(conv, NULL, message, flags,
					  time(NULL));
#endif
	}
}

void sipe_backend_notify_message_error(struct sipe_core_public *sipe_public,
				       struct sipe_backend_chat_session *backend_session,
				       const gchar *who,
				       const gchar *message)
{
	notify_message(sipe_public, PURPLE_MESSAGE_ERROR,
		       backend_session, who, message);
}

void sipe_backend_notify_message_info(struct sipe_core_public *sipe_public,
				      struct sipe_backend_chat_session *backend_session,
				      const gchar *who,
				      const gchar *message)
{
	notify_message(sipe_public, PURPLE_MESSAGE_SYSTEM,
		       backend_session, who, message);
}

void sipe_backend_notify_error(struct sipe_core_public *sipe_public,
			       const gchar *title,
			       const gchar *msg)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	purple_notify_error(purple_private->gc, NULL, title, msg
#if PURPLE_VERSION_CHECK(3,0,0)
			    , NULL
#endif
			    );
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
