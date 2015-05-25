/**
 * @file purple-appshare.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2017 SIPE Project <http://sipe.sourceforge.net/>
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

#include "server.h"
#include "version.h"
#include "request.h"

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

struct purple_request_ctx {
	struct sipe_media_call *appshare_call;
};

static void
stop_presenting_cb(gpointer user_data, SIPE_UNUSED_PARAMETER int action_id)
{
	struct purple_request_ctx *ctx = (struct purple_request_ctx *)user_data;

	sipe_core_appshare_stop_presenting(ctx->appshare_call);

	g_free(ctx);
}

struct sipe_user_ask_ctx *
sipe_backend_appshare_show_presenter_actions(struct sipe_core_public *sipe_public,
					     const gchar *message,
					     struct sipe_media_call *call)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	struct purple_request_ctx *ctx = g_new0(struct purple_request_ctx, 1);

	ctx->appshare_call = call;

	purple_request_action(ctx, NULL, message,
			      NULL, 0,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_account(purple_private->account),
#else
			      purple_private->account, NULL, NULL,
#endif
			      ctx, 1,
			      _("Stop presenting"), stop_presenting_cb);

	return (struct sipe_user_ask_ctx *)ctx;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
