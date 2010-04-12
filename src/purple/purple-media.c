/**
 * @file purple-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"

#include "sipe-media.h"
#include "media.h"

PurpleMediaSessionType sipe_media_to_purple(SipeMediaType type)
{
	switch (type) {
		case SIPE_MEDIA_AUDIO: return PURPLE_MEDIA_AUDIO;
		case SIPE_MEDIA_VIDEO: return PURPLE_MEDIA_VIDEO;
		default:			   return PURPLE_MEDIA_NONE;
	}
}

/*SipeMediaType purple_media_to_sipe(PurpleMediaSessionType type)
{
	switch (type) {
		case PURPLE_MEDIA_AUDIO: return SIPE_MEDIA_AUDIO;
		case PURPLE_MEDIA_VIDEO: return SIPE_MEDIA_VIDEO;
		default:				 return SIPE_MEDIA_AUDIO;
	}
}*/

sipe_codec *
sipe_backend_codec_new(int id, const char *name, SipeMediaType type, guint clock_rate)
{
	return (sipe_codec *)purple_media_codec_new(id, name,
										sipe_media_to_purple(type), clock_rate);
}

void
sipe_backend_codec_free(sipe_codec *codec)
{
	g_object_unref(codec);
}

gchar *
sipe_backend_codec_get_name(sipe_codec *codec)
{
	return purple_media_codec_get_encoding_name((PurpleMediaCodec *)codec);
}

gboolean sipe_backend_set_remote_codecs(struct _sipe_media_call* call, gchar* participant)
{
	PurpleMedia	*media	= call->media;
	GList		*codecs	= call->remote_codecs;

	return purple_media_set_remote_codecs(media, "sipe-voice", participant, codecs);
}

GList* sipe_backend_get_local_codecs(struct _sipe_media_call* call)
{
	return purple_media_get_codecs(call->media, "sipe-voice");
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
