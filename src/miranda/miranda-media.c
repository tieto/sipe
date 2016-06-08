/**
 * @file miranda-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
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

#include <windows.h>
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

struct sipe_backend_media {
	int dummy;
};

struct sipe_backend_media *
sipe_backend_media_new(struct sipe_core_public *sipe_public,
		       struct sipe_media_call *call,
		       const gchar *participant,
		       SipeMediaCallFlags flags)
{
	struct sipe_backend_media *m = g_new0(struct sipe_backend_media,1);

	return m;
}

void
sipe_backend_media_free(struct sipe_backend_media *media)
{
	_NIF();
}

void
sipe_backend_media_set_cname(struct sipe_backend_media *media, gchar *cname)
{
	_NIF();
}

struct sipe_backend_media_relays *
sipe_backend_media_relays_convert(GSList *media_relays, gchar *username, gchar *password)
{
	_NIF();
	return NULL;
}

void
sipe_backend_media_relays_free(struct sipe_backend_media_relays *media_relays)
{
	_NIF();
}

struct sipe_backend_media_stream *
sipe_backend_media_add_stream(struct sipe_media_stream *stream,
			      SipeMediaType type,
			      SipeIceVersion ice_version,
			      gboolean initiator,
			      struct sipe_backend_media_relays *media_relays,
			      guint min_port, guint max_port)
{
	_NIF();
	return NULL;
}

void
sipe_backend_media_add_remote_candidates(struct sipe_media_call *media,
					 struct sipe_media_stream *stream,
					 GList *candidates)
{
	_NIF();
}

gboolean sipe_backend_media_is_initiator(struct sipe_media_call *media,
					 struct sipe_media_stream *stream)
{
	_NIF();
	return FALSE;
}

gboolean sipe_backend_media_accepted(struct sipe_backend_media *media)
{
	_NIF();
	return FALSE;
}

gboolean
sipe_backend_stream_initialized(struct sipe_media_call *media,
				struct sipe_media_stream *stream)
{
	_NIF();
	return FALSE;
}

GList *
sipe_backend_media_stream_get_active_local_candidates(struct sipe_media_stream *stream)
{
	_NIF();
	return NULL;
}

GList *
sipe_backend_media_stream_get_active_remote_candidates(struct sipe_media_stream *stream)
{
	_NIF();
	return NULL;
}

sipe_backend_media_set_encryption_keys(struct sipe_media_call *media,
				       struct sipe_media_stream *stream,
				       const guchar *encryption_key,
				       const guchar *decryption_key)
{
	_NIF();
}

void
sipe_backend_stream_hold(struct sipe_media_call *media,
			 struct sipe_media_stream *stream,
			 gboolean local)
{
	_NIF();
}

void
sipe_backend_stream_unhold(struct sipe_media_call *media,
			   struct sipe_media_stream *stream,
			   gboolean local)
{
	_NIF();
}

gboolean
sipe_backend_stream_is_held(struct sipe_media_stream *stream)
{
	_NIF();
	return FALSE;
}

void
sipe_backend_media_stream_end(struct sipe_media_call *media,
			      struct sipe_media_stream *stream)
{
	_NIF();
}

void
sipe_backend_media_stream_free(struct sipe_backend_media_stream *stream)
{
	_NIF();
}

struct sipe_backend_codec *
sipe_backend_codec_new(int id, const char *name, SipeMediaType type, guint clock_rate)
{
	_NIF();
	return NULL;
}

void
sipe_backend_codec_free(struct sipe_backend_codec *codec)
{
	_NIF();
}

int
sipe_backend_codec_get_id(struct sipe_backend_codec *codec)
{
	_NIF();
	return 0;
}

gchar *
sipe_backend_codec_get_name(struct sipe_backend_codec *codec)
{
	_NIF();
	return NULL;
}

guint
sipe_backend_codec_get_clock_rate(struct sipe_backend_codec *codec)
{
	_NIF();
	return 0;
}

void
sipe_backend_codec_add_optional_parameter(struct sipe_backend_codec *codec,
					  const gchar *name, const gchar *value)
{
	_NIF();
}

GList *
sipe_backend_codec_get_optional_parameters(struct sipe_backend_codec *codec)
{
	_NIF();
	return NULL;
}

gboolean
sipe_backend_set_remote_codecs(struct sipe_media_call *media,
			       struct sipe_media_stream *stream,
			       GList *codecs)
{
	_NIF();
	return FALSE;
}

GList*
sipe_backend_get_local_codecs(struct sipe_media_call *media,
			      struct sipe_media_stream *stream)
{
	_NIF();
	return NULL;
}

struct sipe_backend_candidate *
sipe_backend_candidate_new(const gchar *foundation,
			   SipeComponentType component,
			   SipeCandidateType type, SipeNetworkProtocol proto,
			   const gchar *ip, guint port,
			   const gchar *username,
			   const gchar *password)
{
	_NIF();
	return NULL;
}

void
sipe_backend_candidate_free(struct sipe_backend_candidate *candidate)
{
	_NIF();
}

gchar *
sipe_backend_candidate_get_username(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return NULL;
}

gchar *
sipe_backend_candidate_get_password(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return NULL;
}

gchar *
sipe_backend_candidate_get_foundation(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return NULL;
}

gchar *
sipe_backend_candidate_get_ip(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return NULL;
}

guint
sipe_backend_candidate_get_port(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return 0;
}

gchar *
sipe_backend_candidate_get_base_ip(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return FALSE;
}

guint
sipe_backend_candidate_get_base_port(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return 0;
}

guint32
sipe_backend_candidate_get_priority(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return 0;
}

void
sipe_backend_candidate_set_priority(struct sipe_backend_candidate *candidate, guint32 priority)
{
	_NIF();
}

SipeComponentType
sipe_backend_candidate_get_component_type(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return SIPE_COMPONENT_NONE;
}

SipeCandidateType
sipe_backend_candidate_get_type(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return SIPE_CANDIDATE_TYPE_ANY;
}

SipeNetworkProtocol
sipe_backend_candidate_get_protocol(struct sipe_backend_candidate *candidate)
{
	_NIF();
	return SIPE_NETWORK_PROTOCOL_TCP_ACTIVE;
}

GList *
sipe_backend_get_local_candidates(struct sipe_media_call *media,
				  struct sipe_media_stream *stream)
{
	_NIF();
	return FALSE;
}

void
sipe_backend_media_accept(struct sipe_backend_media *media, gboolean local)
{
	_NIF();
}

void
sipe_backend_media_hangup(struct sipe_backend_media *media, gboolean local)
{
	_NIF();
}

void
sipe_backend_media_reject(struct sipe_backend_media *media, gboolean local)
{
	_NIF();
}

SipeEncryptionPolicy
sipe_backend_media_get_encryption_policy(struct sipe_core_public *sipe_public)
{
	return SIPE_ENCRYPTION_POLICY_REJECTED;
}

gssize
sipe_backend_media_stream_read(struct sipe_media_stream *stream,
			       guint8 *buffer, gsize len)
{
	_NIF();
}

gssize
sipe_backend_media_stream_write(struct sipe_media_stream *stream,
				guint8 *buffer, gsize len)
{
	_NIF();
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
