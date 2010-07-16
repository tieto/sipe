/**
 * @file sdpmsg.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 Jakub Adam <jakub.adam@tieto.com>
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

// TODO: support for multiple media sessions
struct sdpmsg {
	GSList		*attributes;
	GSList		*candidates;
	GSList		*codecs;

	gchar		*ip;
	guint		 port;

	const gchar	*username;
	const gchar	*password;

	gboolean	 legacy;
};

struct sdpcandidate {
	gchar			*foundation;
	SipeComponentType	 component;
	SipeCandidateType	 type;
	SipeNetworkProtocol	 protocol;
	guint32			 priority;
	gchar			*ip;
	guint			 port;
};

struct sdpcodec {
	gint		 id;
	gchar		*name;
	gint		 clock_rate;
	SipeMediaType	 type;
	GSList		*attributes;
};

/**
 * Parses SDP message into @c sdpmsg structure.
 *
 * @param msg SDP message as character string
 *
 * @return New @c sdpmsg or NULL if message can not be parsed.
 */
struct sdpmsg *sdpmsg_parse_msg(gchar *msg);

/**
 * Deallocates @c sdpmsg.
 */
void sdpmsg_free(struct sdpmsg *msg);
