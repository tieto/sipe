/*
 * @file sipe-sign.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

struct sipmsg_breakdown {
	struct sipmsg * msg;
	gchar * protocol;
	gchar * rand;
	gchar * num;
	gchar * realm;
	gchar * target_name;
	const gchar * call_id;
	gchar * cseq;
	//method
	gchar * from_url;
	gchar * from_tag;
	/** @since 3 */
	gchar * to_url;
	gchar * to_tag;
	/** @since 3 */
	gchar * p_assertet_identity_sip_uri;
	/** @since 3 */
	gchar * p_assertet_identity_tel_uri;
	const gchar * expires;
	//response code
};

void sipmsg_breakdown_parse(struct sipmsg_breakdown * msg, gchar * realm, gchar * target,
			    const gchar *protocol);
gchar*
sipmsg_breakdown_get_string(int version,
			    struct sipmsg_breakdown * msgbd);
void sipmsg_breakdown_free(struct sipmsg_breakdown * msg);
