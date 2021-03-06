/**
 * @file sipe-appshare-client.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_core_private;
struct sipe_media_stream;
struct sipmsg;

struct sipe_rdp_client {
	gchar *cmdline;
	void *client_data;

	GSocketAddress *(*get_listen_address_cb)(struct sipe_rdp_client *client);
	gboolean (*launch_cb)(struct sipe_rdp_client *client,
			      GSocketAddress *listen_address,
			      struct sipe_media_stream *stream);
	void (*free_cb)(struct sipe_rdp_client *client);
};

/* Client implementations */
void sipe_appshare_remmina_init(struct sipe_rdp_client *client);
void sipe_appshare_xfreerdp_init(struct sipe_rdp_client *client);
