/**
 * @file telepathy-private.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2013 SIPE Project <http://sipe.sourceforge.net/>
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
struct _GObject;
struct _GObjectClass;
struct _GTlsCertificate;
struct _SipeConnection;
struct _SipeContactList;
struct _SipeTLSManager;
struct _TpBaseConnection;
struct _TpBaseConnectionManager;
struct _TpBaseProtocol;
struct sipe_tls_info;
struct sipe_transport_telepathy;

/* constants */
#define SIPE_TELEPATHY_DOMAIN "sipe"

struct sipe_backend_private {
	struct sipe_core_public *public;

	/* buddies */
	struct _SipeContactList *contact_list;

	/* connection */
	struct _SipeConnection *connection;

	/* photo */
	gchar *cache_dir;

	/* status */
	guint activity;
	gchar *message;

	/* TLS certificate verification */
	struct _SipeTLSManager *tls_manager;

	/* transport */
	struct sipe_transport_telepathy *transport;
	gchar *ipaddress;
};

/* buddy */
struct _SipeContactList *sipe_telepathy_contact_list_new(struct _TpBaseConnection *connection);
const gchar *sipe_telepathy_buddy_get_alias(struct _SipeContactList *contact_list,
					    const guint contact);
void sipe_telepathy_buddy_set_alias(struct _SipeContactList *contact_list,
				    const guint contact,
				    const gchar *alias);
const gchar *sipe_telepathy_buddy_get_hash(struct _SipeContactList *contact_list,
					   const guint contact);
guint sipe_telepathy_buddy_get_presence(struct _SipeContactList *contact_list,
					guint contact);
void sipe_telepathy_avatars_iface_init(gpointer g_iface,
				       gpointer iface_data);
void sipe_telepathy_contact_info_iface_init(gpointer g_iface,
					    gpointer iface_data);
GPtrArray *sipe_telepathy_contact_info_fields(void);
/* TpDBusPropertiesMixinPropImpl is a broken typedef */
gpointer sipe_telepathy_contact_info_props(void);

/* connection */
struct _TpBaseConnection *sipe_telepathy_connection_new(struct _TpBaseProtocol *protocol,
							GHashTable *params,
							GError **error);
void sipe_telepathy_connection_alias_updated(struct _TpBaseConnection *connection,
					     guint contact,
					     const gchar *alias);
struct sipe_backend_private *sipe_telepathy_connection_private(GObject *object);

/* debugging */
void sipe_telepathy_debug_init(void);
void sipe_telepathy_debug_finalize(void);

/* protocol */
void sipe_telepathy_protocol_init(struct _TpBaseConnectionManager *cm);
gchar *sipe_telepathy_protocol_normalize_contact(struct _TpBaseProtocol *self,
						 const gchar *contact,
						 GError **error);

/* contact search */
GType sipe_search_manager_get_type(void);
#define SIPE_TYPE_SEARCH_MANAGER (sipe_search_manager_get_type())
struct _GObject *sipe_telepathy_search_new(struct _TpBaseConnection *connection);

/* status */
void sipe_telepathy_status_init(struct _GObjectClass *object_class,
				gsize struct_offset);

/* TLS certificate verification */
struct _SipeTLSManager *sipe_telepathy_tls_new(struct _TpBaseConnection *connection);
struct sipe_tls_info *sipe_telepathy_tls_info_new(const gchar *hostname,
						  struct _GTlsCertificate *certificate);
void sipe_telepathy_tls_info_free(struct sipe_tls_info *tls_info);
void sipe_telepathy_tls_verify_async(struct _GObject *connection,
				     struct sipe_tls_info *tls_info,
				     GAsyncReadyCallback callback,
				     gpointer user_data);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
