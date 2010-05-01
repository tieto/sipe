/**
 * @file sip-transport.h
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

/* Forward declarations */
struct sipmsg;
struct sip_dialog;
struct sipe_account_data;
struct sipe_core_private;
struct transaction;

typedef gboolean (*TransCallback) (struct sipe_core_private *,
				   struct sipmsg *,
				   struct transaction *);

struct transaction_payload {
	GDestroyNotify destroy;
	void *data;
};

struct transaction {
	time_t time;
	int retries;
	int transport; /* 0 = tcp, 1 = udp */
	int fd;
	/** Not yet perfect, but surely better then plain CSeq
	 * Format is: <Call-ID><CSeq>
	 * (RFC3261 17.2.3 for matching server transactions: Request-URI, To tag, From tag, Call-ID, CSeq, and top Via)
	 */
	gchar *key;
	struct sipmsg *msg;
	TransCallback callback;
	struct transaction_payload *payload;
};

struct transaction *transactions_find(struct sipe_core_private *sipe_private, struct sipmsg *msg);
void transactions_remove(struct sipe_core_private *sipe_private, struct transaction *trans);
void do_register_exp(struct sipe_account_data *sip, int expire);
void do_register_cb(struct sipe_core_private *sipe_private,
		    void *unused);
void do_register(struct sipe_account_data *sip);
void sip_transport_default_contact(struct sipe_core_private *sipe_private);
/* server_name must be g_alloc()'ed */
void sipe_server_register(struct sipe_core_private *sipe_private,
			  guint type,
			  gchar *server_name,
			  guint server_port);
void send_sip_response(struct sipe_core_private *sipe_private,
		       struct sipmsg *msg, int code,
		       const char *text, const char *body);
struct transaction *
send_sip_request(struct sipe_core_private *sipe_private, const gchar *method,
		 const gchar *url, const gchar *to, const gchar *addheaders,
		 const gchar *body, struct sip_dialog *dialog,
		 TransCallback tc);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
