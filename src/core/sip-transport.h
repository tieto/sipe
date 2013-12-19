/**
 * @file sip-transport.h
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

/* Forward declarations */
struct sipmsg;
struct sip_dialog;
struct sipe_core_private;
struct transaction;

/* Transaction that can be associated with a SIP request */
typedef gboolean (*TransCallback) (struct sipe_core_private *,
				   struct sipmsg *,
				   struct transaction *);

struct transaction_payload {
	GDestroyNotify destroy;
	void *data;
};

struct transaction {
	TransCallback callback;
	TransCallback timeout_callback;

	/** Not yet perfect, but surely better then plain CSeq
	 * Format is: <Call-ID><CSeq>
	 * (RFC3261 17.2.3 for matching server transactions: Request-URI, To tag, From tag, Call-ID, CSeq, and top Via)
	 */
	gchar *key;
	gchar *timeout_key;
        struct sipmsg *msg;
	struct transaction_payload *payload;
};

/* Send SIP response */
void sip_transport_response(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg,
			    guint code,
			    const char *text,
			    const char *body);

/* Send SIP request */
struct transaction *sip_transport_request(struct sipe_core_private *sipe_private,
					  const gchar *method,
					  const gchar *url,
					  const gchar *to,
					  const gchar *addheaders,
					  const gchar *body,
					  struct sip_dialog *dialog,
					  TransCallback callback);

/* Send SIP request with timeout [in seconds] */
struct transaction *sip_transport_request_timeout(struct sipe_core_private *sipe_private,
						  const gchar *method,
						  const gchar *url,
						  const gchar *to,
						  const gchar *addheaders,
						  const gchar *body,
						  struct sip_dialog *dialog,
						  TransCallback callback,
						  guint timeout,
						  TransCallback timeout_callback);

/* Common SIP request types */
void sip_transport_ack(struct sipe_core_private *sipe_private,
		       struct sip_dialog *dialog);
void sip_transport_bye(struct sipe_core_private *sipe_private,
		       struct sip_dialog *dialog);
struct transaction *sip_transport_info(struct sipe_core_private *sipe_private,
				       const gchar *addheaders,
				       const gchar *body,
				       struct sip_dialog *dialog,
				       TransCallback callback);
struct transaction *sip_transport_invite(struct sipe_core_private *sipe_private,
					 const gchar *addheaders,
					 const gchar *body,
					 struct sip_dialog *dialog,
					 TransCallback callback);
struct transaction *sip_transport_service(struct sipe_core_private *sipe_private,
					  const gchar *uri,
					  const gchar *addheaders,
					  const gchar *body,
					  TransCallback callback);
void sip_transport_subscribe(struct sipe_core_private *sipe_private,
			     const gchar *uri,
			     const gchar *addheaders,
			     const gchar *body,
			     struct sip_dialog *dialog,
			     TransCallback callback);
void sip_transport_update(struct sipe_core_private *sipe_private,
			  struct sip_dialog *dialog,
			  TransCallback callback);

/* Misc. SIP transport stuff */
guint sip_transport_port(struct sipe_core_private *sipe_private);
void sip_transport_deregister(struct sipe_core_private *sipe_private);
void sip_transport_disconnect(struct sipe_core_private *sipe_private);
void sip_transport_authentication_completed(struct sipe_core_private *sipe_private);

int sip_transaction_cseq(struct transaction *trans);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
