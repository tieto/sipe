/**
 * @file sip-csta.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipmsg;
struct sip_dialog;
struct sipe_account_data;

/** Data model for interaction with SIP/CSTA Gateway */
struct sip_csta {
	gchar *line_uri;
	/** SIP/CSTA Gateway's SIP URI */
	gchar *gateway_uri;
	/** dialog with SIP/CSTA Gateway */
	struct sip_dialog *dialog;

	gchar *gateway_status;
	gchar *monitor_cross_ref_id;
	
	gchar *line_status;
	/** destination tel: URI */
	gchar *to_tel_uri;
	gchar *call_id;
	/* our device ID as reported by SIP/CSTA gateway */
	gchar *device_id;
};

/** Transform telephone number representation
 *  to tel: URI form.
 *  Removes white space, parenthesis ( ), hyphen - symbols
 *
 *  Must be g_free()'d after use.
 *
 * @param phone Ex. +32 2 245 00 00
 * @return Ex. tel:+3222450000 or NULL
 */
gchar *
sip_to_tel_uri(const gchar *phone);


/** Transform telephone number from tel: URI representation
 *  to more human readable form.
 *  Removes tel: prefix if such exist.
 *  (Maybe will add spaces in the future according to local
 *  phone patterns.)
 *
 *  Must be g_free()'d after use.
 *
 * @param tel_uri Ex. tel:+3222450000
 * @return Ex. +3222450000
 */
gchar *
sip_tel_uri_denormalize(const gchar *tel_uri);

/** Initializes GSTA
 * @param line_uri (in) our line tel URI.            Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 * @param server   (in) SIP URI of SIP/CSTA Gateway. Ex.: sip:73124@euuklhccups01.eu.company.local
 */
void
sip_csta_open(struct sipe_account_data *sip,
	      const gchar *line_uri,
	      const gchar *server);

/** Closes GSTA */
void
sip_csta_close(struct sipe_account_data *sip);

/** Makes Call
 * @param to_tel_uri (in) tel URI of called party. Ex.: tel:+3222220220
 */
void
sip_csta_make_call(struct sipe_account_data *sip,
		   const gchar* to_tel_uri);

/** Processes incoming CSTA commands
 */		   
void
process_incoming_info_csta(struct sipe_account_data *sip,
			   struct sipmsg *msg);
