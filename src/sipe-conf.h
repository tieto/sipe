/**
 * @file sipe-conf.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@kinozal.tv>
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

/**
 * Processes incoming INVITE with 
 * Content-Type: application/ms-conf-invite+xml
 * i.e. invitation to join conference.
 *
 * Server 2007+ functionality.
 */
static void
process_incoming_invite_conf(struct sipe_account_data *sip,
			     struct sipmsg *msg);
			     
/** 
 * Process of conference state
 * Content-Type: application/conference-info+xml
 */
static void
sipe_process_conference(struct sipe_account_data *sip,
			struct sipmsg * msg);

/** 
 * AddUser request to Focus. 
 * Params:
 * focus_URI, from, request_id, focus_URI, from, endpoint_GUID
 */
#define SIPE_SEND_CONF_ADD_USER \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<addUser>"\
		"<conferenceKeys confEntity=\"%s\"/>"\
		"<ci:user xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" entity=\"%s\">"\
			"<ci:roles>"\
				"<ci:entry>attendee</ci:entry>"\
			"</ci:roles>"\
			"<ci:endpoint entity=\"{%s}\" xmlns:msci=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\"/>"\
		"</ci:user>"\
	"</addUser>"\
"</request>"
