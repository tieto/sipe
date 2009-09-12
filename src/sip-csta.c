/**
 * @file sip-csta.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
 *
 * Implements Remote Call Control (RCC) feature for
 * integration with legacy enterprise PBX (wired telephony) systems.
 * Should be applicable to 2005 and 2007(R2) systems.
 * Inderlying XML protocol CSTA is defined in ECMA-323.
 *
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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"


/**
 * Sends CSTA RequestSystemStatus request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 */
#define SIP_SEND_CSTA_REQUEST_SYSTEM_STATUS \
"<?xml version=\"1.0\"?>"\
"<RequestSystemStatus xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<extensions>"\
        "<privateData>"\
            "<private>"\
                "<lcs:line xmlns:lcs=\"http://schemas.microsoft.com/Lcs/2005/04/RCCExtension\">%s</lcs:line>"\
            "</private>"\
        "</privateData>"\
    "</extensions>"\
"</RequestSystemStatus>"

/**
 * Sends CSTA start monitor request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 */
#define SIP_SEND_CSTA_MONITOR_START \
"<?xml version=\"1.0\"?>"\
"<MonitorStart xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<monitorObject>"\
        "<deviceObject>%s</deviceObject>"\
    "</monitorObject>"\
"</MonitorStart>"

/**
 * Sends CSTA make call request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 * @param calling_number (%s) Ex.: tel:+3222220220
 */
#define SIP_SEND_CSTA_MAKE_CALL \
"<?xml version=\"1.0\"?>"\
"<MakeCall xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<callingDevice>%s</callingDevice>"\
    "<calledDirectoryNumber>%s</calledDirectoryNumber>"\
    "<autoOriginate>doNotPrompt</autoOriginate>"\
"</MakeCall>"



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
