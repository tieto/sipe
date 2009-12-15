/**
 * @file sipe-ews.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

/**
For communication with Exchange 2007/2010 Web Server/Web Services:

1) Autodiscover (HTTPS POST request). With redirect support. XML content.
1.1) DNS SRV record _autodiscover._tcp.<domain> may also be resolved.
2) Availability Web service (SOAP = HTTPS POST + XML).
3) Web server authentication required - NTLM and/or Negotiate (Kerberos).

Note: ews - EWS stands for Exchange Web Services.

It will be able to retrieve our Calendar information (FreeBusy, WorkingHours,
Meetings Subject and Location, Is_Meeting) from Exchange Web Services for 
subsequent publishing.
Our OOF note retrieval should also be addressed here.

Similar functionality for Lotus Notes/Domino, iCalendar/CalDAV/Google would be great to implement too.
*/



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
