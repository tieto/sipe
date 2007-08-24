/**
 * @file ntlm-sipe.h
 * 
 * gaim
 *
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
 * Modify        2007, Anibal Avelar <avelar@gmail.com>
 * ntlm structs are taken from NTLM description on 
 * http://www.innovation.ch/java/ntlm.html 
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

#ifndef _GAIM_NTLM_SIPE_H
#define _GAIM_NTLM_SIPE_H

/**
 * Generates the base64 encoded type 1 message needed for NTLM authentication
 *
 * @param hostname Your hostname
 * @param domain The domain to authenticate to
 * @return base64 encoded string to send to the server. has to be freed with g_free
 */
gchar *gaim_ntlm_gen_type1_sipe(gchar *hostname, gchar *domain);

/**
 * Parses the ntlm type 2 message
 *
 * @param type2 String containing the base64 encoded type2 message
 * @return The nonce for use in message type3
 */
gchar *gaim_ntlm_parse_type2_sipe(gchar *type2, guint32 *flags);

/**
 * Generates a type3 message
 *
 * @param username The username
 * @param passw The password
 * @param hostname The hostname
 * @param domain The domain to authenticate against
 * @param nonce The nonce returned by gaim_ntlm_parse_type2
 * @param flags Pointer to the flags returned by gaim_ntlm_parse_type2
 * @return A base64 encoded type3 message
 */
gchar *gaim_ntlm_gen_type3_sipe(const gchar *username, const gchar *passw, const gchar *hostname, const gchar *domain, const guint8 *nonce, guint32 *flags);

/**
 * Returns the IP address of the local system.
 *
 * This returns the value for real IP (avoid the 400 LCS error)
 *
 * @return The local real IP address
 */

const char *sipe_network_get_local_system_ip(void);

#endif /* _GAIM_NTLM_SIPE_H */
