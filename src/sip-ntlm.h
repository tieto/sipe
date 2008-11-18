/**
 * @file sip-ntlm.h
 * 
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
 * Modify        2007, Anibal Avelar <avelar@gmail.com>
 *
 * Implemented with reference to the follow documentation:
 *   - http://davenport.sourceforge.net/ntlm.html
 *   - MS-NLMP: http://msdn.microsoft.com/en-us/library/cc207842.aspx
 *   - MS-SIPE: http://msdn.microsoft.com/en-us/library/cc246115.aspx
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

#ifndef _PURPLE_NTLM_SIPE_H
#define _PURPLE_NTLM_SIPE_H

/* Negotiate flag required in connectionless NTLM
 *   0x00000001 = NTLMSSP_NEGOTIATE_UNICODE	(A)
 *   0x00000010 = NTLMSSP_NEGOTIATE_SIGN	(D)
 *   0x00000040 = NTLMSSP_NEGOTIATE_DATAGRAM	(F)
 *   0x00000200 = NTLMSSP_NEGOTIATE_NTLM	(H)
 *   0x00008000 = NTLMSSP_NEGOTIATE_ALWAYS_SIGN (M)
 *   0x40000000 = NTLMSSP_NEGOTIATE_KEY_EXCH	(W)
 */
#define NEGOTIATE_FLAGS 0x40008250

/**
 * Parses the ntlm type 2 message
 *
 * @param challenge String containing the base64 encoded challenge message
 * @return The nonce for use in message authenticate
 */
gchar *purple_ntlm_parse_challenge(gchar *challenge, guint32 *flags);

/**
 * Generates a authenticate message
 *
 * @param username The username
 * @param passw The password
 * @param hostname The hostname
 * @param domain The domain to authenticate against
 * @param nonce The nonce returned by purple_ntlm_parse_challenge
 * @param flags Pointer to the flags returned by purple_ntlm_parse_challenge
 * @return A base64 encoded authenticate message
 */
gchar *purple_ntlm_gen_authenticate(const gchar **ntlm_key, const gchar *username, const gchar *passw, const gchar *hostname, const gchar *domain, const guint8 *nonce, guint32 *flags);

gchar * purple_ntlm_sipe_signature_make (char * msg, char * signing_key);

#endif /* _PURPLE_NTLM_SIPE_H */
