/**
 * @file sipe-tls.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * TLS Protocol Version 1.0 - Handshake Messages
 *
 * TLS-DSK uses the handshake messages during authentication and session key
 * exchange. This module *ONLY* implements this part of the TLS specification!
 *
 * Specification references:
 *
 *   - RFC2246: http://www.ietf.org/rfc/rfc2246.txt
 */

#include <string.h>

#include <glib.h>

#include "sipe-cert-crypto.h"
#include "sipe-tls.h"

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
