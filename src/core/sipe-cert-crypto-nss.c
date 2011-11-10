 /**
 * @file sipe-cert-crypto-nss.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 * Certificate routines implementation based on NSS.
 */

#include <glib.h>

#include "nss.h"
#include "pk11pub.h"

#include "sipe-backend.h"
#include "sipe-cert-crypto.h"

guchar *sipe_cert_crypto_unwrap_kw_aes(const guchar *aes_key,
				       gsize aes_key_len,
				       const guchar *wrapped,
				       gsize wrapped_len,
				       gsize *unwrapped_len)
{
	/* Sanity checks */
	if (!aes_key || !wrapped) {
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_unwrap_kw_aes: invalid input data");
	}

	/* temporary */
	(void)aes_key_len;
	(void)wrapped_len;
	(void)unwrapped_len;
	return(NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
