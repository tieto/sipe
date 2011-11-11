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

#include "pk11pub.h"
#include "keyhi.h"

#include "sipe-backend.h"
#include "sipe-cert-crypto.h"

struct sipe_cert_crypto {
	SECKEYPrivateKey *private;
	SECKEYPublicKey  *public;
};

struct sipe_cert_crypto *sipe_cert_crypto_init(void)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();

	if (slot) {
		PK11RSAGenParams rsaParams;
		struct sipe_cert_crypto *ssc = g_new0(struct sipe_cert_crypto, 1);

		/* RSA parameters - should those be configurable? */
		rsaParams.keySizeInBits = 1024;
		rsaParams.pe            = 65537;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_cert_crypto_init: generate key pair, this might take a while...");
		ssc->private = PK11_GenerateKeyPair(slot,
						    CKM_RSA_PKCS_KEY_PAIR_GEN,
						    &rsaParams,
						    &ssc->public,
						    PR_FALSE, /* not permanent */
						    PR_TRUE,  /* sensitive */
						    NULL);
		if (ssc->private) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_cert_crypto_init: key pair generated");
			PK11_FreeSlot(slot);
			return(ssc);
		}

		SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_init: key generation failed");
		g_free(ssc);
		PK11_FreeSlot(slot);
	}

	return(NULL);
}

void sipe_cert_crypto_free(struct sipe_cert_crypto *ssc)
{
	if (ssc) {
		if (ssc->public)
			SECKEY_DestroyPublicKey(ssc->public);
		if (ssc->private)
			SECKEY_DestroyPrivateKey(ssc->private);
		g_free(ssc);
	}
}

gchar *sipe_cert_crypto_request(struct sipe_cert_crypto *ssc,
				const gchar *subject)
{
	/* temporary */
	(void)ssc;
	(void)subject;
	return(NULL);
}

void sipe_cert_crypto_destroy(gpointer certificate)
{
	/* temporary */
	(void)certificate;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
