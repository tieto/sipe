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

#include "cert.h"
#include "cryptohi.h"
#include "keyhi.h"
#include "pk11pub.h"

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
		rsaParams.keySizeInBits = 2048;
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

static gchar *sign_certreq(CERTCertificateRequest *certreq,
			   SECKEYPrivateKey *private)
{
	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	gchar *base64 = NULL;

	if (arena) {
		SECItem *encoding = SEC_ASN1EncodeItem(arena,
						       NULL,
						       certreq,
						       SEC_ASN1_GET(CERT_CertificateRequestTemplate));

		if (encoding) {
			SECOidTag signtag = SEC_GetSignatureAlgorithmOidTag(private->keyType,
									    SEC_OID_UNKNOWN);

			if (signtag) {
				SECItem raw;

				if (!SEC_DerSignData(arena,
						     &raw,
						     encoding->data,
						     encoding->len,
						     private,
						     signtag)) {

					SIPE_DEBUG_INFO_NOFORMAT("sign_certreq: request signed successfully");
					base64 = g_base64_encode(raw.data, raw.len);

				} else {
					SIPE_DEBUG_ERROR_NOFORMAT("sign_certreq: signing failed");
				}
			} else {
				SIPE_DEBUG_ERROR_NOFORMAT("sign_certreq: can't find signature algorithm");
			}

			/* all memory allocated from "arena"
			   SECITEM_FreeItem(encoding, PR_TRUE); */
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sign_certreq: can't ASN.1 encode certreq");
		}

		PORT_FreeArena(arena, PR_TRUE);
	} else {
		SIPE_DEBUG_ERROR_NOFORMAT("sign_certreq: can't allocate memory");
	}

	return(base64);
}

gchar *sipe_cert_crypto_request(struct sipe_cert_crypto *ssc,
				const gchar *subject)
{
	gchar *base64 = NULL;
	SECItem *pkd;

	if (!ssc || !subject)
		return(NULL);

	pkd = SECKEY_EncodeDERSubjectPublicKeyInfo(ssc->public);
	if (pkd) {
		CERTSubjectPublicKeyInfo *spki = SECKEY_DecodeDERSubjectPublicKeyInfo(pkd);

		if (spki) {
			gchar *cn      = g_strdup_printf("CN=%s", subject);
			CERTName *name = CERT_AsciiToName(cn);
			g_free(cn);

			if (name) {
				CERTCertificateRequest *certreq = CERT_CreateCertificateRequest(name,
												spki,
												NULL);

				if (certreq) {
					base64 = sign_certreq(certreq, ssc->private);
					CERT_DestroyCertificateRequest(certreq);
				} else {
					SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_create: certreq creation failed");
				}

				CERT_DestroyName(name);
			} else {
				SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_create: subject name creation failed");
			}

			SECKEY_DestroySubjectPublicKeyInfo(spki);
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_create: DER decode public key info failed");
		}

		SECITEM_FreeItem(pkd, PR_TRUE);
	} else {
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_cert_crypto_create: DER encode failed");
	}

	return(base64);
}

void sipe_cert_crypto_destroy(gpointer certificate)
{
	CERT_DestroyCertificate(certificate);
}

gpointer sipe_cert_crypto_import(const gchar *base64)
{
	return(CERT_ConvertAndDecodeCertificate((char *) base64));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
