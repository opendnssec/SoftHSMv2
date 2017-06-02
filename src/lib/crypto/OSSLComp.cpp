/*
 * Copyright (c) 2016 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLUtil.cpp

 Adding OpenSSL forward-compatible code as suggested by OpenSSL
 *****************************************************************************/

#include "config.h"
#include "OSSLComp.h"
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#ifdef WITH_ECC
#include <openssl/ecdsa.h>
#endif
#include <openssl/rsa.h>

#include <string.h>

// EVP digest routines
EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX*)OPENSSL_malloc(sizeof *ctx);

	if (ctx)
		EVP_MD_CTX_init(ctx);

	return ctx;
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (ctx)
	{
		EVP_MD_CTX_cleanup(ctx);
		OPENSSL_free(ctx);
	}
}

// HMAC routines
HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(*ctx));
	if (ctx == NULL) return NULL;

	HMAC_CTX_init(ctx);

	return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx == NULL) return;

	HMAC_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
}

// DH routines
void DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
	if (p != NULL)
		*p = dh->p;
	if (q != NULL)
		*q = dh->q;
	if (g != NULL)
		*g = dh->g;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/* If the fields p and g in d are NULL, the corresponding input
	 * parameters MUST be non-NULL.  q may remain NULL.
	 */
	if ((dh->p == NULL && p == NULL)
	    || (dh->g == NULL && g == NULL))
		return 0;

	if (p != NULL)
	{
		BN_free(dh->p);
		dh->p = p;
	}
	if (q != NULL)
	{
		BN_free(dh->q);
		dh->q = q;
	}
	if (g != NULL)
	{
		BN_free(dh->g);
		dh->g = g;
	}

	if (q != NULL)
	{
		dh->length = BN_num_bits(q);
	}

	return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
	if (pub_key != NULL)
		*pub_key = dh->pub_key;
	if (priv_key != NULL)
		*priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	/* If the field pub_key in dh is NULL, the corresponding input
	 * parameters MUST be non-NULL.  The priv_key field may
	 * be left NULL.
	 */
	if (dh->pub_key == NULL && pub_key == NULL)
		return 0;

	if (pub_key != NULL)
	{
		BN_free(dh->pub_key);
		dh->pub_key = pub_key;
	}
	if (priv_key != NULL)
	{
		BN_free(dh->priv_key);
		dh->priv_key = priv_key;
	}

	return 1;
}

long DH_get_length(const DH *dh)
{
	return dh->length;
}

int DH_set_length(DH *dh, long length)
{
	dh->length = length;

	return 1;
}

// DSA routines
void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
	if (p != NULL)
		*p = d->p;
	if (q != NULL)
		*q = d->q;
	if (g != NULL)
		*g = d->g;
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	/* If the fields p, q and g in d are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((d->p == NULL && p == NULL)
	    || (d->q == NULL && q == NULL)
	    || (d->g == NULL && g == NULL))
		return 0;

	if (p != NULL)
	{
		BN_free(d->p);
		d->p = p;
	}
	if (q != NULL)
	{
		BN_free(d->q);
		d->q = q;
	}
	if (g != NULL)
	{
		BN_free(d->g);
		d->g = g;
	}

	return 1;
}

void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key)
{
	if (pub_key != NULL)
		*pub_key = d->pub_key;
	if (priv_key != NULL)
		*priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
	/* If the field pub_key in d is NULL, the corresponding input
	 * parameters MUST be non-NULL.  The priv_key field may
	 * be left NULL.
	 */
	if (d->pub_key == NULL && pub_key == NULL)
		return 0;

	if (pub_key != NULL)
	{
		BN_free(d->pub_key);
		d->pub_key = pub_key;
	}
	if (priv_key != NULL)
	{
		BN_free(d->priv_key);
		d->priv_key = priv_key;
	}

	return 1;
}

// DSA_SIG routines
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
	if (pr != NULL)
		*pr = sig->r;
	if (ps != NULL)
		*ps = sig->s;
}

int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;
	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;
	return 1;
}

// ECDSA_SIG routines
#ifdef WITH_ECC
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
	if (pr != NULL)
		*pr = sig->r;
	if (ps != NULL)
		*ps = sig->s;
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	if (r == NULL || s == NULL)
		return 0;
	BN_clear_free(sig->r);
	BN_clear_free(sig->s);
	sig->r = r;
	sig->s = s;

	return 1;
}
#endif

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	/* If the fields n and e in r are NULL, the corresponding input
	 * parameters MUST be non-NULL for n and e.  d may be
	 * left NULL (in case only the public key is used).
	 */
	if ((r->n == NULL && n == NULL)
	    || (r->e == NULL && e == NULL))
		return 0;

	if (n != NULL)
	{
		BN_free(r->n);
		r->n = n;
	}
	if (e != NULL)
	{
		BN_free(r->e);
		r->e = e;
	}
	if (d != NULL)
	{
		BN_free(r->d);
		r->d = d;
	}

	return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
	/* If the fields p and q in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->p == NULL && p == NULL)
	    || (r->q == NULL && q == NULL))
		return 0;

	if (p != NULL)
	{
		BN_free(r->p);
		r->p = p;
	}
	if (q != NULL)
	{
		BN_free(r->q);
		r->q = q;
	}

	return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
	/* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->dmp1 == NULL && dmp1 == NULL)
	    || (r->dmq1 == NULL && dmq1 == NULL)
	    || (r->iqmp == NULL && iqmp == NULL))
		return 0;

	if (dmp1 != NULL)
	{
		BN_free(r->dmp1);
		r->dmp1 = dmp1;
	}
	if (dmq1 != NULL)
	{
		BN_free(r->dmq1);
		r->dmq1 = dmq1;
	}
	if (iqmp != NULL)
	{
		BN_free(r->iqmp);
		r->iqmp = iqmp;
	}

	return 1;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if (n != NULL)
		*n = r->n;
	if (e != NULL)
		*e = r->e;
	if (d != NULL)
		*d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
	if (p != NULL)
		*p = r->p;
	if (q != NULL)
		*q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
	if (dmp1 != NULL)
		*dmp1 = r->dmp1;
	if (dmq1 != NULL)
		*dmq1 = r->dmq1;
	if (iqmp != NULL)
		*iqmp = r->iqmp;
}

#endif
