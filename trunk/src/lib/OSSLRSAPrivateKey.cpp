/* $Id$ */

/*
 * Copyright (c) 2010 SURFnet bv
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
 OSSLRSAPrivateKey.cpp

 OpenSSL RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLRSAPrivateKey::OSSLRSAPrivateKey()
{
	rsa = RSA_new();
}

OSSLRSAPrivateKey::OSSLRSAPrivateKey(const RSA* inRSA)
{
	OSSLRSAPrivateKey::OSSLRSAPrivateKey();

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPrivateKey::~OSSLRSAPrivateKey()
{
	RSA_free(rsa);
}

// The type
/*static*/ const char* OSSLRSAPrivateKey::type = "OpenSSL RSA Private Key";

// Set from OpenSSL representation
void OSSLRSAPrivateKey::setFromOSSL(const RSA* rsa)
{
	if (rsa->p) { ByteString p = OSSL::bn2ByteString(rsa->p); setP(p); }
	if (rsa->q) { ByteString q = OSSL::bn2ByteString(rsa->q); setQ(q); }
	if (rsa->dmp1) { ByteString dp1 = OSSL::bn2ByteString(rsa->dmp1); setDP1(dp1); }
	if (rsa->dmq1) { ByteString dq1 = OSSL::bn2ByteString(rsa->dmq1); setDQ1(dq1); }
	if (rsa->iqmp) { ByteString pq = OSSL::bn2ByteString(rsa->iqmp); setPQ(pq); }
	if (rsa->d) { ByteString d = OSSL::bn2ByteString(rsa->d); setD(d); }
	if (rsa->n) { ByteString n = OSSL::bn2ByteString(rsa->n); setN(n); }
	if (rsa->e) { ByteString e = OSSL::bn2ByteString(rsa->e); setE(e); }
}

// Check if the key is of the given type
bool OSSLRSAPrivateKey::isOfType(const char* type)
{
	return !strcmp(OSSLRSAPrivateKey::type, type);
}

// Setters for the RSA private key components
void OSSLRSAPrivateKey::setP(const ByteString& p)
{
	RSAPrivateKey::setP(p);

	if (rsa->p) 
	{
		BN_clear_free(rsa->p);
		rsa->p = NULL;
	}

	rsa->p = OSSL::byteString2bn(p);
}

void OSSLRSAPrivateKey::setQ(const ByteString& q)
{
	RSAPrivateKey::setQ(q);

	if (rsa->q) 
	{
		BN_clear_free(rsa->q);
		rsa->q = NULL;
	}

	rsa->q = OSSL::byteString2bn(q);
}

void OSSLRSAPrivateKey::setPQ(const ByteString& pq)
{
	RSAPrivateKey::setPQ(pq);

	if (rsa->iqmp) 
	{
		BN_clear_free(rsa->iqmp);
		rsa->iqmp = NULL;
	}

	rsa->iqmp = OSSL::byteString2bn(pq);
}

void OSSLRSAPrivateKey::setDP1(const ByteString& dp1)
{
	RSAPrivateKey::setDP1(dp1);

	if (rsa->dmp1) 
	{
		BN_clear_free(rsa->dmp1);
		rsa->dmp1 = NULL;
	}

	rsa->dmp1 = OSSL::byteString2bn(dp1);
}

void OSSLRSAPrivateKey::setDQ1(const ByteString& dq1)
{
	RSAPrivateKey::setDQ1(dq1);

	if (rsa->dmq1) 
	{
		BN_clear_free(rsa->dmq1);
		rsa->dmq1 = NULL;
	}

	rsa->dmq1 = OSSL::byteString2bn(dq1);
}

void OSSLRSAPrivateKey::setD(const ByteString& d)
{
	RSAPrivateKey::setD(d);

	if (rsa->d) 
	{
		BN_clear_free(rsa->d);
		rsa->d = NULL;
	}

	rsa->d = OSSL::byteString2bn(d);
}


// Setters for the RSA public key components
void OSSLRSAPrivateKey::setN(const ByteString& n)
{
	RSAPrivateKey::setN(n);

	if (rsa->n) 
	{
		BN_clear_free(rsa->n);
		rsa->n = NULL;
	}

	rsa->n = OSSL::byteString2bn(n);
}

void OSSLRSAPrivateKey::setE(const ByteString& e)
{
	RSAPrivateKey::setE(e);

	if (rsa->e) 
	{
		BN_clear_free(rsa->e);
		rsa->e = NULL;
	}

	rsa->e = OSSL::byteString2bn(e);
}

// Retrieve the OpenSSL representation of the key
RSA* OSSLRSAPrivateKey::getOSSLKey()
{
	return rsa;
}

