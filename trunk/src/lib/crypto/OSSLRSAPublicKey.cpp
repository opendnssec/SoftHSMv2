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
 OSSLRSAPublicKey.cpp

 OpenSSL RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLRSAPublicKey::OSSLRSAPublicKey()
{
	rsa = RSA_new();
}

OSSLRSAPublicKey::OSSLRSAPublicKey(const RSA* inRSA)
{
	OSSLRSAPublicKey::OSSLRSAPublicKey();

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPublicKey::~OSSLRSAPublicKey()
{
	RSA_free(rsa);
}

// The type
/*static*/ const char* OSSLRSAPublicKey::type = "OpenSSL RSA Public Key";

// Check if the key is of the given type
bool OSSLRSAPublicKey::isOfType(const char* type)
{
	return !strcmp(OSSLRSAPublicKey::type, type);
}

// Set from OpenSSL representation
void OSSLRSAPublicKey::setFromOSSL(const RSA* rsa)
{
	if (rsa->n) { ByteString n = OSSL::bn2ByteString(rsa->n); setN(n); }
	if (rsa->e) { ByteString e = OSSL::bn2ByteString(rsa->e); setE(e); }
}

// Setters for the RSA public key components
void OSSLRSAPublicKey::setN(const ByteString& n)
{
	RSAPublicKey::setN(n);

	if (rsa->n) 
	{
		BN_clear_free(rsa->n);
		rsa->n = NULL;
	}

	rsa->n = OSSL::byteString2bn(n);
}

void OSSLRSAPublicKey::setE(const ByteString& e)
{
	RSAPublicKey::setE(e);

	if (rsa->e) 
	{
		BN_clear_free(rsa->e);
		rsa->e = NULL;
	}

	rsa->e = OSSL::byteString2bn(e);
}

// Retrieve the OpenSSL representation of the key
RSA* OSSLRSAPublicKey::getOSSLKey()
{
	return rsa;
}

