/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanRSAPrivateKey.h

 Botan RSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANRSAPRIVATEKEY_H
#define _SOFTHSM_V2_BOTANRSAPRIVATEKEY_H

#include "config.h"
#include "RSAPrivateKey.h"
#include <botan/rsa.h>

class BotanRSAPrivateKey : public RSAPrivateKey
{
public:
	// Constructors
	BotanRSAPrivateKey();

	BotanRSAPrivateKey(const Botan::RSA_PrivateKey* inRSA);

	// Destructor
	virtual ~BotanRSAPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the RSA private key components
	virtual void setP(const ByteString& inP);
	virtual void setQ(const ByteString& inQ);
	virtual void setPQ(const ByteString& inPQ);
	virtual void setDP1(const ByteString& inDP1);
	virtual void setDQ1(const ByteString& inDQ1);
	virtual void setD(const ByteString& inD);

	// Setters for the RSA public key components
	virtual void setN(const ByteString& inN);
	virtual void setE(const ByteString& inE);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from Botan representation
	virtual void setFromBotan(const Botan::RSA_PrivateKey* inRSA);

	// Retrieve the Botan representation of the key
	Botan::RSA_PrivateKey* getBotanKey();

private:
	// The internal Botan representation
	Botan::RSA_PrivateKey* rsa;

	void createBotanKey();
};

#endif // !_SOFTHSM_V2_OSSLRSAPRIVATEKEY_H

