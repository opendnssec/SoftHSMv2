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
 BotanEDKeyPair.h

 Botan EDDSA key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANEDKEYPAIR_H
#define _SOFTHSM_V2_BOTANEDKEYPAIR_H

#include "config.h"
#include "AsymmetricKeyPair.h"
#include "BotanEDPublicKey.h"
#include "BotanEDPrivateKey.h"

class BotanEDKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(BotanEDPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(BotanEDPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	BotanEDPublicKey pubKey;

	// The private key
	BotanEDPrivateKey privKey;
};
#endif // !_SOFTHSM_V2_BOTANEDKEYPAIR_H

