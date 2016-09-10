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
 OSSLEVPMacAlgorithm.h

 OpenSSL MAC algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLEVPMACALGORITHM_H
#define _SOFTHSM_V2_OSSLEVPMACALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "MacAlgorithm.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

class OSSLEVPMacAlgorithm : public MacAlgorithm
{
public:
	// Constructor
	OSSLEVPMacAlgorithm() {
		curCTX = NULL;
	};

	// Destructor
	~OSSLEVPMacAlgorithm();

	// Signing functions
	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	// Return the MAC size
	virtual size_t getMacSize() const = 0;

protected:
	// Return the right hash for the operation
	virtual const EVP_MD* getEVPHash() const = 0;

private:
	// The current context
	HMAC_CTX* curCTX;
};

#endif // !_SOFTHSM_V2_OSSLEVPMACALGORITHM_H

