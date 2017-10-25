/*
 * Copyright (c) 2017 SURFnet bv
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
 OSSLEVPCMacAlgorithm.h

 OpenSSL CMAC algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLEVPCMACALGORITHM_H
#define _SOFTHSM_V2_OSSLEVPCMACALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "MacAlgorithm.h"
#include <openssl/evp.h>
#include <openssl/cmac.h>

class OSSLEVPCMacAlgorithm : public MacAlgorithm
{
public:
	// Constructor
	OSSLEVPCMacAlgorithm() {
		curCTX = NULL;
	};

	// Destructor
	~OSSLEVPCMacAlgorithm();

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
	// Return the right cipher for the operation
	virtual const EVP_CIPHER* getEVPCipher() const = 0;

private:
	// The current context
	CMAC_CTX* curCTX;
};

#endif // !_SOFTHSM_V2_OSSLEVPCMACALGORITHM_H

