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
 OSSLAES.h

 OpenSSL AES implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLAES_H
#define _SOFTHSM_V2_OSSLAES_H

#include <openssl/evp.h>
#include <string>
#include "config.h"
#include "OSSLEVPSymmetricAlgorithm.h"

class OSSLAES : public OSSLEVPSymmetricAlgorithm
{
public:
	// Destructor
	virtual ~OSSLAES() { }

	// Wrap/Unwrap keys
	virtual bool wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);

	virtual bool unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);

	// Return the block size
	virtual size_t getBlockSize() const;

protected:
	// Return the right EVP cipher for the operation
	virtual const EVP_CIPHER* getCipher() const;
	const EVP_CIPHER* getWrapCipher(const SymWrap::Type mode, const SymmetricKey* key) const;
	bool wrapUnwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out, const int wrap) const;
	bool checkLength(const int insize, const int minsize, const char * const operation) const;
};

#endif // !_SOFTHSM_V2_OSSLAES_H

