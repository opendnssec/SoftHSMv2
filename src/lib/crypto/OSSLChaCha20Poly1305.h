/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLChaCha20Poly1305.h

 OpenSSL ChaCha20-Poly1305 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLCHACHA20POLY1305_H
#define _SOFTHSM_V2_OSSLCHACHA20POLY1305_H

#include <openssl/evp.h>
#include "config.h"
#include "OSSLEVPSymmetricAlgorithm.h"

class OSSLChaCha20Poly1305 : public OSSLEVPSymmetricAlgorithm
{
public:
	virtual ~OSSLChaCha20Poly1305() { }

	virtual bool wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/) { return false; }
	virtual bool unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/) { return false; }

	virtual size_t getBlockSize() const { return 1; }

protected:
	virtual const EVP_CIPHER* getCipher() const;
};

#endif // !_SOFTHSM_V2_OSSLCHACHA20POLY1305_H
