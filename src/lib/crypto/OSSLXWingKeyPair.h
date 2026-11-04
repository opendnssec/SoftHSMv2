/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingKeyPair.h

 OpenSSL X-Wing key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGKEYPAIR_H
#define _SOFTHSM_V2_OSSLXWINGKEYPAIR_H

#include "config.h"
#ifdef WITH_X_WING
#include "AsymmetricKeyPair.h"
#include "OSSLXWingPublicKey.h"
#include "OSSLXWingPrivateKey.h"

class OSSLXWingKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(OSSLXWingPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(OSSLXWingPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	OSSLXWingPublicKey pubKey;

	// The private key
	OSSLXWingPrivateKey privKey;
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGKEYPAIR_H
