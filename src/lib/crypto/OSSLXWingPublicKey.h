/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPublicKey.h

 OpenSSL X-Wing public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGPUBLICKEY_H
#define _SOFTHSM_V2_OSSLXWINGPUBLICKEY_H

#include "config.h"
#ifdef WITH_X_WING
#include "XWingPublicKey.h"
#include <openssl/evp.h>

class OSSLXWingPublicKey : public XWingPublicKey
{
public:
	// Constructor
	OSSLXWingPublicKey();

	// Destructor
	virtual ~OSSLXWingPublicKey();

	// Non-copyable (raw ownership of EVP_PKEY)
	OSSLXWingPublicKey(const OSSLXWingPublicKey&) = delete;
	OSSLXWingPublicKey& operator=(const OSSLXWingPublicKey&) = delete;

	// Movable
	OSSLXWingPublicKey(OSSLXWingPublicKey&&) noexcept;
	OSSLXWingPublicKey& operator=(OSSLXWingPublicKey&&) noexcept;

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Set the X-Wing public key value
	virtual void setValue(const ByteString& value);

	// Set from the OpenSSL representations of the component keys
	virtual void setFromOSSL(const EVP_PKEY* mlkemKey, const EVP_PKEY* x25519Key);

	// Retrieve the OpenSSL representations of the component keys
	EVP_PKEY* getOSSLMLKEMKey();
	EVP_PKEY* getOSSLX25519Key();

private:
	// The internal OpenSSL representations
	EVP_PKEY* mlkemPkey;
	EVP_PKEY* x25519Pkey;

	// Create the OpenSSL representations from the public key value
	void createOSSLKeys();

	// Release the OpenSSL representations
	void resetOSSLKeys();
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGPUBLICKEY_H
