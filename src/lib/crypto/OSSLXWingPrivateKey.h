/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWingPrivateKey.h

 OpenSSL X-Wing private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H

#include "config.h"
#ifdef WITH_X_WING
#include "XWingPrivateKey.h"
#include <openssl/evp.h>

class OSSLXWingPrivateKey : public XWingPrivateKey
{
public:
	// Constructor
	OSSLXWingPrivateKey();

	// Destructor
	virtual ~OSSLXWingPrivateKey();

	// Non-copyable (raw ownership of EVP_PKEY)
	OSSLXWingPrivateKey(const OSSLXWingPrivateKey&) = delete;
	OSSLXWingPrivateKey& operator=(const OSSLXWingPrivateKey&) = delete;

	// Movable
	OSSLXWingPrivateKey(OSSLXWingPrivateKey&&) noexcept;
	OSSLXWingPrivateKey& operator=(OSSLXWingPrivateKey&&) noexcept;

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Set the X-Wing private key value
	virtual void setValue(const ByteString& value);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Retrieve the OpenSSL representations of the component keys
	EVP_PKEY* getOSSLMLKEMKey();
	EVP_PKEY* getOSSLX25519Key();

private:
	// The internal OpenSSL representations
	EVP_PKEY* mlkemPkey;
	EVP_PKEY* x25519Pkey;

	// Create the OpenSSL representations from the private key value
	void createOSSLKeys();

	// Release the OpenSSL representations
	void resetOSSLKeys();
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWINGPRIVATEKEY_H
