/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconPrivateKey.h

 OpenSSL Falcon private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLFALCONPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLFALCONPRIVATEKEY_H

#include "config.h"
#ifdef WITH_FALCON
#include "FalconPrivateKey.h"
#include <openssl/evp.h>

class OSSLFalconPrivateKey : public FalconPrivateKey
{
public:
	OSSLFalconPrivateKey();
	explicit OSSLFalconPrivateKey(const EVP_PKEY* inFalconKey);
	virtual ~OSSLFalconPrivateKey();

	OSSLFalconPrivateKey(const OSSLFalconPrivateKey&) = delete;
	OSSLFalconPrivateKey& operator=(const OSSLFalconPrivateKey&) = delete;
	OSSLFalconPrivateKey(OSSLFalconPrivateKey&& other) noexcept;
	OSSLFalconPrivateKey& operator=(OSSLFalconPrivateKey&& other) noexcept;

	static const char* type;
	virtual bool isOfType(const char* inType);
	virtual void setValue(const ByteString& value);

	virtual void setPublicKeyInfo(const ByteString& publicKeyInfo);

	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);

	virtual bool setFromOSSL(const EVP_PKEY* inFalconKey);
	EVP_PKEY* getOSSLKey();

private:
	EVP_PKEY* pkey;
	void createOSSLKey();
	void invalidateOSSLKey();
};

#endif // !WITH_FALCON
#endif // !_SOFTHSM_V2_OSSLFALCONPRIVATEKEY_H
