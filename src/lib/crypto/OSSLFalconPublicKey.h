/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconPublicKey.h

 OpenSSL Falcon public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLFALCONPUBLICKEY_H
#define _SOFTHSM_V2_OSSLFALCONPUBLICKEY_H

#include "config.h"
#ifdef WITH_FALCON
#include "FalconPublicKey.h"
#include <openssl/evp.h>

class OSSLFalconPublicKey : public FalconPublicKey
{
public:
	OSSLFalconPublicKey();
	explicit OSSLFalconPublicKey(const EVP_PKEY* inFalconKey);
	virtual ~OSSLFalconPublicKey();

	OSSLFalconPublicKey(const OSSLFalconPublicKey&) = delete;
	OSSLFalconPublicKey& operator=(const OSSLFalconPublicKey&) = delete;
	OSSLFalconPublicKey(OSSLFalconPublicKey&& other) noexcept;
	OSSLFalconPublicKey& operator=(OSSLFalconPublicKey&& other) noexcept;

	static const char* type;
	virtual bool isOfType(const char* inType);
	virtual void setValue(const ByteString& value);

	virtual void setFromOSSL(const EVP_PKEY* inFalconKey);
	EVP_PKEY* getOSSLKey();

private:
	EVP_PKEY* pkey;
	void createOSSLKey();
};

#endif // !WITH_FALCON
#endif // !_SOFTHSM_V2_OSSLFALCONPUBLICKEY_H
