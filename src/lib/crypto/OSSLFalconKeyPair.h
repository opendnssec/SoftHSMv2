/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconKeyPair.h

 OpenSSL Falcon key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLFALCONKEYPAIR_H
#define _SOFTHSM_V2_OSSLFALCONKEYPAIR_H

#include "config.h"
#ifdef WITH_FALCON
#include "AsymmetricKeyPair.h"
#include "OSSLFalconPrivateKey.h"
#include "OSSLFalconPublicKey.h"

class OSSLFalconKeyPair : public AsymmetricKeyPair
{
public:
	void setPublicKey(OSSLFalconPublicKey& publicKey);
	void setPrivateKey(OSSLFalconPrivateKey& privateKey);

	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	OSSLFalconPublicKey pubKey;
	OSSLFalconPrivateKey privKey;
};

#endif // !WITH_FALCON
#endif // !_SOFTHSM_V2_OSSLFALCONKEYPAIR_H
