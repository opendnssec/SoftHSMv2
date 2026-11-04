/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalconKeyPair.cpp

 OpenSSL Falcon key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_FALCON
#include "OSSLFalconKeyPair.h"

void OSSLFalconKeyPair::setPublicKey(OSSLFalconPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
}

void OSSLFalconKeyPair::setPrivateKey(OSSLFalconPrivateKey& privateKey)
{
	ByteString publicKeyInfo = privateKey.getPublicKeyInfo();
	privKey.setValue(privateKey.getValue());
	privKey.setPublicKeyInfo(publicKeyInfo);
}

PublicKey* OSSLFalconKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLFalconKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

PrivateKey* OSSLFalconKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLFalconKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif
