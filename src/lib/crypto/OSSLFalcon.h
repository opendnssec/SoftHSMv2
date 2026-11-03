/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLFalcon.h

 OpenSSL Falcon asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLFALCON_H
#define _SOFTHSM_V2_OSSLFALCON_H

#include "config.h"
#ifdef WITH_FALCON
#include "AsymmetricAlgorithm.h"

class OSSLFalcon : public AsymmetricAlgorithm
{
public:
	virtual ~OSSLFalcon() { }

	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign,
		ByteString& signature, const AsymMech::Type mechanism,
		const MechanismParam* mechanismParam = NULL);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
		const MechanismParam* mechanismParam = NULL);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	virtual bool verify(PublicKey* publicKey, const ByteString& originalData,
		const ByteString& signature, const AsymMech::Type mechanism,
		const MechanismParam* mechanismParam = NULL);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
		const MechanismParam* mechanismParam = NULL);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	virtual bool encrypt(PublicKey* publicKey, const ByteString& data,
		ByteString& encryptedData, const AsymMech::Type padding,
		const MechanismParam* mechanismParam = NULL);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
		ByteString& data, const AsymMech::Type padding,
		const MechanismParam* mechanismParam = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();

	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair,
		AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair,
		ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey,
		ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey,
		ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams,
		ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();
};

#endif // !WITH_FALCON
#endif // !_SOFTHSM_V2_OSSLFALCON_H
