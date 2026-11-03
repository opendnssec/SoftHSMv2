/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 FalconUtil.cpp

 Falcon convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_FALCON
#include "FalconUtil.h"
#include "CryptoFactory.h"

/*static*/ CK_RV FalconUtil::getFalconPrivateKey(FalconPrivateKey* privateKey, Token* token,
	OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	const bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	privateKey->setValue(value);
	value.wipe();
	ByteString publicKeyInfo = key->getByteStringValue(CKA_PUBLIC_KEY_INFO);
	if (publicKeyInfo.size() != 0)
	{
		if (isKeyPrivate)
		{
			ByteString decryptedInfo;
			if (!token->decrypt(publicKeyInfo, decryptedInfo)) return CKR_GENERAL_ERROR;
			publicKeyInfo = decryptedInfo;
		}
	}
	privateKey->setPublicKeyInfo(publicKeyInfo);
	return CKR_OK;
}

/*static*/ CK_RV FalconUtil::getFalconPublicKey(FalconPublicKey* publicKey, Token* token,
	OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	const bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);
	ByteString value;
	if (isKeyPrivate)
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setValue(value);
	value.wipe();
	return CKR_OK;
}

/*static*/ bool FalconUtil::setFalconPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* falcon = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::FALCON);
	if (falcon == NULL) return false;
	PrivateKey* priv = falcon->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(falcon);
		return false;
	}

	bool bOK = priv->PKCS8Decode(ber);
	if (bOK)
	{
		FalconPrivateKey* falconPrivateKey = (FalconPrivateKey*)priv;
		ByteString value;
		ByteString publicKeyInfo = falconPrivateKey->getPublicKeyInfo();
		if (isPrivate)
		{
			ByteString encryptedInfo;
			bOK = token->encrypt(publicKeyInfo, encryptedInfo);
			publicKeyInfo = encryptedInfo;
			bOK = bOK && token->encrypt(falconPrivateKey->getValue(), value);
		}
		else
			value = falconPrivateKey->getValue();
		bOK = bOK && key->setAttribute(CKA_PARAMETER_SET, falconPrivateKey->getParameterSet());
		bOK = bOK && key->setAttribute(CKA_PUBLIC_KEY_INFO, publicKeyInfo);
		bOK = bOK && key->setAttribute(CKA_VALUE, value);
	}

	falcon->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(falcon);
	return bOK;
}

#endif
