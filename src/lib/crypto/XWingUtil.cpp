/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 XWingUtil.cpp

 X-Wing convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_X_WING
#include "XWingUtil.h"
#include "XWingParameters.h"
#include "CryptoFactory.h"

/*static*/ CK_RV XWingUtil::getXWingPrivateKey(XWingPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	ByteString value;
	if (key->getBooleanValue(CKA_PRIVATE, false))
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = key->getByteStringValue(CKA_VALUE);
	if (value.size() != XWingParameters::X_WING_PRIV_LENGTH)
		return CKR_GENERAL_ERROR;

	privateKey->setValue(value);
	value.wipe();
	return CKR_OK;
}

/*static*/ CK_RV XWingUtil::getXWingPublicKey(XWingPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	ByteString value;
	if (key->getBooleanValue(CKA_PRIVATE, false))
	{
		if (!token->decrypt(key->getByteStringValue(CKA_VALUE), value))
			return CKR_GENERAL_ERROR;
	}
	else
		value = key->getByteStringValue(CKA_VALUE);
	if (value.size() != XWingParameters::X_WING_PUB_LENGTH)
		return CKR_GENERAL_ERROR;

	publicKey->setValue(value);
	value.wipe();
	return CKR_OK;
}

/*static*/ bool XWingUtil::setXWingPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* xwing = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::XWING);
	if (xwing == NULL) return false;
	PrivateKey* priv = xwing->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(xwing);
		return false;
	}

	bool bOK = priv->PKCS8Decode(ber);
	if (bOK)
	{
		ByteString value;
		if (isPrivate)
			bOK = token->encrypt(((XWingPrivateKey*)priv)->getValue(), value);
		else
			value = ((XWingPrivateKey*)priv)->getValue();
		bOK = bOK && key->setAttribute(CKA_VALUE, value);
	}

	xwing->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(xwing);
	return bOK;
}

#endif
