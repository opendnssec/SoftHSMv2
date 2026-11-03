/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/****************************************************************************
 OSSLXWing.h

 OpenSSL X-Wing asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLXWING_H
#define _SOFTHSM_V2_OSSLXWING_H

#include "config.h"
#ifdef WITH_X_WING
#include "AsymmetricAlgorithm.h"
#include <openssl/evp.h>

class OSSLXWing : public AsymmetricAlgorithm
{
public:
	// Destructor
	virtual ~OSSLXWing() { }

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data,
	                     ByteString& encryptedData, const AsymMech::Type padding,
	                     const MechanismParam* mechanismParam = NULL);

	// Encapsulate/Decapsulate functions
	virtual bool encapsulate(PublicKey* publicKey, ByteString& cipherText,
	                         SymmetricKey** secretKey, CK_KEY_TYPE keyType,
	                         const AsymMech::Type mechanism);
	virtual bool decapsulate(PrivateKey* privateKey,
	                         const ByteString& cipherText,
	                         SymmetricKey** secretKey, CK_KEY_TYPE keyType,
	                         const AsymMech::Type mechanism);

	// Decryption functions
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
	                     ByteString& data, const AsymMech::Type padding,
	                     const MechanismParam* mechanismParam = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair,
	                             AsymmetricParameters* parameters,
	                             RNG* rng = NULL);
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

protected:
	// Deterministic encapsulation for test vectors (draft 10, section 5.4.1)
	bool encapsulate(PublicKey* publicKey, ByteString& cipherText,
	                 SymmetricKey** secretKey, CK_KEY_TYPE keyType,
	                 const AsymMech::Type mechanism, const ByteString& seed);

private:
	// Component encapsulation/decapsulation functions
	bool encapsulateMLKEM(EVP_PKEY* mlkemPkey, ByteString& cipherText,
	                     ByteString& sharedSecret, const ByteString& seed);
	bool encapsulateX25519(EVP_PKEY* x25519Pkey, ByteString& cipherText,
	                      ByteString& sharedSecret, const ByteString& seed);
	bool encapsulateComponents(EVP_PKEY* mlkemPkey,
	                           EVP_PKEY* x25519Pkey,
	                           ByteString& mlkemCipherText,
	                           ByteString& mlkemSharedSecret,
	                           ByteString& x25519CipherText,
	                           ByteString& x25519SharedSecret,
	                           const ByteString& seed);
	bool decapsulateMLKEM(EVP_PKEY* mlkemPkey,
	                     const ByteString& cipherText,
	                     ByteString& sharedSecret);
	bool decapsulateX25519(EVP_PKEY* x25519Pkey,
	                      const ByteString& cipherText,
	                      ByteString& sharedSecret);

	// X-Wing combiner
	bool combineSharedSecrets(const ByteString& mlkemSharedSecret,
	                          const ByteString& x25519SharedSecret,
	                          const ByteString& x25519CipherText,
	                          const ByteString& x25519PublicKey,
	                          ByteString& sharedSecret);
};

#endif // WITH_X_WING
#endif // !_SOFTHSM_V2_OSSLXWING_H
