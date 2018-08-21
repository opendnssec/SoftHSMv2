/*
 * Copyright (c) 2012 SURFnet
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SymmetricAlgorithmTests.cpp

 Contains test cases for symmetrical algorithms (i.e., AES and DES)
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <climits>
//#include <iomanip>
#include "SymmetricAlgorithmTests.h"

// CKA_TOKEN
const CK_BBOOL ON_TOKEN = CK_TRUE;
const CK_BBOOL IN_SESSION = CK_FALSE;

// CKA_PRIVATE
const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;

#define NR_OF_BLOCKS_IN_TEST 0x10001

CPPUNIT_TEST_SUITE_REGISTRATION(SymmetricAlgorithmTests);

CK_RV SymmetricAlgorithmTests::generateGenericKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV SymmetricAlgorithmTests::generateAesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_ULONG bytes = 16;
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

#ifndef WITH_FIPS
CK_RV SymmetricAlgorithmTests::generateDesKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

CK_RV SymmetricAlgorithmTests::generateDes2Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES2_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}
#endif

CK_RV SymmetricAlgorithmTests::generateDes3Key(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	// CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
	};

	hKey = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			     keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
			     &hKey) );
}

void SymmetricAlgorithmTests::encryptDecrypt(
		const CK_MECHANISM_TYPE mechanismType,
		const size_t blockSize,
		const CK_SESSION_HANDLE hSession,
		const CK_OBJECT_HANDLE hKey,
		const size_t messageSize,
		const bool isSizeOK)
{
	class PartSize {// class to get random size for part
	private:        // we want to know for sure that no part length is causing any problem.
		const int blockSize;
		const unsigned* pRandom;// point to memory with random data. We are using the data to be encrypted.
		const unsigned* pBack;// point to memory where random data ends.
		int current;// the current size.
	public:
		PartSize(
				const int _blockSize,
				const std::vector<CK_BYTE>* pvData) :
					blockSize(_blockSize),
					pRandom((const unsigned*)&pvData->front()),
					pBack((const unsigned*)&pvData->back()),
					current(blockSize*4){};
		int getCurrent() {// current part size
			return current;
		}
		int getNext() {// get next part size.
			// Check if we do not have more random data
			if ((pRandom+sizeof(unsigned)-1) > pBack) {
				current = blockSize*4;
				return current;
			}
			const unsigned random(*(pRandom++));
			// Bit shift to handle 32- and 64-bit systems.
			// Just want a simple random part length,
			// not a perfect random number (bit shifting will
			// give some loss of precision).
			current = ((unsigned long)random >> 20)*blockSize*0x100/(UINT_MAX >> 20) + 1;
			//std::cout << "New random " << std::hex << random << " current " << std::hex << std::setfill('0') << std::setw(4) << current << " block size " << std::hex << blockSize << std::endl;
			return current;
		}
	};

	const std::vector<CK_BYTE> vData(messageSize);
	std::vector<CK_BYTE> vEncryptedData;
	std::vector<CK_BYTE> vEncryptedDataParted;
	PartSize partSize(blockSize, &vData);

	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_GenerateRandom(hSession, (CK_BYTE_PTR)&vData.front(), messageSize) ) );

	const CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_MECHANISM_PTR pMechanism((CK_MECHANISM_PTR)&mechanism);
	CK_AES_CTR_PARAMS ctrParams =
	{
		32,
		{
			0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		}
	};
	CK_BYTE gcmIV[] = {
		0xCA, 0xFE, 0xBA, 0xBE, 0xFA, 0xCE,
		0xDB, 0xAD, 0xDE, 0xCA, 0xF8, 0x88
	};
	CK_BYTE gcmAAD[] = {
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
		0xAB, 0xAD, 0xDA, 0xD2
	};
	CK_GCM_PARAMS gcmParams =
	{
		&gcmIV[0],
		sizeof(gcmIV),
		sizeof(gcmIV)*8,
		&gcmAAD[0],
		sizeof(gcmAAD),
		16*8
	};

	switch (mechanismType)
	{
		case CKM_DES_CBC:
		case CKM_DES_CBC_PAD:
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
		case CKM_AES_CBC:
		case CKM_AES_CBC_PAD:
			pMechanism->pParameter = (CK_VOID_PTR)&vData.front();
			pMechanism->ulParameterLen = blockSize;
			break;
		case CKM_AES_CTR:
			pMechanism->pParameter = &ctrParams;
			pMechanism->ulParameterLen = sizeof(ctrParams);
			break;
		case CKM_AES_GCM:
			pMechanism->pParameter = &gcmParams;
			pMechanism->ulParameterLen = sizeof(gcmParams);
			break;
		default:
			break;
	}

	// Single-part encryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptInit(hSession,pMechanism,hKey) ) );
	{
		CK_ULONG ulEncryptedDataLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_Encrypt(hSession,(CK_BYTE_PTR)&vData.front(),messageSize,NULL_PTR,&ulEncryptedDataLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			vEncryptedData.resize(ulEncryptedDataLen);
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_Encrypt(hSession,(CK_BYTE_PTR)&vData.front(),messageSize,&vEncryptedData.front(),&ulEncryptedDataLen) ) );
			vEncryptedData.resize(ulEncryptedDataLen);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE("C_Encrypt should fail with C_CKR_DATA_LEN_RANGE", (CK_RV)CKR_DATA_LEN_RANGE, rv);
			vEncryptedData = vData;
		}
	}

	// Multi-part encryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptInit(hSession,pMechanism,hKey) ) );

	for ( std::vector<CK_BYTE>::const_iterator i(vData.begin()); i<vData.end(); i+=partSize.getCurrent() ) {
		const CK_ULONG lPartLen( i+partSize.getNext()<vData.end() ? partSize.getCurrent() : vData.end()-i );
		CK_ULONG ulEncryptedPartLen;
		CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,(CK_BYTE_PTR)&(*i),lPartLen,NULL_PTR,&ulEncryptedPartLen) ) );
		const size_t oldSize( vEncryptedDataParted.size() );
		vEncryptedDataParted.resize(oldSize+ulEncryptedPartLen);
		CK_BYTE dummy;
		const CK_BYTE_PTR pEncryptedPart( ulEncryptedPartLen>0 ? &vEncryptedDataParted.at(oldSize) : &dummy );
		CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,(CK_BYTE_PTR)&(*i),lPartLen,pEncryptedPart,&ulEncryptedPartLen) ) );
		vEncryptedDataParted.resize(oldSize+ulEncryptedPartLen);
	}
	{
		CK_ULONG ulLastEncryptedPartLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_EncryptFinal(hSession,NULL_PTR,&ulLastEncryptedPartLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			const size_t oldSize( vEncryptedDataParted.size() );
			CK_BYTE dummy;
			vEncryptedDataParted.resize(oldSize+ulLastEncryptedPartLen);
			const CK_BYTE_PTR pLastEncryptedPart( ulLastEncryptedPartLen>0 ? &vEncryptedDataParted.at(oldSize) : &dummy );
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_EncryptFinal(hSession,pLastEncryptedPart,&ulLastEncryptedPartLen) ) );
			vEncryptedDataParted.resize(oldSize+ulLastEncryptedPartLen);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE("C_EncryptFinal should fail with C_CKR_DATA_LEN_RANGE", (CK_RV)CKR_DATA_LEN_RANGE, rv);
			vEncryptedDataParted = vData;
		}
	}

	// Single-part decryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptInit(hSession,pMechanism,hKey) ) );

	{
		CK_ULONG ulDataLen;
		const CK_RV rv( CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataLen) ) );
		if ( isSizeOK ) {
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
			std::vector<CK_BYTE> vDecryptedData(ulDataLen);
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedData.front(),&ulDataLen) ) );
			vDecryptedData.resize(ulDataLen);
			CPPUNIT_ASSERT_MESSAGE("C_Encrypt C_Decrypt does not give the original", vData==vDecryptedData);
		} else {
			CPPUNIT_ASSERT_EQUAL_MESSAGE( "C_Decrypt should fail with CKR_ENCRYPTED_DATA_LEN_RANGE", (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
		}
	}

	// Multi-part decryption
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptInit(hSession,pMechanism,hKey) ) );
	{
		std::vector<CK_BYTE> vDecryptedData;
		CK_BYTE dummy;
		for ( std::vector<CK_BYTE>::iterator i(vEncryptedDataParted.begin()); i<vEncryptedDataParted.end(); i+=partSize.getCurrent()) {
			const CK_ULONG ulPartLen( i+partSize.getNext()<vEncryptedDataParted.end() ? partSize.getCurrent() : vEncryptedDataParted.end()-i );
			CK_ULONG ulDecryptedPartLen;
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&(*i),ulPartLen,NULL_PTR,&ulDecryptedPartLen) ) );
			const size_t oldSize( vDecryptedData.size() );
			vDecryptedData.resize(oldSize+ulDecryptedPartLen);
			const CK_BYTE_PTR pDecryptedPart( ulDecryptedPartLen>0 ? &vDecryptedData.at(oldSize) : &dummy );
			CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&(*i),ulPartLen,pDecryptedPart,&ulDecryptedPartLen) ) );
			vDecryptedData.resize(oldSize+ulDecryptedPartLen);
		}
		{
			CK_ULONG ulLastPartLen;
			const CK_RV rv( CRYPTOKI_F_PTR( C_DecryptFinal(hSession,NULL_PTR,&ulLastPartLen) ) );
			if ( isSizeOK ) {
				CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
				const size_t oldSize( vDecryptedData.size() );
				vDecryptedData.resize(oldSize+ulLastPartLen);
				const CK_BYTE_PTR pLastPart( ulLastPartLen>0 ? &vDecryptedData.at(oldSize) : &dummy );
				CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, CRYPTOKI_F_PTR( C_DecryptFinal(hSession,pLastPart,&ulLastPartLen) ) );
				vDecryptedData.resize(oldSize+ulLastPartLen);
				CPPUNIT_ASSERT_MESSAGE("C_EncryptUpdate/C_EncryptFinal C_DecryptUpdate/C_DecryptFinal does not give the original", vData==vDecryptedData);
			} else {
				CPPUNIT_ASSERT_EQUAL_MESSAGE( "C_EncryptFinal should fail with CKR_ENCRYPTED_DATA_LEN_RANGE", (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
			}
		}
	}
}

CK_RV SymmetricAlgorithmTests::generateRsaPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ULONG bits = 1536;
	CK_BYTE pubExp[] = {0x01, 0x00, 0x01};
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pubAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, &pubExp[0], sizeof(pubExp) }
	};
	CK_ATTRIBUTE privAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
	hKey = CK_INVALID_HANDLE;
	CK_RV rv;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
			       pubAttribs, sizeof(pubAttribs)/sizeof(CK_ATTRIBUTE),
			       privAttribs, sizeof(privAttribs)/sizeof(CK_ATTRIBUTE),
			       &hPub, &hKey) );
	if (hPub != CK_INVALID_HANDLE)
	{
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
	}
	return rv;
}

#ifdef WITH_GOST
CK_RV SymmetricAlgorithmTests::generateGostPrivateKey(CK_SESSION_HANDLE hSession, CK_BBOOL bToken, CK_BBOOL bPrivate, CK_OBJECT_HANDLE &hKey)
{
	CK_MECHANISM mechanism = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BYTE param_a[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
	CK_BYTE param_b[] = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };
	CK_BYTE subject[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE pubAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bFalse, sizeof(bFalse) },
		{ CKA_GOSTR3410_PARAMS, &param_a[0], sizeof(param_a) },
		{ CKA_GOSTR3411_PARAMS, &param_b[0], sizeof(param_b) }
	};
	CK_ATTRIBUTE privAttribs[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bPrivate, sizeof(bPrivate) },
		{ CKA_SUBJECT, &subject[0], sizeof(subject) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_SIGN, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bFalse, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
	hKey = CK_INVALID_HANDLE;
	CK_RV rv;
	rv = CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
			       pubAttribs, sizeof(pubAttribs)/sizeof(CK_ATTRIBUTE),
			       privAttribs, sizeof(privAttribs)/sizeof(CK_ATTRIBUTE),
			       &hPub, &hKey) );
	if (hPub != CK_INVALID_HANDLE)
	{
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
	}
	return rv;
}
#endif

void SymmetricAlgorithmTests::aesWrapUnwrapGeneric(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_KEY_TYPE genKeyType = CKK_GENERIC_SECRET;
	CK_BYTE keyPtr[128];
	CK_ULONG keyLen =
		mechanismType == CKM_AES_KEY_WRAP_PAD ? 125UL : 128UL;
	CK_ATTRIBUTE attribs[] = {
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) },
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) }, // Wrapping is allowed even on sensitive objects
		{ CKA_VALUE, keyPtr, keyLen }
	};
	CK_OBJECT_HANDLE hSecret;
	CK_RV rv;

	rv = CRYPTOKI_F_PTR( C_GenerateRandom(hSession, keyPtr, keyLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	hSecret = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSecret != CK_INVALID_HANDLE);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	CK_ULONG zero = 0UL;
	CK_ULONG rndKeyLen = keyLen;
	if (mechanismType == CKM_AES_KEY_WRAP_PAD)
		rndKeyLen =  (keyLen + 7) & ~7;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_KEY_UNEXTRACTABLE);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	attribs[0].pValue = &bTrue;

	hSecret = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, attribs, sizeof(attribs)/sizeof(CK_ATTRIBUTE), &hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hSecret != CK_INVALID_HANDLE);

	// Estimate wrapped length
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrappedLen == rndKeyLen + 8);

	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(wrappedLen == rndKeyLen + 8);

	// This should always fail because wrapped data have to be longer than 0 bytes
	zero = 0;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hSecret, wrappedPtr, &zero) );
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	CK_ATTRIBUTE nattribs[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &genKeyType, sizeof(genKeyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bFalse, sizeof(bFalse) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_VERIFY, &bTrue, sizeof(bTrue) }
	};
	CK_OBJECT_HANDLE hNew;

	hNew = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nattribs, sizeof(nattribs)/sizeof(CK_ATTRIBUTE), &hNew) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hNew != CK_INVALID_HANDLE);

	free(wrappedPtr);
	wrappedPtr = NULL_PTR;
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hSecret) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::aesWrapUnwrapRsa(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = generateRsaPrivateKey(hSession, CK_TRUE, CK_TRUE, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BYTE_PTR prkAttrPtr = NULL_PTR;
	CK_ULONG prkAttrLen = 0UL;
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_PRIME_2, NULL_PTR, 0UL }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_RSA);

	prkAttrLen = prkAttribs[2].ulValueLen;
	prkAttrPtr = (CK_BYTE_PTR) malloc(2 * prkAttrLen);
	CPPUNIT_ASSERT(prkAttrPtr != NULL_PTR);
	prkAttribs[2].pValue = prkAttrPtr;
	prkAttribs[2].ulValueLen = prkAttrLen;

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	hPrk = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	prkAttribs[2].pValue = prkAttrPtr + prkAttrLen;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_RSA);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);
	CPPUNIT_ASSERT(memcmp(prkAttrPtr, prkAttrPtr + prkAttrLen, prkAttrLen) == 0);

	free(wrappedPtr);
	free(prkAttrPtr);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#ifdef WITH_GOST
void SymmetricAlgorithmTests::aesWrapUnwrapGost(CK_MECHANISM_TYPE mechanismType, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_MECHANISM mechanism = { mechanismType, NULL_PTR, 0 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;
	CK_RV rv = generateGostPrivateKey(hSession, CK_TRUE, CK_TRUE, hPrk);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_GOSTR3410;
	CK_BYTE_PTR prkAttrPtr = NULL_PTR;
	CK_ULONG prkAttrLen = 0UL;
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VALUE, NULL_PTR, 0UL }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_GOSTR3410);

	prkAttrLen = prkAttribs[2].ulValueLen;
	prkAttrPtr = (CK_BYTE_PTR) malloc(2 * prkAttrLen);
	CPPUNIT_ASSERT(prkAttrPtr != NULL_PTR);
	prkAttribs[2].pValue = prkAttrPtr;
	prkAttribs[2].ulValueLen = prkAttrLen;

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);

	CK_BYTE_PTR wrappedPtr = NULL_PTR;
	CK_ULONG wrappedLen = 0UL;
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	wrappedPtr = (CK_BYTE_PTR) malloc(wrappedLen);
	CPPUNIT_ASSERT(wrappedPtr != NULL_PTR);
	rv = CRYPTOKI_F_PTR( C_WrapKey(hSession, &mechanism, hKey, hPrk, wrappedPtr, &wrappedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE nPrkAttribs[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_SIGN, &bFalse,sizeof(bFalse) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_SENSITIVE, &bFalse, sizeof(bFalse) },
		{ CKA_EXTRACTABLE, &bTrue, sizeof(bTrue) }
	};

	hPrk = CK_INVALID_HANDLE;
	rv = CRYPTOKI_F_PTR( C_UnwrapKey(hSession, &mechanism, hKey, wrappedPtr, wrappedLen, nPrkAttribs, sizeof(nPrkAttribs)/sizeof(CK_ATTRIBUTE), &hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

	prkAttribs[2].pValue = prkAttrPtr + prkAttrLen;
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hPrk, prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE)) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT(prkAttribs[0].ulValueLen == sizeof(CK_OBJECT_CLASS));
	CPPUNIT_ASSERT(*(CK_OBJECT_CLASS*)prkAttribs[0].pValue == CKO_PRIVATE_KEY);
	CPPUNIT_ASSERT(prkAttribs[1].ulValueLen == sizeof(CK_KEY_TYPE));
	CPPUNIT_ASSERT(*(CK_KEY_TYPE*)prkAttribs[1].pValue == CKK_GOSTR3410);
	CPPUNIT_ASSERT(prkAttribs[2].ulValueLen == prkAttrLen);
	CPPUNIT_ASSERT(memcmp(prkAttrPtr, prkAttrPtr + prkAttrLen, prkAttrLen) == 0);

	free(wrappedPtr);
	free(prkAttrPtr);
	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPrk) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
#endif

void SymmetricAlgorithmTests::testAesEncryptDecrypt()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateAesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// AES allways have the block size of 128 bits (0x80 bits 0x10 bytes).
	// with padding all message sizes could be encrypted-decrypted.
	// without padding the message size must be a multiple of the block size.
	const int blockSize(0x10);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_AES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_AES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_CTR,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
#ifdef WITH_AES_GCM
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_AES_GCM,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
#endif
}

void SymmetricAlgorithmTests::testAesWrapUnwrap()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private object
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate a wrapping session public key
	rv = generateAesKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	aesWrapUnwrapGeneric(CKM_AES_KEY_WRAP, hSession, hKey);
	aesWrapUnwrapRsa(CKM_AES_KEY_WRAP, hSession, hKey);
#ifdef WITH_GOST
	aesWrapUnwrapGost(CKM_AES_KEY_WRAP, hSession, hKey);
#endif

#ifdef HAVE_AES_KEY_WRAP_PAD
	aesWrapUnwrapGeneric(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
	aesWrapUnwrapRsa(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
#ifdef WITH_GOST
	aesWrapUnwrapGost(CKM_AES_KEY_WRAP_PAD, hSession, hKey);
#endif
#endif
}

void SymmetricAlgorithmTests::testDesEncryptDecrypt()
{
	CK_RV rv;
	// CK_UTF8CHAR sopin[] = SLOT_0_SO1_PIN;
	// CK_ULONG sopinLength = sizeof(sopin) - 1;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	// 3DES and DES always have the block size of 64 bits (0x40 bits 0x8 bytes).
	// with padding all message sizes could be encrypted-decrypted.
	// without padding the message size must be a multiple of the block size.
	const int blockSize(0x8);

#ifndef WITH_FIPS
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDesKey(hSessionRW,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);

	CK_OBJECT_HANDLE hKey2 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes2Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey2);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
#endif

	CK_OBJECT_HANDLE hKey3 = CK_INVALID_HANDLE;

	// Generate all combinations of session/token keys.
	rv = generateDes3Key(hSessionRW,IN_SESSION,IS_PUBLIC,hKey3);
	CPPUNIT_ASSERT(rv == CKR_OK);

	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST-1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1);
	encryptDecrypt(CKM_DES3_CBC_PAD,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_CBC,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST);
	encryptDecrypt(CKM_DES3_ECB,blockSize,hSessionRO,hKey,blockSize*NR_OF_BLOCKS_IN_TEST+1, false);
}

void SymmetricAlgorithmTests::testNullTemplate()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism1 = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	CK_MECHANISM mechanism2 = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism1, NULL_PTR, 0, &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism2, NULL_PTR, 0, &hKey) );
	CPPUNIT_ASSERT(rv == CKR_TEMPLATE_INCOMPLETE);
}

void SymmetricAlgorithmTests::testNonModifiableDesKeyGeneration()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = { CKM_DES3_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bToken = IN_SESSION;

	CK_ATTRIBUTE keyAttribs[] =
		{
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) }
	};

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs, sizeof(keyAttribs)/sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// The C_GenerateKey call failed if CKA_MODIFIABLE was bFalse
	// This was a bug in the SoftHSM implementation
	keyAttribs[2].pValue = &bFalse;
	keyAttribs[2].ulValueLen = sizeof(bFalse);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs, sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	// The call would fail with CKR_ATTRIBUTE_READ_ONLY
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now create a template where the CKA_MODIFIABLE attribute is last in the list
	CK_ATTRIBUTE keyAttribs1[] =
	{
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_MODIFIABLE, &bTrue, sizeof(bTrue) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs1, sizeof(keyAttribs1) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Now when CKA_MODIFIABLE is bFalse the key generation succeeds
	keyAttribs1[2].pValue = &bFalse;
	keyAttribs1[2].ulValueLen = sizeof(bFalse);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
		keyAttribs1, sizeof(keyAttribs1) / sizeof(CK_ATTRIBUTE),
		&hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::testCheckValue()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_ULONG bytes = 16;
	CK_BYTE pCheckValue[] = { 0x2b, 0x84, 0xf6 };
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;
	CK_ATTRIBUTE keyAttribs[] = {
		{ CKA_TOKEN, &bFalse, sizeof(bFalse) },
		{ CKA_PRIVATE, &bTrue, sizeof(bTrue) },
		{ CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_DECRYPT, &bTrue, sizeof(bTrue) },
		{ CKA_WRAP, &bTrue, sizeof(bTrue) },
		{ CKA_UNWRAP, &bTrue, sizeof(bTrue) },
		{ CKA_VALUE_LEN, &bytes, sizeof(bytes) },
		{ CKA_CHECK_VALUE, &pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 8,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

	keyAttribs[7].ulValueLen = 0;
	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 8,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_ATTRIBUTE checkAttrib[] = {
		{ CKA_CHECK_VALUE, &pCheckValue, sizeof(pCheckValue) }
	};

	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey, checkAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(checkAttrib[0].ulValueLen == 0);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_GenerateKey(hSession, &mechanism,
			   keyAttribs, 7,
			   &hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	checkAttrib[0].ulValueLen = sizeof(pCheckValue);
	rv = CRYPTOKI_F_PTR( C_GetAttributeValue(hSession, hKey, checkAttrib, 1) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(checkAttrib[0].ulValueLen == 3);

	rv = CRYPTOKI_F_PTR( C_DestroyObject(hSession, hKey) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void SymmetricAlgorithmTests::testAesCtrOverflow()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate a session keys.
	rv = generateAesKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CK_MECHANISM mechanism = { CKM_AES_CTR, NULL_PTR, 0 };
	CK_AES_CTR_PARAMS ctrParams =
	{
		2,
		{
			0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		}
	};
	mechanism.pParameter = &ctrParams;
	mechanism.ulParameterLen = sizeof(ctrParams);

	CK_BYTE plainText[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x00 };
	std::vector<CK_BYTE> vEncryptedData;
	std::vector<CK_BYTE> vEncryptedDataParted;
	std::vector<CK_BYTE> vDecryptedData;
	std::vector<CK_BYTE> vDecryptedDataParted;
	CK_ULONG ulEncryptedDataLen;
	CK_ULONG ulEncryptedPartLen;
	CK_ULONG ulDataLen;
	CK_ULONG ulDataPartLen;

	// Single-part encryption
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText),NULL_PTR,&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_DATA_LEN_RANGE, rv );
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText)-1,NULL_PTR,&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedData.resize(ulEncryptedDataLen);
	rv = CRYPTOKI_F_PTR( C_Encrypt(hSession,plainText,sizeof(plainText)-1,&vEncryptedData.front(),&ulEncryptedDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedData.resize(ulEncryptedDataLen);

	// Multi-part encryption
	rv = CRYPTOKI_F_PTR( C_EncryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,sizeof(plainText)-1,NULL_PTR,&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedDataParted.resize(ulEncryptedPartLen);
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,sizeof(plainText)-1,&vEncryptedDataParted.front(),&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vEncryptedDataParted.resize(ulEncryptedPartLen);
	rv = CRYPTOKI_F_PTR( C_EncryptUpdate(hSession,plainText,1,NULL_PTR,&ulEncryptedPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_DATA_LEN_RANGE, rv );

	// Single-part decryption
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size()+1,NULL_PTR,&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedData.resize(ulDataLen);
	rv = CRYPTOKI_F_PTR( C_Decrypt(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedData.front(),&ulDataLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedData.resize(ulDataLen);

	// Multi-part decryption
	rv = CRYPTOKI_F_PTR( C_DecryptInit(hSession,&mechanism,hKey) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),vEncryptedData.size(),NULL_PTR,&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedDataParted.resize(ulDataPartLen);
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),vEncryptedData.size(),&vDecryptedDataParted.front(),&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_OK, rv );
	vDecryptedDataParted.resize(ulDataPartLen);
	rv = CRYPTOKI_F_PTR( C_DecryptUpdate(hSession,&vEncryptedData.front(),1,NULL_PTR,&ulDataPartLen) );
	CPPUNIT_ASSERT_EQUAL( (CK_RV)CKR_ENCRYPTED_DATA_LEN_RANGE, rv );
}

void SymmetricAlgorithmTests::testGenericKey()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the session so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSession,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

	// Generate a session key.
	rv = generateGenericKey(hSession,IN_SESSION,IS_PUBLIC,hKey);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
