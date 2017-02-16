/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 BotanRSAPrivateKey.cpp

 Botan RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "BotanRSAPrivateKey.h"
#include "BotanUtil.h"
#include "BotanRNG.h"
#include "BotanCryptoFactory.h"
#include <string.h>
#include <botan/pkcs8.h>
#include <botan/pkcs8.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/version.h>

// Constructors
BotanRSAPrivateKey::BotanRSAPrivateKey()
{
	rsa = NULL;
}

BotanRSAPrivateKey::BotanRSAPrivateKey(const Botan::RSA_PrivateKey* inRSA)
{
	rsa = NULL;

	setFromBotan(inRSA);
}

// Destructor
BotanRSAPrivateKey::~BotanRSAPrivateKey()
{
	delete rsa;
}

// The type
/*static*/ const char* BotanRSAPrivateKey::type = "Botan RSA Private Key";

// Set from Botan representation
void BotanRSAPrivateKey::setFromBotan(const Botan::RSA_PrivateKey* inRSA)
{
	ByteString inP = BotanUtil::bigInt2ByteString(inRSA->get_p());
	setP(inP);
	ByteString inQ = BotanUtil::bigInt2ByteString(inRSA->get_q());
	setQ(inQ);
	ByteString inDP1 = BotanUtil::bigInt2ByteString(inRSA->get_d1());
	setDP1(inDP1);
	ByteString inDQ1 = BotanUtil::bigInt2ByteString(inRSA->get_d2());
	setDQ1(inDQ1);
	ByteString inPQ = BotanUtil::bigInt2ByteString(inRSA->get_c());
	setPQ(inPQ);
	ByteString inD = BotanUtil::bigInt2ByteString(inRSA->get_d());
	setD(inD);
	ByteString inN = BotanUtil::bigInt2ByteString(inRSA->get_n());
	setN(inN);
	ByteString inE = BotanUtil::bigInt2ByteString(inRSA->get_e());
	setE(inE);
}

// Check if the key is of the given type
bool BotanRSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the RSA private key components
void BotanRSAPrivateKey::setP(const ByteString& inP)
{
	RSAPrivateKey::setP(inP);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setQ(const ByteString& inQ)
{
	RSAPrivateKey::setQ(inQ);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setPQ(const ByteString& inPQ)
{
	RSAPrivateKey::setPQ(inPQ);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setDP1(const ByteString& inDP1)
{
	RSAPrivateKey::setDP1(inDP1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setD(const ByteString& inD)
{
	RSAPrivateKey::setD(inD);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}


// Setters for the RSA public key components
void BotanRSAPrivateKey::setN(const ByteString& inN)
{
	RSAPrivateKey::setN(inN);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

void BotanRSAPrivateKey::setE(const ByteString& inE)
{
	RSAPrivateKey::setE(inE);

	if (rsa)
	{
		delete rsa;
		rsa = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString BotanRSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	createBotanKey();
	if (rsa == NULL) return der;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	const Botan::secure_vector<Botan::byte> ber = Botan::PKCS8::BER_encode(*rsa);
#else
	const Botan::SecureVector<Botan::byte> ber = Botan::PKCS8::BER_encode(*rsa);
#endif
	der.resize(ber.size());
	memcpy(&der[0], &ber[0], ber.size());
	return der;
}

// Decode from PKCS#8 BER
bool BotanRSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	Botan::DataSource_Memory source(ber.const_byte_str(), ber.size());
	if (source.end_of_data()) return false;
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,0)
	Botan::secure_vector<Botan::byte> keydata;
#else
	Botan::SecureVector<Botan::byte> keydata;
#endif
	Botan::AlgorithmIdentifier alg_id;
	Botan::RSA_PrivateKey* key = NULL;
	try
	{

		Botan::BER_Decoder(source)
		.start_cons(Botan::SEQUENCE)
			.decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
			.decode(alg_id)
			.decode(keydata, Botan::OCTET_STRING)
			.discard_remaining()
		.end_cons();
		if (keydata.empty())
			throw Botan::Decoding_Error("PKCS #8 private key decoding failed");
		if (Botan::OIDS::lookup(alg_id.oid).compare("RSA"))
		{
			ERROR_MSG("Decoded private key not RSA");

			return false;
		}
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,34)
		key = new Botan::RSA_PrivateKey(alg_id, keydata);
#else
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		key = new Botan::RSA_PrivateKey(alg_id, keydata, *rng->getRNG());
#endif
		if (key == NULL) return false;

		setFromBotan(key);

		delete key;
	}
	catch (std::exception& e)
	{
		ERROR_MSG("Decode failed on %s", e.what());

		return false;
	}

	return true;
}

// Retrieve the Botan representation of the key
Botan::RSA_PrivateKey* BotanRSAPrivateKey::getBotanKey()
{
	if (!rsa)
	{
		createBotanKey();
	}

	return rsa;
}

// Create the Botan representation of the key
void BotanRSAPrivateKey::createBotanKey()
{
	// d and n is not needed, they can be calculated
	if (p.size() != 0 &&
	    q.size() != 0 &&
	    e.size() != 0)
	{
		if (rsa)
		{
			delete rsa;
			rsa = NULL;
		}

		try
		{
#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(1,11,34)
			rsa = new Botan::RSA_PrivateKey(
						BotanUtil::byteString2bigInt(p),
						BotanUtil::byteString2bigInt(q),
						BotanUtil::byteString2bigInt(e),
						BotanUtil::byteString2bigInt(d),
						BotanUtil::byteString2bigInt(n));
#else
			BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
			rsa = new Botan::RSA_PrivateKey(*rng->getRNG(),
						BotanUtil::byteString2bigInt(p),
						BotanUtil::byteString2bigInt(q),
						BotanUtil::byteString2bigInt(e),
						BotanUtil::byteString2bigInt(d),
						BotanUtil::byteString2bigInt(n));
#endif
		}
		catch (...)
		{
			ERROR_MSG("Could not create the Botan private key");
		}
        }
}
