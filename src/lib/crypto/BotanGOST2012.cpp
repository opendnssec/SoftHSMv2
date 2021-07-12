#include "BotanGOST2012.h"
#ifdef WITH_GOST
#include "BotanGOSTKeyPair.h"
#include "BotanRNG.h"
#include "BotanCryptoFactory.h"
#include "ECParameters.h"

#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/gost_3410.h>

bool BotanGOST2012::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng)
{
	ECParameters *p = reinterpret_cast<ECParameters*>(parameters);
	const ByteString &ec = p->getEC();
	Botan::BER_Decoder dec(ec.const_byte_str(), ec.size());
	if(ec.size())
	{
		Botan::OID oid;
		oid.decode_from(dec);
		if (oid != Botan::OID({1,2,643,2,2,35,1}) &&
				oid != Botan::OID({1,2,643,2,2,35,2}) &&
				oid != Botan::OID({1,2,643,2,2,35,3}) &&
				oid != Botan::OID({1,2,643,2,2,36,0}) &&
				oid != Botan::OID({1,2,643,2,2,36,1}) &&
				oid != Botan::OID({1,2,643,7,1,2,1,1,1})
				)
		{
			ERROR_MSG("Public Key paramSet is not valid for GOST R34.10-2012 256");
			return false;
		}
	}
	else
	{
		const std::vector<u_char> &data = Botan::OID({1,2,643,2,2,35,1}).BER_encode();
		p->setEC(ByteString(data.data(), data.size()));
	}
	return BotanGOST::generateKeyPair(ppKeyPair, parameters, rng);
}

// Signing functions
bool BotanGOST2012::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			 const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(BotanGOSTPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::GOST:
			emsa = "Raw";
			break;
		case AsymMech::GOST_GOST_256:
			emsa = "EMSA1(Streebog-256)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);

			return false;
	}

		BotanGOSTPrivateKey* pk = (BotanGOSTPrivateKey*) currentPrivateKey;
		Botan::GOST_3410_PrivateKey* botanKey = pk->getBotanKey();

		if (botanKey == NULL)
		{
		ERROR_MSG("Could not get the Botan private key");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	try
	{
		BotanRNG* rng = (BotanRNG*)BotanCryptoFactory::i()->getRNG();
		signer = new Botan::PK_Signer(*botanKey, *rng->getRNG(), emsa);
	}
	catch (Botan::Exception except)
	{
		ERROR_MSG("Could not create the signer token. msg: %s", except.what());

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

// Verification functions
bool BotanGOST2012::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			   const void* param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, param, paramLen))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(BotanGOSTPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	std::string emsa;

	switch (mechanism)
	{
		case AsymMech::GOST:
			emsa = "Raw";
			break;
		case AsymMech::GOST_GOST_256:
			emsa = "EMSA1(Streebog-256)";
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);

			return false;
	}

	BotanGOSTPublicKey* pk = (BotanGOSTPublicKey*) currentPublicKey;
	Botan::GOST_3410_PublicKey* botanKey = pk->getBotanKey();

	if (botanKey == NULL)
	{
		ERROR_MSG("Could not get the Botan public key");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	try
	{
		verifier = new Botan::PK_Verifier(*botanKey, emsa);
	}
	catch (...)
	{
		ERROR_MSG("Could not create the verifier token");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}
#endif
